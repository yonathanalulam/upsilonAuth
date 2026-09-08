package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const ClaimsContextKey = "upsilonAuth.claims"

var (
	ErrInvalidConfig = errors.New("invalid verifier configuration")
	ErrInvalidJWKS   = errors.New("invalid JWKS")
)

type Config struct {
	JWKSURL    string
	Audience   string
	HTTPClient *http.Client
	CacheTTL   time.Duration
}

type Capability struct {
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Depth     int      `json:"depth"`
	Parent    string   `json:"parent,omitempty"`
}

type Claims struct {
	UPS Capability `json:"ups"`
	jwt.RegisteredClaims
}

type Verifier struct {
	jwksURL  string
	client   *http.Client
	cacheTTL time.Duration
	audience string
	mu       sync.RWMutex
	refresh  sync.Mutex
	keys     map[string]ed25519.PublicKey
	expires  time.Time
}

type keySet struct {
	Keys []webKey `json:"keys"`
}

type webKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
}

func New(config Config) (*Verifier, error) {
	parsed, err := url.ParseRequestURI(config.JWKSURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrInvalidConfig
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	cacheTTL := config.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}
	return &Verifier{
		jwksURL:  config.JWKSURL,
		client:   client,
		cacheTTL: cacheTTL,
		audience: config.Audience,
		keys:     make(map[string]ed25519.PublicKey),
	}, nil
}

func (verifier *Verifier) Require(action, resource string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}

		claims := &Claims{}
		options := []jwt.ParserOption{
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
		}
		if verifier.audience != "" {
			options = append(options, jwt.WithAudience(verifier.audience))
		}
		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			func(token *jwt.Token) (any, error) {
				keyID, ok := token.Header["kid"].(string)
				if !ok || keyID == "" {
					return nil, ErrInvalidJWKS
				}
				return verifier.key(c.Request.Context(), keyID)
			},
			options...,
		)
		if err != nil || !token.Valid {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}
		if !contains(claims.UPS.Actions, action) || !contains(claims.UPS.Resources, resource) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient capability"})
			return
		}

		c.Set(ClaimsContextKey, claims)
		c.Next()
	}
}

func ClaimsFromContext(c *gin.Context) (*Claims, bool) {
	value, exists := c.Get(ClaimsContextKey)
	if !exists {
		return nil, false
	}
	claims, ok := value.(*Claims)
	return claims, ok
}

func (verifier *Verifier) key(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if key, ok := verifier.cachedKey(keyID); ok {
		return key, nil
	}

	verifier.refresh.Lock()
	defer verifier.refresh.Unlock()
	if key, ok := verifier.cachedKey(keyID); ok {
		return key, nil
	}

	keys, err := verifier.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	verifier.mu.Lock()
	verifier.keys = keys
	verifier.expires = time.Now().Add(verifier.cacheTTL)
	key, ok := verifier.keys[keyID]
	verifier.mu.Unlock()
	if !ok {
		return nil, ErrInvalidJWKS
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func (verifier *Verifier) cachedKey(keyID string) (ed25519.PublicKey, bool) {
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	if !time.Now().Before(verifier.expires) {
		return nil, false
	}
	key, ok := verifier.keys[keyID]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), key...), true
}

func (verifier *Verifier) fetchKeys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, verifier.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	response, err := verifier.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	if len(body) > 1<<20 {
		return nil, ErrInvalidJWKS
	}
	var set keySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyType != "OKP" || key.Curve != "Ed25519" || key.Algorithm != "EdDSA" || key.Use != "sig" || key.KeyID == "" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			continue
		}
		if _, exists := keys[key.KeyID]; exists {
			return nil, ErrInvalidJWKS
		}
		keys[key.KeyID] = ed25519.PublicKey(decoded)
	}
	if len(keys) == 0 {
		return nil, ErrInvalidJWKS
	}
	return keys, nil
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func contains(values []string, required string) bool {
	for _, value := range values {
		if value == required {
			return true
		}
	}
	return false
}
