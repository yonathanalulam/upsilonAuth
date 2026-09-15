package middleware

import (
	"bytes"
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

	constraintpkg "github.com/yonathanalulam/upsilonAuth/internal/constraints"
	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
	resourcepkg "github.com/yonathanalulam/upsilonAuth/internal/resource"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/autherrors"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/pop"
)

const ClaimsContextKey = "upsilonAuth.claims"
const maxMetadataBytes = 1 << 20
const maxTokenBytes = authcrypto.MaxLeaseTokenBytes

var (
	ErrInvalidConfig = errors.New("invalid verifier configuration")
	ErrInvalidJWKS   = errors.New("invalid JWKS")
)

type RevocationMode string

const (
	RevocationStrict       RevocationMode = "STRICT"
	RevocationBoundedStale RevocationMode = "BOUNDED_STALE"
	RevocationExpiryOnly   RevocationMode = "EXPIRY_ONLY"
)

type Config struct {
	JWKSURL                  string
	RevocationsURL           string
	Issuer                   string
	Audience                 string
	HTTPClient               *http.Client
	CacheTTL                 time.Duration
	RevocationCacheTTL       time.Duration
	RevocationMode           RevocationMode
	MaxRevocationStaleness   time.Duration
	ClockSkew                time.Duration
	AllowInsecureHTTP        bool
	RequireProofOfPossession bool
	ProofWindow              time.Duration
	ExternalURL              func(*http.Request) (string, error)
	ConsumeLease             LeaseConsumer
	ConstraintValues         func(*http.Request) map[string]string
}

type Capability = authcrypto.CapabilityClaims
type Claims = authcrypto.LeaseClaims
type ResourceResolver func(*gin.Context) string
type LeaseConsumer func(context.Context, string, string, string) error

type ErrorCode string

const (
	CodeTokenExpired             ErrorCode = "TOKEN_EXPIRED"
	CodeInvalidAudience          ErrorCode = "INVALID_AUDIENCE"
	CodeInsufficientAction       ErrorCode = "INSUFFICIENT_ACTION"
	CodeResourceOutOfScope       ErrorCode = "RESOURCE_OUT_OF_SCOPE"
	CodeLeaseRevoked             ErrorCode = "LEASE_REVOKED"
	CodeMaxUsesExceeded          ErrorCode = "MAX_USES_EXCEEDED"
	CodeInvalidSignature         ErrorCode = "INVALID_SIGNATURE"
	CodeProofRequired            ErrorCode = "PROOF_REQUIRED"
	CodeConstraintNotSatisfied   ErrorCode = "CONSTRAINT_NOT_SATISFIED"
	CodeAuthorizationUnavailable ErrorCode = "AUTHORIZATION_UNAVAILABLE"
)

type AuthorizationError struct {
	Code   ErrorCode
	Status int
	Cause  error
}

func (err *AuthorizationError) Error() string { return string(err.Code) }
func (err *AuthorizationError) Unwrap() error { return err.Cause }

type Verifier struct {
	jwksURL            *url.URL
	revocationsURL     *url.URL
	client             *http.Client
	cacheTTL           time.Duration
	revocationCacheTTL time.Duration
	revocationMode     RevocationMode
	maxStaleness       time.Duration
	clockSkew          time.Duration
	audience           string
	issuer             string
	requireProof       bool
	proofWindow        time.Duration
	externalURL        func(*http.Request) (string, error)
	consumeLease       LeaseConsumer
	constraintValues   func(*http.Request) map[string]string
	proofMu            sync.Mutex
	proofReplay        map[string]time.Time
	mu                 sync.RWMutex
	refresh            sync.Mutex
	keys               map[string]ed25519.PublicKey
	keysExpire         time.Time
	revocationMu       sync.RWMutex
	revocationRefresh  sync.Mutex
	revoked            map[string]struct{}
	revocationsExpire  time.Time
	revocationsFetched time.Time
	revocationsETag    string
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

type revocationSet struct {
	Revoked     []string  `json:"revoked"`
	GeneratedAt time.Time `json:"generated_at"`
}

func New(config Config) (*Verifier, error) {
	jwksURL, err := parseMetadataURL(config.JWKSURL, config.AllowInsecureHTTP)
	if err != nil || strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.Audience) == "" {
		return nil, ErrInvalidConfig
	}
	mode := config.RevocationMode
	if mode == "" {
		mode = RevocationStrict
	}
	if mode != RevocationStrict && mode != RevocationBoundedStale && mode != RevocationExpiryOnly {
		return nil, ErrInvalidConfig
	}
	var revocationsURL *url.URL
	if mode != RevocationExpiryOnly {
		revocationsValue := config.RevocationsURL
		if revocationsValue == "" {
			revocations := *jwksURL
			revocations.Path = "/.well-known/revocations.json"
			revocations.RawQuery = ""
			revocations.Fragment = ""
			revocationsValue = revocations.String()
		}
		revocationsURL, err = parseMetadataURL(revocationsValue, config.AllowInsecureHTTP)
		if err != nil {
			return nil, ErrInvalidConfig
		}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: sameOriginRedirect(jwksURL, revocationsURL)}
	}
	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	if cacheTTL < time.Second || cacheTTL > 15*time.Minute {
		return nil, ErrInvalidConfig
	}
	revocationCacheTTL := config.RevocationCacheTTL
	if revocationCacheTTL == 0 {
		revocationCacheTTL = 30 * time.Second
	}
	if revocationCacheTTL < 100*time.Millisecond || revocationCacheTTL > 15*time.Minute {
		return nil, ErrInvalidConfig
	}
	maxStaleness := config.MaxRevocationStaleness
	if mode == RevocationBoundedStale {
		if maxStaleness == 0 {
			maxStaleness = 5 * time.Minute
		}
		if maxStaleness < revocationCacheTTL || maxStaleness > time.Hour {
			return nil, ErrInvalidConfig
		}
	} else if maxStaleness != 0 {
		return nil, ErrInvalidConfig
	}
	if config.ClockSkew < 0 || config.ClockSkew > time.Minute {
		return nil, ErrInvalidConfig
	}
	proofWindow := config.ProofWindow
	if proofWindow == 0 {
		proofWindow = 30 * time.Second
	}
	if proofWindow < time.Second || proofWindow > time.Minute {
		return nil, ErrInvalidConfig
	}
	return &Verifier{
		jwksURL: jwksURL, revocationsURL: revocationsURL, client: client, cacheTTL: cacheTTL,
		revocationCacheTTL: revocationCacheTTL, revocationMode: mode, maxStaleness: maxStaleness, clockSkew: config.ClockSkew,
		audience: config.Audience, issuer: config.Issuer, keys: make(map[string]ed25519.PublicKey), revoked: make(map[string]struct{}),
		requireProof: config.RequireProofOfPossession, proofWindow: proofWindow, externalURL: config.ExternalURL,
		consumeLease:     config.ConsumeLease,
		constraintValues: config.ConstraintValues,
		proofReplay:      make(map[string]time.Time),
	}, nil
}

func (verifier *Verifier) Require(action string, resource any) gin.HandlerFunc {
	return func(c *gin.Context) {
		requiredResource, ok := resolveResource(c, resource)
		if action == "" || !ok || requiredResource == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid capability requirement"})
			return
		}
		tokenString, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			writeAuthorizationError(c, authorizationError(CodeInvalidSignature, http.StatusUnauthorized, nil))
			return
		}
		claims, err := verifier.Authorize(c.Request, tokenString, action, requiredResource)
		if err != nil {
			writeAuthorizationError(c, err)
			return
		}
		c.Set(ClaimsContextKey, claims)
		c.Next()
	}
}

func (verifier *Verifier) Authorize(request *http.Request, tokenString, action, requiredResource string) (*Claims, error) {
	if request == nil || action == "" || requiredResource == "" || len(tokenString) == 0 || len(tokenString) > maxTokenBytes {
		return nil, authorizationError(CodeInvalidSignature, http.StatusUnauthorized, nil)
	}
	keyID, err := authcrypto.TokenKeyID(tokenString)
	if err != nil {
		return nil, authorizationError(CodeInvalidSignature, http.StatusUnauthorized, err)
	}
	key, err := verifier.key(request.Context(), keyID)
	if err != nil {
		return nil, authorizationError(CodeAuthorizationUnavailable, http.StatusServiceUnavailable, err)
	}
	claims, err := authcrypto.VerifyLeaseToken(tokenString, map[string]ed25519.PublicKey{keyID: key}, verifier.issuer, verifier.audience, verifier.clockSkew)
	if err != nil {
		switch {
		case errors.Is(err, authcrypto.ErrTokenExpired):
			return nil, authorizationError(CodeTokenExpired, http.StatusUnauthorized, err)
		case errors.Is(err, authcrypto.ErrInvalidAudience):
			return nil, authorizationError(CodeInvalidAudience, http.StatusUnauthorized, err)
		default:
			return nil, authorizationError(CodeInvalidSignature, http.StatusUnauthorized, err)
		}
	}
	if err := verifier.verifyProof(request, tokenString, claims); err != nil {
		return nil, authorizationError(CodeProofRequired, http.StatusUnauthorized, err)
	}
	revoked, err := verifier.isRevoked(request.Context(), claims.UPS.LeaseID)
	if err != nil {
		return nil, authorizationError(CodeAuthorizationUnavailable, http.StatusServiceUnavailable, err)
	}
	if revoked {
		return nil, authorizationError(CodeLeaseRevoked, http.StatusUnauthorized, domain.ErrLeaseRevoked)
	}
	if !contains(claims.UPS.Actions, action) {
		return nil, authorizationError(CodeInsufficientAction, http.StatusForbidden, nil)
	}
	if !resourceAllowed(claims.UPS.Resources, requiredResource) {
		return nil, authorizationError(CodeResourceOutOfScope, http.StatusForbidden, nil)
	}
	if !verifier.constraintsSatisfied(request, claims.UPS.Constraints) {
		return nil, authorizationError(CodeConstraintNotSatisfied, http.StatusForbidden, nil)
	}
	if claims.UPS.MaxUses > 0 {
		idempotencyKey := request.Header.Get("Idempotency-Key")
		if verifier.consumeLease == nil || idempotencyKey == "" {
			return nil, authorizationError(CodeAuthorizationUnavailable, http.StatusServiceUnavailable, nil)
		}
		if err := verifier.consumeLease(request.Context(), claims.UPS.LeaseID, tokenString, idempotencyKey); err != nil {
			if errors.Is(err, domain.ErrMaxUsesExceeded) || errors.Is(err, autherrors.ErrMaxUsesExceeded) {
				return nil, authorizationError(CodeMaxUsesExceeded, http.StatusForbidden, err)
			}
			return nil, authorizationError(CodeAuthorizationUnavailable, http.StatusServiceUnavailable, err)
		}
	}
	return claims, nil
}

func (verifier *Verifier) constraintsSatisfied(request *http.Request, constraints map[string]string) bool {
	values := map[string]string{"http_method": strings.ToUpper(request.Method)}
	if verifier.constraintValues != nil {
		for key, value := range verifier.constraintValues(request) {
			if key != "http_method" {
				values[key] = value
			}
		}
	}
	return constraintpkg.Satisfied(constraints, values)
}

func authorizationError(code ErrorCode, status int, cause error) *AuthorizationError {
	return &AuthorizationError{Code: code, Status: status, Cause: cause}
}

func writeAuthorizationError(c *gin.Context, err error) {
	var authorization *AuthorizationError
	if !errors.As(err, &authorization) {
		authorization = authorizationError(CodeAuthorizationUnavailable, http.StatusServiceUnavailable, err)
	}
	if authorization.Status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", "Bearer")
	}
	c.AbortWithStatusJSON(authorization.Status, gin.H{"error": gin.H{"code": authorization.Code, "message": "authorization denied"}})
}

func resolveResource(c *gin.Context, resolver any) (string, bool) {
	switch value := resolver.(type) {
	case string:
		return value, value != ""
	case ResourceResolver:
		return value(c), true
	case func(*gin.Context) string:
		return value(c), true
	default:
		return "", false
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

func (verifier *Verifier) verifyProof(request *http.Request, accessToken string, claims *Claims) error {
	if claims.Confirmation == nil {
		if verifier.requireProof {
			return pop.ErrInvalidProof
		}
		return nil
	}
	proofValue := request.Header.Get("DPoP")
	if proofValue == "" {
		return pop.ErrInvalidProof
	}
	target, err := verifier.proofTarget(request)
	if err != nil {
		return pop.ErrInvalidProof
	}
	now := time.Now().UTC()
	verified, err := pop.Verify(
		proofValue, request.Method, target, accessToken, claims.Confirmation.JWKThumbprint, now, verifier.proofWindow,
	)
	if err != nil {
		return err
	}
	if !verifier.consumeProof(verified.Thumbprint+":"+verified.ID, verified.ReplayExpiry, now) {
		return pop.ErrInvalidProof
	}
	return nil
}

func (verifier *Verifier) proofTarget(request *http.Request) (string, error) {
	if verifier.externalURL != nil {
		return verifier.externalURL(request)
	}
	if request.Host == "" {
		return "", pop.ErrInvalidProof
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + request.URL.EscapedPath(), nil
}

func (verifier *Verifier) consumeProof(key string, expiresAt, now time.Time) bool {
	verifier.proofMu.Lock()
	defer verifier.proofMu.Unlock()
	if existing, exists := verifier.proofReplay[key]; exists && !now.After(existing) {
		return false
	}
	if len(verifier.proofReplay) >= 10000 {
		for candidate, expiration := range verifier.proofReplay {
			if now.After(expiration) {
				delete(verifier.proofReplay, candidate)
			}
		}
		if len(verifier.proofReplay) >= 10000 {
			return false
		}
	}
	verifier.proofReplay[key] = expiresAt
	return true
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
	verifier.keysExpire = time.Now().Add(verifier.cacheTTL)
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
	if !time.Now().Before(verifier.keysExpire) {
		return nil, false
	}
	key, ok := verifier.keys[keyID]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), key...), true
}

func (verifier *Verifier) fetchKeys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	var set keySet
	if err := verifier.fetchJSON(ctx, verifier.jwksURL, &set); err != nil {
		return nil, err
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
		publicKey := ed25519.PublicKey(decoded)
		expectedID, err := authcrypto.PublicKeyID(publicKey)
		if err != nil || key.KeyID != expectedID {
			return nil, ErrInvalidJWKS
		}
		keys[key.KeyID] = publicKey
	}
	if len(keys) == 0 {
		return nil, ErrInvalidJWKS
	}
	return keys, nil
}

func (verifier *Verifier) isRevoked(ctx context.Context, leaseID string) (bool, error) {
	if verifier.revocationMode == RevocationExpiryOnly {
		return false, nil
	}
	if revoked, fresh := verifier.cachedRevocation(leaseID); fresh {
		return revoked, nil
	}
	verifier.revocationRefresh.Lock()
	defer verifier.revocationRefresh.Unlock()
	if revoked, fresh := verifier.cachedRevocation(leaseID); fresh {
		return revoked, nil
	}
	set, notModified, etag, err := verifier.fetchRevocations(ctx)
	if err != nil {
		if verifier.revocationMode == RevocationBoundedStale {
			if revoked, usable := verifier.staleRevocation(leaseID, time.Now()); usable {
				return revoked, nil
			}
		}
		return false, err
	}
	if notModified {
		verifier.revocationMu.Lock()
		now := time.Now()
		verifier.revocationsExpire = now.Add(verifier.revocationCacheTTL)
		verifier.revocationsFetched = now
		_, found := verifier.revoked[leaseID]
		verifier.revocationMu.Unlock()
		return found, nil
	}
	if set.GeneratedAt.IsZero() || set.GeneratedAt.After(time.Now().Add(verifier.clockSkew)) {
		return false, errors.New("invalid revocation snapshot time")
	}
	revoked := make(map[string]struct{}, len(set.Revoked))
	for _, id := range set.Revoked {
		if id == "" {
			return false, errors.New("invalid revocation set")
		}
		revoked[id] = struct{}{}
	}
	verifier.revocationMu.Lock()
	verifier.revoked = revoked
	now := time.Now()
	verifier.revocationsExpire = now.Add(verifier.revocationCacheTTL)
	verifier.revocationsFetched = now
	verifier.revocationsETag = etag
	_, found := verifier.revoked[leaseID]
	verifier.revocationMu.Unlock()
	return found, nil
}

func (verifier *Verifier) fetchRevocations(ctx context.Context) (revocationSet, bool, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, verifier.revocationsURL.String(), nil)
	if err != nil {
		return revocationSet{}, false, "", err
	}
	request.Header.Set("Accept", "application/json")
	verifier.revocationMu.RLock()
	if verifier.revocationsETag != "" {
		request.Header.Set("If-None-Match", verifier.revocationsETag)
	}
	verifier.revocationMu.RUnlock()
	requestClient := *verifier.client
	requestClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := requestClient.Do(request)
	if err != nil {
		return revocationSet{}, false, "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.Request == nil || response.Request.URL.Scheme != verifier.revocationsURL.Scheme || !strings.EqualFold(response.Request.URL.Host, verifier.revocationsURL.Host) {
		return revocationSet{}, false, "", errors.New("revocation redirect changed origin")
	}
	if response.StatusCode == http.StatusNotModified {
		verifier.revocationMu.RLock()
		hasSnapshot := !verifier.revocationsFetched.IsZero()
		verifier.revocationMu.RUnlock()
		if !hasSnapshot {
			return revocationSet{}, false, "", errors.New("revocation endpoint returned 304 without a cached snapshot")
		}
		return revocationSet{}, true, response.Header.Get("ETag"), nil
	}
	if response.StatusCode != http.StatusOK {
		return revocationSet{}, false, "", fmt.Errorf("fetch revocations: status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes || rejectDuplicateJSONKeys(body) != nil {
		return revocationSet{}, false, "", errors.New("invalid revocation response")
	}
	var set revocationSet
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return revocationSet{}, false, "", err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return revocationSet{}, false, "", errors.New("revocation response contains trailing data")
	}
	return set, false, response.Header.Get("ETag"), nil
}

func (verifier *Verifier) staleRevocation(leaseID string, now time.Time) (bool, bool) {
	verifier.revocationMu.RLock()
	defer verifier.revocationMu.RUnlock()
	if verifier.revocationsFetched.IsZero() || now.Sub(verifier.revocationsFetched) > verifier.maxStaleness {
		return false, false
	}
	_, revoked := verifier.revoked[leaseID]
	return revoked, true
}

func (verifier *Verifier) cachedRevocation(leaseID string) (bool, bool) {
	verifier.revocationMu.RLock()
	defer verifier.revocationMu.RUnlock()
	if !time.Now().Before(verifier.revocationsExpire) {
		return false, false
	}
	_, revoked := verifier.revoked[leaseID]
	return revoked, true
}

func (verifier *Verifier) fetchJSON(ctx context.Context, target *url.URL, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("create metadata request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	// A custom HTTP client may have a permissive redirect policy. Metadata is
	// trust material, so never follow redirects here: an endpoint must return
	// its document directly and cannot turn the verifier into an SSRF proxy.
	requestClient := *verifier.client
	requestClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := requestClient.Do(request)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.Request == nil || response.Request.URL.Scheme != target.Scheme || !strings.EqualFold(response.Request.URL.Host, target.Host) {
		return errors.New("metadata redirect changed origin")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch metadata: status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}
	if len(body) > maxMetadataBytes {
		return errors.New("metadata response too large")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return errors.New("metadata response contains duplicate keys")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("metadata response contains trailing data")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		seen := make(map[string]struct{})
		for decoder.More() {
			if delimiter == '{' {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON key")
				}
				seen[key] = struct{}{}
			}
			if err := walk(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func parseMetadataURL(value string, allowInsecure bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if parsed.Scheme != "https" && (!allowInsecure || parsed.Scheme != "http") {
		return nil, ErrInvalidConfig
	}
	return parsed, nil
}

func sameOriginRedirect(allowed ...*url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, _ []*http.Request) error {
		for _, candidate := range allowed {
			if candidate == nil {
				continue
			}
			if request.URL.Scheme == candidate.Scheme && strings.EqualFold(request.URL.Host, candidate.Host) {
				return nil
			}
		}
		return errors.New("metadata redirect changed origin")
	}
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

func resourceAllowed(resources []string, required string) bool {
	if _, err := resourcepkg.CanonicalizeValue(required); err != nil {
		return false
	}
	for _, pattern := range resources {
		if resourcepkg.Allows(pattern, required) {
			return true
		}
	}
	return false
}
