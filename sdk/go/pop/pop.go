package pop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
)

const TokenType = "dpop+jwt"
const MaxProofBytes = 8 << 10

var ErrInvalidProof = errors.New("invalid proof of possession")

type JSONWebKey struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

type Claims struct {
	HTTPMethod string `json:"htm"`
	HTTPURI    string `json:"htu"`
	AccessHash string `json:"ath"`
	jwt.RegisteredClaims
}

type VerifiedProof struct {
	ID           string
	Thumbprint   string
	ReplayExpiry time.Time
}

func Sign(privateKey ed25519.PrivateKey, method, target, accessToken string, now time.Time) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || method == "" || accessToken == "" {
		return "", ErrInvalidProof
	}
	canonicalTarget, err := canonicalURI(target)
	if err != nil {
		return "", err
	}
	identifier := make([]byte, 24)
	if _, err := rand.Read(identifier); err != nil {
		return "", fmt.Errorf("generate proof id: %w", err)
	}
	accessDigest := sha256.Sum256([]byte(accessToken))
	claims := Claims{
		HTTPMethod: strings.ToUpper(method), HTTPURI: canonicalTarget,
		AccessHash: base64.RawURLEncoding.EncodeToString(accessDigest[:]),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(now.UTC().Truncate(time.Second)),
			ID:       base64.RawURLEncoding.EncodeToString(identifier),
		},
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = TokenType
	token.Header["jwk"] = JSONWebKey{
		KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(publicKey),
	}
	delete(token.Header, "kid")
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign proof: %w", err)
	}
	return signed, nil
}

func Verify(raw, method, target, accessToken, expectedThumbprint string, now time.Time, window time.Duration) (VerifiedProof, error) {
	if len(raw) == 0 || len(raw) > MaxProofBytes || method == "" || accessToken == "" || len(expectedThumbprint) != 43 || window <= 0 || window > time.Minute {
		return VerifiedProof{}, ErrInvalidProof
	}
	header, payload, err := strictParts(raw)
	if err != nil || len(header) != 3 || len(payload) != 5 {
		return VerifiedProof{}, ErrInvalidProof
	}
	var algorithm, tokenType string
	if json.Unmarshal(header["alg"], &algorithm) != nil || algorithm != jwt.SigningMethodEdDSA.Alg() || json.Unmarshal(header["typ"], &tokenType) != nil || tokenType != TokenType {
		return VerifiedProof{}, ErrInvalidProof
	}
	var key JSONWebKey
	var rawKey map[string]json.RawMessage
	if json.Unmarshal(header["jwk"], &rawKey) != nil || len(rawKey) != 3 {
		return VerifiedProof{}, ErrInvalidProof
	}
	for _, required := range []string{"kty", "crv", "x"} {
		if _, exists := rawKey[required]; !exists {
			return VerifiedProof{}, ErrInvalidProof
		}
	}
	if json.Unmarshal(header["jwk"], &key) != nil || key.KeyType != "OKP" || key.Curve != "Ed25519" {
		return VerifiedProof{}, ErrInvalidProof
	}
	decoded, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return VerifiedProof{}, ErrInvalidProof
	}
	publicKey := ed25519.PublicKey(decoded)
	thumbprint, err := authcrypto.JWKThumbprint(publicKey)
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(expectedThumbprint)) != 1 {
		return VerifiedProof{}, ErrInvalidProof
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithIssuedAt(), jwt.WithStrictDecoding())
	if err != nil || !token.Valid || claims.ID == "" || len(claims.ID) > 128 || claims.IssuedAt == nil {
		return VerifiedProof{}, ErrInvalidProof
	}
	canonicalTarget, err := canonicalURI(target)
	if err != nil || claims.HTTPMethod != strings.ToUpper(method) || claims.HTTPURI != canonicalTarget {
		return VerifiedProof{}, ErrInvalidProof
	}
	delta := now.UTC().Sub(claims.IssuedAt.Time)
	if delta < -window || delta > window {
		return VerifiedProof{}, ErrInvalidProof
	}
	accessDigest := sha256.Sum256([]byte(accessToken))
	expectedAccessHash := base64.RawURLEncoding.EncodeToString(accessDigest[:])
	if subtle.ConstantTimeCompare([]byte(claims.AccessHash), []byte(expectedAccessHash)) != 1 {
		return VerifiedProof{}, ErrInvalidProof
	}
	// NumericDate has one-second precision. Retain the replay marker through
	// the entire final second of the accepted proof window.
	return VerifiedProof{ID: claims.ID, Thumbprint: thumbprint, ReplayExpiry: claims.IssuedAt.Time.Add(window).Add(time.Second)}, nil
}

func canonicalURI(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", ErrInvalidProof
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func strictParts(raw string) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, ErrInvalidProof
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if rejectDuplicateKeys(headerBytes) != nil || rejectDuplicateKeys(payloadBytes) != nil {
		return nil, nil, ErrInvalidProof
	}
	var header, payload map[string]json.RawMessage
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(payloadBytes, &payload) != nil {
		return nil, nil, ErrInvalidProof
	}
	for name := range header {
		if name != "alg" && name != "typ" && name != "jwk" {
			return nil, nil, ErrInvalidProof
		}
	}
	for name := range payload {
		if name != "htm" && name != "htu" && name != "ath" && name != "iat" && name != "jti" {
			return nil, nil, ErrInvalidProof
		}
	}
	return header, payload, nil
}

func rejectDuplicateKeys(data []byte) error {
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
		if delimiter == '{' {
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidProof
				}
				if _, exists := seen[key]; exists {
					return ErrInvalidProof
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
		if delimiter == '[' {
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
		return ErrInvalidProof
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidProof
	}
	return nil
}
