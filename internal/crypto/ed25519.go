package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	constraintpkg "github.com/yonathanalulam/upsilonAuth/internal/constraints"
	resourcepkg "github.com/yonathanalulam/upsilonAuth/internal/resource"
)

// #nosec G101 -- this is a public JOSE media type, not a credential.
const LeaseTokenType = "upsilon-lease+jwt"
const LeaseTokenVersion = 1
const MaxLeaseTokenBytes = 16 << 10

var (
	ErrInvalidPrivateKey = errors.New("invalid Ed25519 private key")
	ErrInvalidPublicKey  = errors.New("invalid Ed25519 public key")
	ErrInvalidToken      = errors.New("invalid lease token")
	ErrTokenExpired      = errors.New("lease token expired")
	ErrInvalidAudience   = errors.New("invalid lease token audience")
	ErrInvalidIssuer     = errors.New("invalid lease token issuer")
	ErrInvalidSignature  = errors.New("invalid lease token signature")
	ErrTokenNotYetValid  = errors.New("lease token not yet valid")
)

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
}

type CapabilityClaims struct {
	Version               int               `json:"version"`
	LeaseID               string            `json:"lease_id"`
	RootLeaseID           string            `json:"root_lease_id"`
	RootWorkloadID        string            `json:"root_workload_id"`
	WorkloadID            string            `json:"workload_id"`
	DelegatedByWorkloadID string            `json:"delegated_by_workload_id,omitempty"`
	Actions               []string          `json:"actions"`
	Resources             []string          `json:"resources"`
	Depth                 int               `json:"depth"`
	MaxDepth              int               `json:"max_depth"`
	ParentLeaseID         string            `json:"parent_lease_id,omitempty"`
	MaxUses               int               `json:"max_uses"`
	Constraints           map[string]string `json:"constraints"`
}

type LeaseClaims struct {
	UPS          CapabilityClaims   `json:"ups"`
	Confirmation *ConfirmationClaim `json:"cnf,omitempty"`
	jwt.RegisteredClaims
}

type ConfirmationClaim struct {
	JWKThumbprint string `json:"jkt"`
}

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SignClaims(claims map[string]any, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", ErrInvalidPrivateKey
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	token.Header["typ"] = LeaseTokenType
	token.Header["kid"] = keyID(publicKey)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

func SignLeaseClaims(claims LeaseClaims, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", ErrInvalidPrivateKey
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = LeaseTokenType
	token.Header["kid"] = keyID(publicKey)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	decoded, err := decodeBase64(encoded)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	key := ed25519.PrivateKey(append([]byte(nil), decoded...))
	derived := ed25519.NewKeyFromSeed(key.Seed())
	if !key.Equal(derived) {
		return nil, ErrInvalidPrivateKey
	}
	return key, nil
}

func ParsePublicKeys(encoded string) ([]ed25519.PublicKey, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	parts := strings.Split(encoded, ",")
	keys := make([]ed25519.PublicKey, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		decoded, err := decodeBase64(strings.TrimSpace(part))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, ErrInvalidPublicKey
		}
		key := ed25519.PublicKey(append([]byte(nil), decoded...))
		id := keyID(key)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		keys = append(keys, key)
	}
	return keys, nil
}

func VerificationKeys(keys []ed25519.PublicKey) map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(keys))
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize {
			result[keyID(key)] = append(ed25519.PublicKey(nil), key...)
		}
	}
	return result
}

func PublicKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	return keyID(publicKey), nil
}

func JWKThumbprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, base64.RawURLEncoding.EncodeToString(publicKey))
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func VerifyLeaseToken(raw string, keys map[string]ed25519.PublicKey, issuer, audience string, leeway time.Duration) (*LeaseClaims, error) {
	if raw == "" || len(raw) > MaxLeaseTokenBytes || issuer == "" || audience == "" || len(keys) == 0 || leeway < 0 {
		return nil, errors.New("invalid token verification configuration")
	}
	keyID, err := TokenKeyID(raw)
	if err != nil {
		return nil, errors.New("invalid lease token")
	}
	if _, exists := keys[keyID]; !exists {
		return nil, errors.New("invalid lease token")
	}
	claims := &LeaseClaims{}
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Header["typ"] != LeaseTokenType {
				return nil, errors.New("invalid token type")
			}
			keyID, ok := token.Header["kid"].(string)
			if !ok || keyID == "" {
				return nil, errors.New("missing token key id")
			}
			key, exists := keys[keyID]
			if !exists {
				return nil, errors.New("unknown token key id")
			}
			return key, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithNotBeforeRequired(),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithLeeway(leeway),
		jwt.WithStrictDecoding(),
	)
	if err != nil || !token.Valid {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrTokenNotYetValid
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, ErrInvalidAudience
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, ErrInvalidIssuer
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrInvalidSignature
		default:
			return nil, ErrInvalidToken
		}
	}
	if claims.ID == "" || claims.Subject == "" || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil || len(claims.Audience) != 1 {
		return nil, errors.New("missing required token claims")
	}
	if claims.UPS.Version != LeaseTokenVersion || claims.UPS.LeaseID == "" || claims.UPS.RootLeaseID == "" || claims.UPS.RootWorkloadID == "" || claims.UPS.WorkloadID != claims.Subject || len(claims.UPS.Actions) == 0 || len(claims.UPS.Resources) == 0 || claims.UPS.Depth < 0 || claims.UPS.MaxDepth < claims.UPS.Depth || claims.UPS.MaxDepth > 16 || claims.UPS.MaxUses < 0 || claims.UPS.Constraints == nil || !constraintpkg.Valid(claims.UPS.Constraints) || !validCapabilityValues(claims.UPS.Actions, false) || !validCapabilityValues(claims.UPS.Resources, true) {
		return nil, errors.New("invalid capability claims")
	}
	if claims.Confirmation != nil && len(claims.Confirmation.JWKThumbprint) != 43 {
		return nil, errors.New("invalid confirmation claim")
	}
	if claims.UPS.Depth == 0 {
		if claims.UPS.ParentLeaseID != "" || claims.UPS.DelegatedByWorkloadID != "" || claims.UPS.RootLeaseID != claims.UPS.LeaseID || claims.UPS.RootWorkloadID != claims.Subject {
			return nil, errors.New("invalid root lease claims")
		}
	} else if claims.UPS.ParentLeaseID == "" || claims.UPS.DelegatedByWorkloadID == "" {
		return nil, errors.New("invalid delegated lease claims")
	}
	if !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.NotBefore.Before(claims.IssuedAt.Time) {
		return nil, errors.New("invalid lease time claims")
	}
	return claims, nil
}

func TokenKeyID(raw string) (string, error) {
	header, _, err := strictTokenParts(raw)
	if err != nil {
		return "", err
	}
	if len(header) != 3 {
		return "", errors.New("unexpected token header")
	}
	var algorithm, tokenType, id string
	if err := json.Unmarshal(header["alg"], &algorithm); err != nil || algorithm != jwt.SigningMethodEdDSA.Alg() {
		return "", errors.New("invalid token algorithm")
	}
	if err := json.Unmarshal(header["typ"], &tokenType); err != nil || tokenType != LeaseTokenType {
		return "", errors.New("invalid token type")
	}
	if err := json.Unmarshal(header["kid"], &id); err != nil || id == "" {
		return "", errors.New("invalid token key id")
	}
	return id, nil
}

func PublicKeyJWKS(publicKey ed25519.PublicKey) ([]byte, error) {
	return PublicKeysJWKS([]ed25519.PublicKey{publicKey})
}

func PublicKeysJWKS(publicKeys []ed25519.PublicKey) ([]byte, error) {
	keys := make([]JSONWebKey, 0, len(publicKeys))
	seen := make(map[string]struct{}, len(publicKeys))
	for _, publicKey := range publicKeys {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidPublicKey
		}
		id := keyID(publicKey)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		keys = append(keys, JSONWebKey{
			KeyType:   "OKP",
			Use:       "sig",
			Algorithm: "EdDSA",
			KeyID:     id,
			Curve:     "Ed25519",
			X:         base64.RawURLEncoding.EncodeToString(publicKey),
		})
	}
	if len(keys) == 0 {
		return nil, ErrInvalidPublicKey
	}
	data, err := json.Marshal(JSONWebKeySet{Keys: keys})
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return data, nil
}

func decodeBase64(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func validCapabilityValues(values []string, resources bool) bool {
	if len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return false
		}
		if resources && !validResource(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validResource(value string) bool {
	_, err := resourcepkg.CanonicalizePattern(value)
	return err == nil
}

func strictTokenParts(raw string) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxLeaseTokenBytes {
		return nil, nil, errors.New("invalid token size")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, errors.New("invalid compact token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if err := rejectDuplicateJSONKeys(headerBytes); err != nil {
		return nil, nil, err
	}
	if err := rejectDuplicateJSONKeys(payloadBytes); err != nil {
		return nil, nil, err
	}
	var header map[string]json.RawMessage
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, err
	}
	allowedClaims := map[string]struct{}{"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {}, "ups": {}, "cnf": {}}
	for name := range payload {
		if _, allowed := allowedClaims[name]; !allowed {
			return nil, nil, errors.New("unexpected token claim")
		}
	}
	var capability map[string]json.RawMessage
	if err := json.Unmarshal(payload["ups"], &capability); err != nil {
		return nil, nil, errors.New("invalid capability claim")
	}
	allowedCapability := map[string]struct{}{
		"version": {}, "lease_id": {}, "root_lease_id": {}, "root_workload_id": {}, "workload_id": {},
		"delegated_by_workload_id": {}, "actions": {}, "resources": {}, "depth": {}, "max_depth": {}, "parent_lease_id": {}, "max_uses": {}, "constraints": {},
	}
	for name := range capability {
		if _, allowed := allowedCapability[name]; !allowed {
			return nil, nil, errors.New("unexpected capability claim")
		}
	}
	for _, required := range []string{"version", "lease_id", "root_lease_id", "root_workload_id", "workload_id", "actions", "resources", "depth", "max_depth", "max_uses", "constraints"} {
		if _, exists := capability[required]; !exists {
			return nil, nil, errors.New("missing capability claim")
		}
	}
	if confirmationRaw, exists := payload["cnf"]; exists {
		var confirmation map[string]json.RawMessage
		if err := json.Unmarshal(confirmationRaw, &confirmation); err != nil || len(confirmation) != 1 {
			return nil, nil, errors.New("invalid confirmation claim")
		}
		if _, exists := confirmation["jkt"]; !exists {
			return nil, nil, errors.New("invalid confirmation claim")
		}
	}
	return header, payload, nil
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
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func keyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
