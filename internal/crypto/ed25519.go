package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid Ed25519 private key")
	ErrInvalidPublicKey  = errors.New("invalid Ed25519 public key")
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

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SignClaims(claims map[string]any, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", ErrInvalidPrivateKey
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	token.Header["kid"] = keyID(publicKey)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

func PublicKeyJWKS(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	key := JSONWebKey{
		KeyType:   "OKP",
		Use:       "sig",
		Algorithm: "EdDSA",
		KeyID:     keyID(publicKey),
		Curve:     "Ed25519",
		X:         base64.RawURLEncoding.EncodeToString(publicKey),
	}

	data, err := json.Marshal(JSONWebKeySet{Keys: []JSONWebKey{key}})
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return data, nil
}

func keyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
