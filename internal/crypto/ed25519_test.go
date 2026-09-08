package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSignClaims(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	token, err := SignClaims(map[string]any{"sub": "workload-a", "exp": 1788868800}, privateKey)
	if err != nil {
		t.Fatalf("SignClaims() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("signature verification failed")
	}
}

func TestSignClaimsRejectsInvalidKey(t *testing.T) {
	_, err := SignClaims(map[string]any{}, ed25519.PrivateKey("invalid"))
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("SignClaims() error = %v, want %v", err, ErrInvalidPrivateKey)
	}
}

func TestPublicKeyJWKS(t *testing.T) {
	publicKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	data, err := PublicKeyJWKS(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyJWKS() error = %v", err)
	}

	var set JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(set.Keys))
	}
	key := set.Keys[0]
	if key.KeyType != "OKP" || key.Curve != "Ed25519" || key.Algorithm != "EdDSA" || key.Use != "sig" {
		t.Fatalf("unexpected JWK: %+v", key)
	}
	wantX := base64.RawURLEncoding.EncodeToString(publicKey)
	if key.X != wantX || key.KeyID == "" {
		t.Fatalf("unexpected key material: %+v", key)
	}
}
