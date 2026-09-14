package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestParsePrivateKeyAndVerifyLeaseToken(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKey(base64.RawURLEncoding.EncodeToString(privateKey.Seed()))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equal(privateKey) {
		t.Fatal("parsed private key differs")
	}
	now := time.Now().UTC().Truncate(time.Second)
	token, err := SignClaims(map[string]any{
		"aud": "service:orders", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"iss": "https://issuer.example", "jti": "token-a", "nbf": now.Unix(), "sub": "workload-a",
		"ups": map[string]any{
			"version": LeaseTokenVersion, "lease_id": "lease-a", "root_lease_id": "lease-a",
			"root_workload_id": "workload-a", "workload_id": "workload-a",
			"actions": []string{"read"}, "resources": []string{"orders/*"}, "depth": 0, "max_depth": 2, "max_uses": 0, "constraints": map[string]string{},
		},
	}, parsed)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyLeaseToken(
		token,
		VerificationKeys([]ed25519.PublicKey{publicKey}),
		"https://issuer.example",
		"service:orders",
		5*time.Second,
	)
	if err != nil || claims.ID != "token-a" || claims.UPS.LeaseID != "lease-a" {
		t.Fatalf("VerifyLeaseToken() claims = %+v, error = %v", claims, err)
	}
}

func TestVerifyLeaseTokenRejectsMissingCapabilityClaimAndZeroLifetime(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := map[string]any{
		"aud": "service:orders", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "iss": "https://issuer.example",
		"jti": "token-a", "nbf": now.Unix(), "sub": "workload-a",
		"ups": map[string]any{
			"version": LeaseTokenVersion, "lease_id": "lease-a", "root_lease_id": "lease-a",
			"root_workload_id": "workload-a", "workload_id": "workload-a", "actions": []string{"read"},
			"resources": []string{"orders/*"}, "depth": 0, "max_depth": 0,
		},
	}
	token, err := SignClaims(base, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLeaseToken(token, VerificationKeys([]ed25519.PublicKey{publicKey}), "https://issuer.example", "service:orders", 0); err == nil {
		t.Fatal("accepted token missing required max_uses claim")
	}
	base["ups"].(map[string]any)["max_uses"] = 0
	base["ups"].(map[string]any)["constraints"] = map[string]string{}
	base["exp"] = now.Unix()
	token, err = SignClaims(base, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLeaseToken(token, VerificationKeys([]ed25519.PublicKey{publicKey}), "https://issuer.example", "service:orders", time.Second); err == nil {
		t.Fatal("accepted token whose expiration equals its issuance time")
	}
}
