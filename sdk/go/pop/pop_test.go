package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
)

func TestProofBindsKeyMethodURIAndAccessToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	proof, err := Sign(privateKey, "POST", "https://api.example/payments/1?ignored=true", "lease-token", now)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, _ := authcrypto.JWKThumbprint(publicKey)
	verified, err := Verify(proof, "POST", "https://api.example/payments/1", "lease-token", thumbprint, now, 30*time.Second)
	if err != nil || verified.ID == "" {
		t.Fatalf("Verify() = %+v, %v", verified, err)
	}
	for _, changed := range []struct{ method, target, token string }{
		{"GET", "https://api.example/payments/1", "lease-token"},
		{"POST", "https://api.example/payments/2", "lease-token"},
		{"POST", "https://api.example/payments/1", "other-token"},
	} {
		if _, err := Verify(proof, changed.method, changed.target, changed.token, thumbprint, now, 30*time.Second); err == nil {
			t.Fatalf("changed proof inputs unexpectedly verified: %+v", changed)
		}
	}
}
