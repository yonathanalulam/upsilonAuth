package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yonathanalulam/upsilonAuth/sdk/go/autherrors"
)

func TestNewJSONRequestSignsCanonicalRequest(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("workload-a", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return now }
	body := []byte(`{"audience":"service:orders"}`)
	request, err := signer.NewJSONRequest(context.Background(), http.MethodPost, "https://auth.example/v1/leases", body)
	if err != nil {
		t.Fatal(err)
	}
	readBody, err := io.ReadAll(request.Body)
	if err != nil || string(readBody) != string(body) {
		t.Fatalf("request body = %q, error = %v", readBody, err)
	}
	digest := sha256.Sum256(body)
	message := []byte(fmt.Sprintf("POST\n/v1/leases\n%d\n%s\n%s", now.Unix(), request.Header.Get("X-Upsilon-Nonce"), hex.EncodeToString(digest[:])))
	signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Upsilon-Signature"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("request signature verification failed")
	}
}

func TestConsumerMapsAtomicConsumptionResponses(t *testing.T) {
	const consumerToken = "verifier-control-plane-credential"
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/leases/lease-a/consume" || request.Header.Get("Authorization") != "Bearer "+consumerToken || request.Header.Get("Upsilon-Capability") != "token-a" || request.Header.Get("Idempotency-Key") == "" {
			t.Errorf("unexpected request: %s headers=%v", request.URL.Path, request.Header)
		}
		response.WriteHeader(status)
	}))
	defer server.Close()
	consumer, err := NewConsumer(server.URL, consumerToken, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Consume(context.Background(), "lease-a", "token-a", "request-00000000000000000001"); err != nil {
		t.Fatal(err)
	}
	status = http.StatusForbidden
	if err := consumer.Consume(context.Background(), "lease-a", "token-a", "request-00000000000000000002"); !errors.Is(err, autherrors.ErrMaxUsesExceeded) {
		t.Fatalf("Consume() error = %v", err)
	}
}
