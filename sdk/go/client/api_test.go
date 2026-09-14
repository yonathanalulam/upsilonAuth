package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlPlaneRequestLeaseUsesSignedRequest(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("workload-a", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/leases" || request.Header.Get("X-Upsilon-Workload-ID") != "workload-a" || request.Header.Get("X-Upsilon-Signature") == "" {
			t.Errorf("request was not workload-signed: %s %s", request.Method, request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"id":"lease-a","token":"token-a","workload_id":"workload-a","audience":"service:test","expiration":"2026-09-14T12:00:00Z","depth":0,"max_depth":1,"proof_of_possession":false,"max_uses":0,"constraints":{}}`))
	}))
	defer server.Close()
	control, err := NewControlPlane(server.URL, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := control.RequestLease(context.Background(), signer, LeaseRequest{
		Audience: "service:test", Actions: []string{"read"}, Resources: []string{"item/*"}, TTL: "30s", MaxDepth: 1,
		Constraints: map[string]string{},
	})
	if err != nil || lease.ID != "lease-a" || lease.Token != "token-a" {
		t.Fatalf("RequestLease() = %+v, %v", lease, err)
	}
}

func TestControlPlaneReturnsStructuredAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"error":      map[string]string{"code": "AUTHORITY_ESCALATION", "message": "request violates authorization policy"},
			"request_id": "request-123456789",
		})
	}))
	defer server.Close()
	control, err := NewControlPlane(server.URL, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = control.GetLease(context.Background(), "admin-token", "lease-a")
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Code != "AUTHORITY_ESCALATION" || apiError.RequestID != "request-123456789" || apiError.Status != http.StatusUnprocessableEntity {
		t.Fatalf("structured error = %#v", err)
	}
}
