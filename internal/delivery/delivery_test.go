package delivery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/domain"
)

type leaseUsecaseStub struct{}

func (leaseUsecaseStub) MintRootLease(context.Context, domain.MintRootLeaseRequest) (domain.IssuedLease, error) {
	return domain.IssuedLease{}, nil
}

func (leaseUsecaseStub) DelegateLease(context.Context, domain.DelegateLeaseRequest) (domain.IssuedLease, error) {
	return domain.IssuedLease{}, nil
}

func TestJWKS(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	handler := NewHandler(leaseUsecaseStub{}, publicKey)
	request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response status = %d", response.Code)
	}
	var set authcrypto.JSONWebKeySet
	if err := json.Unmarshal(response.Body.Bytes(), &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Curve != "Ed25519" {
		t.Fatalf("unexpected JWKS: %+v", set)
	}
}
