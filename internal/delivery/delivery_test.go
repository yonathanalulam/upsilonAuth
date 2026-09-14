package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
)

var testAdminToken = deterministicTestCredential("admin")
var testConsumptionToken = deterministicTestCredential("consumption")

func deterministicTestCredential(label string) string {
	digest := sha256.Sum256([]byte("upsilonauth-test-" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type leaseUsecaseStub struct {
	workload      domain.Workload
	authenticated bool
	issued        domain.IssuedLease
}

func (stub *leaseUsecaseStub) RegisterWorkload(context.Context, domain.RegisterWorkloadRequest) (domain.Workload, error) {
	return stub.workload, nil
}

func (stub *leaseUsecaseStub) GetWorkload(context.Context, string) (domain.Workload, error) {
	return stub.workload, nil
}

func (stub *leaseUsecaseStub) AuthenticateWorkload(context.Context, domain.AuthenticateWorkloadRequest) (domain.Workload, error) {
	if !stub.authenticated {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	return stub.workload, nil
}

func (stub *leaseUsecaseStub) DisableWorkload(context.Context, string, string) (int64, error) {
	return 1, nil
}

func (stub *leaseUsecaseStub) RotateWorkloadKey(context.Context, domain.RotateWorkloadKeyRequest) (domain.Workload, int64, error) {
	return stub.workload, 0, nil
}

func (stub *leaseUsecaseStub) MintRootLease(context.Context, domain.MintRootLeaseRequest) (domain.IssuedLease, error) {
	return stub.issued, nil
}

func (stub *leaseUsecaseStub) GetLease(context.Context, string) (domain.Lease, error) {
	return stub.issued.Lease, nil
}

func (stub *leaseUsecaseStub) TraceLease(context.Context, string) ([]domain.Lease, error) {
	return []domain.Lease{stub.issued.Lease}, nil
}

func (stub *leaseUsecaseStub) ListAuditEvents(context.Context, string, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}

func (stub *leaseUsecaseStub) DelegateLease(context.Context, domain.DelegateLeaseRequest) (domain.IssuedLease, error) {
	return stub.issued, nil
}

func (stub *leaseUsecaseStub) ConsumeLease(_ context.Context, request domain.ConsumeLeaseRequest) (domain.LeaseConsumption, error) {
	return domain.LeaseConsumption{LeaseID: request.LeaseID, IdempotencyKey: request.IdempotencyKey, UseNumber: 1, MaxUses: 1}, nil
}

func (stub *leaseUsecaseStub) RevokeLease(context.Context, domain.RevokeLeaseRequest) (int64, error) {
	return 1, nil
}

func (stub *leaseUsecaseStub) ListActiveRevocations(context.Context) ([]string, error) {
	return []string{"revoked-lease"}, nil
}

func TestJWKS(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response status = %d", response.Code)
	}
	var set authcrypto.JSONWebKeySet
	if err := json.Unmarshal(response.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Curve != "Ed25519" {
		t.Fatalf("unexpected JWKS: %+v", set)
	}
}

func TestRevocationsSupportsConditionalRequests(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	firstRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/revocations.json", nil)
	firstResponse := httptest.NewRecorder()
	handler.Router().ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK || firstResponse.Header().Get("ETag") == "" {
		t.Fatalf("first response = %d etag=%q", firstResponse.Code, firstResponse.Header().Get("ETag"))
	}
	secondRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/revocations.json", nil)
	secondRequest.Header.Set("If-None-Match", firstResponse.Header().Get("ETag"))
	secondResponse := httptest.NewRecorder()
	handler.Router().ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusNotModified {
		t.Fatalf("conditional response = %d", secondResponse.Code)
	}
}

func TestNewHandlerRejectsPredictableAdminToken(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"short", strings.Repeat("a", 64), "replace-with-at-least-32-random-bytes"} {
		if _, err := NewHandler(Config{
			Usecase: &leaseUsecaseStub{}, PublicKeys: []ed25519.PublicKey{publicKey}, AdminToken: token, ConsumptionToken: testConsumptionToken,
			RateLimitPerMinute: 60, RateLimitBurst: 10,
		}); err == nil {
			t.Fatalf("accepted predictable admin token %q", token)
		}
	}
}

func TestControlPlaneRoutesRequireAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/v1/workloads", `{"name":"worker-a","public_key":"invalid"}`},
		{http.MethodPost, "/v1/leases", `{"audience":"service:payments","actions":["read"],"resources":["customer/1"],"ttl":"30s"}`},
		{http.MethodPost, "/v1/leases/lease-a/delegate", `{"actions":["read"],"resources":["customer/1"],"ttl":"20s"}`},
		{http.MethodPost, "/v1/leases/lease-a/revoke", `{}`},
		{http.MethodPost, "/v1/leases/lease-a/consume", ``},
	}
	for _, test := range tests {
		request := httptest.NewRequestWithContext(context.Background(), test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.Router().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d", test.path, response.Code)
		}
		if strings.Contains(response.Body.String(), "token") || strings.Contains(response.Body.String(), "public_key") {
			t.Fatalf("sensitive response leaked: %s", response.Body.String())
		}
	}
}

func TestConsumptionRequiresVerifierCredential(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/leases/lease-a/consume", nil)
	request.Header.Set("Authorization", "Bearer "+testConsumptionToken)
	request.Header.Set("Upsilon-Capability", "lease-token")
	request.Header.Set("Idempotency-Key", "request-00000000000000000001")
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated consumption status = %d: %s", response.Code, response.Body.String())
	}

	stolenTokenRequest := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/leases/lease-a/consume", nil)
	stolenTokenRequest.Header.Set("Authorization", "Bearer lease-token")
	stolenTokenRequest.Header.Set("Upsilon-Capability", "lease-token")
	stolenTokenRequest.Header.Set("Idempotency-Key", "request-00000000000000000002")
	stolenTokenResponse := httptest.NewRecorder()
	handler.Router().ServeHTTP(stolenTokenResponse, stolenTokenRequest)
	if stolenTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("capability-only consumption status = %d", stolenTokenResponse.Code)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{authenticated: true}, publicKey)
	body := `{"audience":"service:test","actions":["` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"],"resources":["x"],"ttl":"30s"}`
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/leases", strings.NewReader(body))
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestReadJSONRejectsDuplicateKeys(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	tests := []string{
		`{"name":"first","name":"second","public_key":"invalid","grant":{}}`,
		`{"name":"workload","public_key":"invalid","grant":{"max_ttl":"1m","max_ttl":"2m"}}`,
	}
	for _, body := range tests {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/workloads", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
		response := httptest.NewRecorder()
		handler.Router().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d for %s", response.Code, http.StatusBadRequest, body)
		}
	}
}

func TestForwardedProtoRequiresTrustedProxy(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		Usecase: &leaseUsecaseStub{}, PublicKeys: []ed25519.PublicKey{publicKey}, AdminToken: testAdminToken, ConsumptionToken: testConsumptionToken,
		RequireTLS: true, TrustForwardedProto: true, TrustedProxies: []string{"10.0.0.0/8"},
		RateLimitPerMinute: 10000, RateLimitBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "203.0.113.9:4000"
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestForwardedProtoFromTrustedProxy(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		Usecase: &leaseUsecaseStub{}, PublicKeys: []ed25519.PublicKey{publicKey}, AdminToken: testAdminToken, ConsumptionToken: testConsumptionToken,
		RequireTLS: true, TrustForwardedProto: true, TrustedProxies: []string{"10.0.0.0/8"},
		RateLimitPerMinute: 10000, RateLimitBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "10.1.2.3:4000"
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestSignedMintRejectsQueryString(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, &leaseUsecaseStub{authenticated: true}, publicKey)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/leases?scope=ignored", strings.NewReader(`{"audience":"service:test","actions":["read"],"resources":["item/1"],"ttl":"30s"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Router().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestRecoveryNeverLogsCredentialHeaders(t *testing.T) {
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	previousMode := gin.Mode()
	gin.SetMode(gin.DebugMode)
	t.Cleanup(func() { gin.SetMode(previousMode) })

	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	handler := newTestHandler(t, &leaseUsecaseStub{}, publicKey)
	router := handler.Router()
	router.GET("/panic", func(*gin.Context) { panic("panic-value-must-not-be-logged") })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/panic", nil)
	request.Header.Set("Authorization", "Bearer admin-token-must-not-be-logged")
	request.Header.Set("DPoP", "proof-must-not-be-logged")
	request.Header.Set("Upsilon-Capability", "capability-must-not-be-logged")
	request.Header.Set("X-Upsilon-Signature", "signature-must-not-be-logged")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("response status = %d", response.Code)
	}
	for _, sensitive := range []string{
		"admin-token-must-not-be-logged",
		"proof-must-not-be-logged",
		"capability-must-not-be-logged",
		"signature-must-not-be-logged",
		"panic-value-must-not-be-logged",
	} {
		if strings.Contains(logs.String(), sensitive) {
			t.Fatalf("recovery log contains sensitive value")
		}
	}
	if !strings.Contains(logs.String(), `"event":"http.panic_recovered"`) {
		t.Fatalf("recovery event was not logged")
	}
}

func newTestHandler(t *testing.T, usecase domain.LeaseUsecase, publicKey ed25519.PublicKey) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		Usecase: usecase, PublicKeys: []ed25519.PublicKey{publicKey}, AdminToken: testAdminToken, ConsumptionToken: testConsumptionToken,
		RateLimitPerMinute: 10000, RateLimitBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
