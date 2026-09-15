package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/pop"
)

const testIssuer = "https://issuer.example"
const testAudience = "service:orders"

func TestRequireAcceptsWildcardResource(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	verifier := newVerifier(t, server.URL)
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-a", []string{"read"}, []string{"orders/*"})
	router := gin.New()
	router.GET("/orders/123", verifier.Require("read", "orders/123"), func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, claims.Subject)
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/123", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "workload-a" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestRequireDerivesResourceFromGinContext(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	verifier := newVerifier(t, server.URL)
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-dynamic", []string{"read"}, []string{"orders/*"})
	router := gin.New()
	router.GET("/orders/:orderID", verifier.Require("read", func(c *gin.Context) string {
		return "orders/" + c.Param("orderID")
	}), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/ord_123", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestRequireRejectsJWTAttacks(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	valid := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-a", []string{"read"}, []string{"orders/1"})
	expired := signToken(t, privateKey, time.Now().Add(-time.Minute), "lease-b", []string{"read"}, []string{"orders/1"})
	tests := []struct {
		name  string
		token string
		code  string
	}{
		{"missing", "", "INVALID_SIGNATURE"},
		{"expired", expired, "TOKEN_EXPIRED"},
		{"tampered", tamperSignature(t, valid), "INVALID_SIGNATURE"},
		{"none algorithm", noneAlgorithm(t, valid), "INVALID_SIGNATURE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := newVerifier(t, server.URL)
			router := gin.New()
			router.GET("/protected", verifier.Require("read", "orders/1"), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"protected": "data"})
			})
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "protected") {
				t.Fatalf("protected data leaked: %s", response.Body.String())
			}
		})
	}
}

func TestRequireEnforcesProofOfPossessionAndRejectsReplay(t *testing.T) {
	signingPublicKey, signingPrivateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	workloadPublicKey, workloadPrivateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := authcrypto.JWKThumbprint(workloadPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, signingPublicKey, nil, http.StatusOK)
	verifier := newVerifier(t, server.URL)
	token := signPoPToken(t, signingPrivateKey, thumbprint)
	router := gin.New()
	router.GET("/protected", verifier.Require("read", "orders/1"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	missing := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	missing.Header.Set("Authorization", "Bearer "+token)
	missingResponse := httptest.NewRecorder()
	router.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing proof status = %d", missingResponse.Code)
	}

	proof, err := pop.Sign(workloadPrivateKey, http.MethodGet, "http://example.com/protected", token, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for attempt, want := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("DPoP", proof)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt, response.Code, want)
		}
	}
}

func TestLimitedUseLeaseFailsClosedAndConsumesBeforeHandler(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	var consumed atomic.Int32
	verifier, err := New(Config{
		JWKSURL: server.URL + "/.well-known/jwks.json", RevocationsURL: server.URL + "/.well-known/revocations.json",
		Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true, CacheTTL: time.Second, RevocationCacheTTL: 100 * time.Millisecond,
		ConsumeLease: func(_ context.Context, leaseID, _ string, idempotencyKey string) error {
			if leaseID != "lease-limited" || idempotencyKey != "request-00000000000000000001" {
				t.Errorf("unexpected consumption %q %q", leaseID, idempotencyKey)
			}
			consumed.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signLimitedToken(t, privateKey)
	router := gin.New()
	router.GET("/protected", verifier.Require("read", "orders/1"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "request-00000000000000000001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || consumed.Load() != 1 {
		t.Fatalf("response=%d consumed=%d", response.Code, consumed.Load())
	}

	withoutConsumer := newVerifier(t, server.URL)
	request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if _, err := withoutConsumer.Authorize(request, token, "read", "orders/1"); err == nil {
		t.Fatal("limited-use token was accepted without an atomic consumer")
	}
}

func TestStatelessConstraintsUseLocalRequestContext(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	amount := "99"
	verifier, err := New(Config{
		JWKSURL: server.URL + "/.well-known/jwks.json", RevocationsURL: server.URL + "/.well-known/revocations.json",
		Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true, CacheTTL: time.Second, RevocationCacheTTL: 100 * time.Millisecond,
		ConstraintValues: func(*http.Request) map[string]string {
			return map[string]string{"environment": "prod", "max_transaction_minor_units": amount}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signTokenWithConstraints(t, privateKey, map[string]string{
		"environment": "prod", "http_method": "POST", "max_transaction_minor_units": "100",
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/payments", nil)
	if _, err := verifier.Authorize(request, token, "read", "orders/1"); err != nil {
		t.Fatalf("valid constraints rejected: %v", err)
	}
	amount = "101"
	request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/payments", nil)
	_, err = verifier.Authorize(request, token, "read", "orders/1")
	var authorization *AuthorizationError
	if !errors.As(err, &authorization) || authorization.Code != CodeConstraintNotSatisfied {
		t.Fatalf("over-limit constraint error = %v", err)
	}
	amount = "99"
	request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/payments", nil)
	_, err = verifier.Authorize(request, token, "read", "orders/1")
	if !errors.As(err, &authorization) || authorization.Code != CodeConstraintNotSatisfied {
		t.Fatalf("wrong-method constraint error = %v", err)
	}
}

func TestRequireRejectsRevokedToken(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, []string{"lease-revoked"}, http.StatusOK)
	verifier := newVerifier(t, server.URL)
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-revoked", []string{"read"}, []string{"orders"})
	response := exerciseVerifier(verifier, token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestRequireFailsClosedWhenRevocationUnavailable(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusServiceUnavailable)
	verifier := newVerifier(t, server.URL)
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-a", []string{"read"}, []string{"orders"})
	response := exerciseVerifier(verifier, token)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response status = %d", response.Code)
	}
}

func TestBoundedStaleUsesRecentLastKnownGoodSnapshot(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := authcrypto.PublicKeyJWKS(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/jwks.json" {
			_, _ = response.Write(jwks)
			return
		}
		if unavailable.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"revoked": []string{}, "generated_at": time.Now().UTC()})
	}))
	defer server.Close()
	verifier, err := New(Config{
		JWKSURL: server.URL + "/.well-known/jwks.json", RevocationsURL: server.URL + "/.well-known/revocations.json",
		Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true, CacheTTL: time.Second,
		RevocationMode: RevocationBoundedStale, RevocationCacheTTL: 100 * time.Millisecond, MaxRevocationStaleness: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-stale", []string{"read"}, []string{"orders"})
	if response := exerciseVerifier(verifier, token); response.Code != http.StatusNoContent {
		t.Fatalf("initial response = %d", response.Code)
	}
	unavailable.Store(true)
	time.Sleep(120 * time.Millisecond)
	if response := exerciseVerifier(verifier, token); response.Code != http.StatusNoContent {
		t.Fatalf("bounded stale response = %d", response.Code)
	}
}

func TestExpiryOnlyDoesNotFetchRevocations(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusServiceUnavailable)
	verifier, err := New(Config{
		JWKSURL: server.URL + "/.well-known/jwks.json", Issuer: testIssuer, Audience: testAudience,
		AllowInsecureHTTP: true, CacheTTL: time.Second, RevocationCacheTTL: time.Second, RevocationMode: RevocationExpiryOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-expiry-only", []string{"read"}, []string{"orders"})
	if response := exerciseVerifier(verifier, token); response.Code != http.StatusNoContent {
		t.Fatalf("expiry-only response = %d", response.Code)
	}
}

func TestRequireDoesNotFollowMetadataRedirectsWithCustomClient(t *testing.T) {
	_, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attackerHit := make(chan struct{}, 1)
	attacker := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attackerHit <- struct{}{}
		response.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, attacker.URL, http.StatusFound)
	}))
	defer redirector.Close()

	verifier, err := New(Config{
		JWKSURL: redirector.URL + "/.well-known/jwks.json", Issuer: testIssuer, Audience: testAudience,
		HTTPClient: &http.Client{}, AllowInsecureHTTP: true, CacheTTL: time.Second, RevocationCacheTTL: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-a", []string{"read"}, []string{"orders"})
	response := exerciseVerifier(verifier, token)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	select {
	case <-attackerHit:
		t.Fatal("metadata verifier followed a redirect to another origin")
	default:
	}
}

func TestRequireRejectsMalformedResourceClaim(t *testing.T) {
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := metadataServer(t, publicKey, nil, http.StatusOK)
	verifier := newVerifier(t, server.URL)
	token := signToken(t, privateKey, time.Now().Add(time.Minute), "lease-a", []string{"read"}, []string{"orders/**"})
	response := exerciseVerifier(verifier, token)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func newVerifier(t *testing.T, baseURL string) *Verifier {
	t.Helper()
	verifier, err := New(Config{
		JWKSURL: baseURL + "/.well-known/jwks.json", RevocationsURL: baseURL + "/.well-known/revocations.json",
		Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
		CacheTTL: time.Second, RevocationCacheTTL: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func metadataServer(t *testing.T, publicKey ed25519.PublicKey, revoked []string, revocationStatus int) *httptest.Server {
	t.Helper()
	jwks, err := authcrypto.PublicKeyJWKS(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/.well-known/jwks.json" {
			_, _ = response.Write(jwks)
			return
		}
		if revocationStatus != http.StatusOK {
			response.WriteHeader(revocationStatus)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"revoked": revoked, "generated_at": time.Now().UTC()})
	}))
	t.Cleanup(server.Close)
	return server
}

func signToken(t *testing.T, privateKey ed25519.PrivateKey, expiration time.Time, id string, actions, resources []string) string {
	t.Helper()
	now := time.Now().Add(-time.Second).UTC()
	token, err := authcrypto.SignClaims(map[string]any{
		"aud": testAudience, "exp": expiration.Unix(), "iat": now.Unix(), "iss": testIssuer,
		"jti": "token-" + id, "nbf": now.Unix(), "sub": "workload-a",
		"ups": map[string]any{
			"version": authcrypto.LeaseTokenVersion, "lease_id": id, "root_lease_id": id,
			"root_workload_id": "workload-a", "workload_id": "workload-a",
			"actions": actions, "resources": resources, "depth": 0, "max_depth": 2, "max_uses": 0, "constraints": map[string]string{},
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signTokenWithConstraints(t *testing.T, privateKey ed25519.PrivateKey, constraints map[string]string) string {
	t.Helper()
	now := time.Now().Add(-time.Second).UTC()
	token, err := authcrypto.SignClaims(map[string]any{
		"aud": testAudience, "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "iss": testIssuer,
		"jti": "token-constraints", "nbf": now.Unix(), "sub": "workload-a",
		"ups": map[string]any{
			"version": authcrypto.LeaseTokenVersion, "lease_id": "lease-constraints", "root_lease_id": "lease-constraints",
			"root_workload_id": "workload-a", "workload_id": "workload-a", "actions": []string{"read"},
			"resources": []string{"orders/*"}, "depth": 0, "max_depth": 0, "max_uses": 0, "constraints": constraints,
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signPoPToken(t *testing.T, privateKey ed25519.PrivateKey, thumbprint string) string {
	t.Helper()
	now := time.Now().Add(-time.Second).UTC()
	token, err := authcrypto.SignClaims(map[string]any{
		"aud": testAudience, "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "iss": testIssuer,
		"jti": "token-lease-pop", "nbf": now.Unix(), "sub": "workload-a", "cnf": map[string]any{"jkt": thumbprint},
		"ups": map[string]any{
			"version": authcrypto.LeaseTokenVersion, "lease_id": "lease-pop", "root_lease_id": "lease-pop",
			"root_workload_id": "workload-a", "workload_id": "workload-a",
			"actions": []string{"read"}, "resources": []string{"orders/*"}, "depth": 0, "max_depth": 0, "max_uses": 0, "constraints": map[string]string{},
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signLimitedToken(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()
	now := time.Now().Add(-time.Second).UTC()
	token, err := authcrypto.SignClaims(map[string]any{
		"aud": testAudience, "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "iss": testIssuer,
		"jti": "token-limited", "nbf": now.Unix(), "sub": "workload-a",
		"ups": map[string]any{
			"version": authcrypto.LeaseTokenVersion, "lease_id": "lease-limited", "root_lease_id": "lease-limited",
			"root_workload_id": "workload-a", "workload_id": "workload-a",
			"actions": []string{"read"}, "resources": []string{"orders/*"}, "depth": 0, "max_depth": 0, "max_uses": 1, "constraints": map[string]string{},
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func exerciseVerifier(verifier *Verifier, token string) *httptest.ResponseRecorder {
	router := gin.New()
	router.GET("/protected", verifier.Require("read", "orders"), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func tamperSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}

func noneAlgorithm(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": authcrypto.LeaseTokenType})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + parts[1] + "."
}
