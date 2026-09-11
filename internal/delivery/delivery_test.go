package delivery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/domain"
	upsmiddleware "upsilonAuth/sdk/go/middleware"
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

func TestCapabilityMiddlewareRejectsJWTAttacks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	jwks, err := authcrypto.PublicKeyJWKS(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyJWKS() error = %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(jwks)
	}))
	defer jwksServer.Close()

	verifier, err := upsmiddleware.New(upsmiddleware.Config{
		JWKSURL:  jwksServer.URL,
		Audience: "service:payments",
	})
	if err != nil {
		t.Fatalf("middleware.New() error = %v", err)
	}

	validToken := signCapabilityToken(t, privateKey, time.Now().Add(time.Minute))
	expiredToken := signCapabilityToken(t, privateKey, time.Now().Add(-time.Minute))
	tamperedToken := tamperTokenPayload(t, validToken)
	tamperedSignature := tamperTokenSignature(t, validToken)
	noneToken := tokenWithNoneAlgorithm(t, validToken)

	tests := []struct {
		name          string
		authorization string
	}{
		{
			name: "missing authorization bearer header",
		},
		{
			name:          "expired jwt",
			authorization: "Bearer " + expiredToken,
		},
		{
			name:          "tampered jwt payload",
			authorization: "Bearer " + tamperedToken,
		},
		{
			name:          "tampered jwt signature",
			authorization: "Bearer " + tamperedSignature,
		},
		{
			name:          "none algorithm confusion",
			authorization: "Bearer " + noneToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/protected", verifier.Require("payments:read", "customer/123"), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"protected": "payment data"})
			})
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("response status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if response.Body.String() != `{"error":"invalid bearer token"}` {
				t.Fatalf("response body = %q", response.Body.String())
			}
			if strings.Contains(response.Body.String(), "payment data") || strings.Contains(response.Body.String(), "protected") {
				t.Fatalf("protected handler data leaked: %q", response.Body.String())
			}
		})
	}
}

func signCapabilityToken(t *testing.T, privateKey []byte, expiration time.Time) string {
	t.Helper()
	token, err := authcrypto.SignClaims(map[string]any{
		"aud": "service:payments",
		"exp": expiration.Unix(),
		"iat": time.Now().Add(-time.Second).Unix(),
		"jti": "security-audit-lease",
		"ups": map[string]any{
			"actions":   []string{"payments:read"},
			"resources": []string{"customer/123"},
			"depth":     0,
			"max_depth": 2,
		},
	}, privateKey)
	if err != nil {
		t.Fatalf("SignClaims() error = %v", err)
	}
	return token
}

func tamperTokenPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	claims["aud"] = "service:admin"
	modified, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(modified)
	return strings.Join(parts, ".")
}

func tokenWithNoneAlgorithm(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var values map[string]any
	if err := json.Unmarshal(header, &values); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	values["alg"] = "none"
	modified, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(modified) + "." + parts[1] + "."
}

func tamperTokenSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("empty signature")
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}
