package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	authcrypto "upsilonAuth/internal/crypto"
)

func TestRequire(t *testing.T) {
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

	verifier, err := New(Config{JWKSURL: jwksServer.URL})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	token, err := authcrypto.SignClaims(map[string]any{
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Add(-time.Second).Unix(),
		"sub": "workload-a",
		"ups": map[string]any{
			"actions":   []string{"read"},
			"resources": []string{"orders"},
			"depth":     1,
		},
	}, privateKey)
	if err != nil {
		t.Fatalf("SignClaims() error = %v", err)
	}

	router := gin.New()
	router.GET("/orders", verifier.Require("read", "orders"), func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, claims.Subject)
	})

	request := httptest.NewRequest(http.MethodGet, "/orders", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "workload-a" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestRequireRejectsInsufficientCapability(t *testing.T) {
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
		_, _ = response.Write(jwks)
	}))
	defer jwksServer.Close()
	verifier, err := New(Config{JWKSURL: jwksServer.URL})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	token, err := authcrypto.SignClaims(map[string]any{
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Add(-time.Second).Unix(),
		"ups": map[string]any{
			"actions":   []string{"read"},
			"resources": []string{"orders"},
		},
	}, privateKey)
	if err != nil {
		t.Fatalf("SignClaims() error = %v", err)
	}

	router := gin.New()
	router.DELETE("/orders", verifier.Require("delete", "orders"), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodDelete, "/orders", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("response status = %d", response.Code)
	}
}
