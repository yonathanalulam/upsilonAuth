package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/client"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/middleware"
)

type workloadResponse struct {
	ID string `json:"id"`
}

type leaseResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func main() {
	baseFlag := flag.String("base", "http://127.0.0.1:18080", "")
	admin := flag.String("admin", "", "")
	flag.Parse()
	base := strings.TrimRight(*baseFlag, "/")
	if *admin == "" {
		panic("admin token is required")
	}
	publicKey, privateKey, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	workloadID := enroll(base, *admin, publicKey)
	signer, err := client.NewSigner(workloadID, privateKey)
	if err != nil {
		panic(err)
	}
	body := []byte(`{"audience":"service:payments","actions":["payments:refund"],"resources":["customer/*"],"ttl":"60s","max_depth":2}`)
	request, err := signer.NewJSONRequest(context.Background(), http.MethodPost, base+"/v1/leases", body)
	if err != nil {
		panic(err)
	}
	root := leaseResponse{}
	doJSON(request, http.StatusCreated, &root)
	childBody := []byte(`{"delegate_to":"` + workloadID + `","actions":["payments:refund"],"resources":["customer/cus_123"],"ttl":"30s"}`)
	childRequest, err := signer.NewJSONRequest(context.Background(), http.MethodPost, base+"/v1/leases/"+root.ID+"/delegate", childBody)
	if err != nil {
		panic(err)
	}
	childRequest.Header.Set("Authorization", "Bearer "+root.Token)
	child := leaseResponse{}
	doJSON(childRequest, http.StatusCreated, &child)
	verifier, err := middleware.New(middleware.Config{JWKSURL: base + "/.well-known/jwks.json", RevocationsURL: base + "/.well-known/revocations.json", Issuer: "http://upsilonauth:8080", Audience: "service:payments", AllowInsecureHTTP: true, CacheTTL: time.Second, RevocationCacheTTL: 100 * time.Millisecond})
	if err != nil {
		panic(err)
	}
	protected := gin.New()
	protected.GET("/refund", verifier.Require("payments:refund", "customer/cus_123"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	verify := httptest.NewRecorder()
	verifyRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/refund", nil)
	verifyRequest.Header.Set("Authorization", "Bearer "+child.Token)
	protected.ServeHTTP(verify, verifyRequest)
	if verify.Code != http.StatusNoContent {
		panic(fmt.Sprintf("middleware verification status %d: %s", verify.Code, verify.Body.String()))
	}
	revokeRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/leases/"+root.ID+"/revoke", nil)
	if err != nil {
		panic(err)
	}
	revokeRequest.Header.Set("Authorization", "Bearer "+*admin)
	doJSON(revokeRequest, http.StatusOK, nil)
	time.Sleep(150 * time.Millisecond)
	verify = httptest.NewRecorder()
	protected.ServeHTTP(verify, verifyRequest)
	if verify.Code != http.StatusUnauthorized {
		panic(fmt.Sprintf("revoked token status %d", verify.Code))
	}
	fmt.Println("smoke ok")
}

func enroll(base, admin string, publicKey ed25519.PublicKey) string {
	body, err := json.Marshal(map[string]any{
		"name": "smoke-" + base64.RawURLEncoding.EncodeToString(publicKey[:6]), "public_key": base64.RawURLEncoding.EncodeToString(publicKey),
		"grant": map[string]any{
			"audiences": []string{"service:payments"}, "actions": []string{"payments:refund"},
			"resources": []string{"customer/*"}, "max_ttl": "5m", "max_delegation_depth": 2, "can_delegate": true,
		},
	})
	if err != nil {
		panic(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/workloads", strings.NewReader(string(body)))
	if err != nil {
		panic(err)
	}
	request.Header.Set("Authorization", "Bearer "+admin)
	request.Header.Set("Content-Type", "application/json")
	result := workloadResponse{}
	doJSON(request, http.StatusCreated, &result)
	return result.ID
}

func doJSON(request *http.Request, expected int, destination any) {
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		panic(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != expected {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		panic(fmt.Sprintf("status %d: %s", response.StatusCode, body))
	}
	if destination != nil {
		if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
			panic(err)
		}
	}
}
