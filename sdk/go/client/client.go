package client

import (
	"bytes"
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
	"net/url"
	"strings"
	"time"

	"github.com/yonathanalulam/upsilonAuth/sdk/go/autherrors"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/pop"
)

const maxConsumerResponseBytes = 4 << 10

type Consumer struct {
	baseURL       *url.URL
	consumerToken string
	client        *http.Client
}

func NewConsumer(baseURL, consumerToken string, httpClient *http.Client, allowInsecureHTTP bool) (*Consumer, error) {
	parsed, err := parseBaseURL(baseURL, allowInsecureHTTP)
	if err != nil || consumerToken == "" || len(consumerToken) > 256 {
		return nil, errors.New("invalid UpsilonAuth consumer configuration")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Consumer{baseURL: parsed, consumerToken: consumerToken, client: httpClient}, nil
}

func (consumer *Consumer) Consume(ctx context.Context, leaseID, token, idempotencyKey string) error {
	if leaseID == "" || token == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		return autherrors.ErrLeaseRejected
	}
	target := *consumer.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + "/v1/leases/" + url.PathEscape(leaseID) + "/consume"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		return autherrors.ErrLeaseRejected
	}
	request.Header.Set("Authorization", "Bearer "+consumer.consumerToken)
	request.Header.Set("Upsilon-Capability", token)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	requestClient := *consumer.client
	requestClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := requestClient.Do(request)
	if err != nil {
		return autherrors.ErrUnavailable
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxConsumerResponseBytes))
	if err := response.Body.Close(); err != nil {
		return autherrors.ErrUnavailable
	}
	switch response.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusForbidden:
		return autherrors.ErrMaxUsesExceeded
	case http.StatusUnauthorized, http.StatusNotFound, http.StatusUnprocessableEntity:
		return autherrors.ErrLeaseRejected
	default:
		return autherrors.ErrUnavailable
	}
}

type Signer struct {
	workloadID string
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

// NewAuthorizedRequest creates a bearer request and adds a DPoP proof bound to
// the signer's workload key. Use it for leases containing a cnf.jkt claim.
func (signer *Signer) NewAuthorizedRequest(ctx context.Context, method, target string, body []byte, accessToken string) (*http.Request, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	proof, err := pop.Sign(signer.privateKey, method, target, accessToken, signer.now().UTC())
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("DPoP", proof)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func NewSigner(workloadID string, privateKey ed25519.PrivateKey) (*Signer, error) {
	if workloadID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid workload signer configuration")
	}
	return &Signer{workloadID: workloadID, privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: time.Now}, nil
}

func (signer *Signer) NewJSONRequest(ctx context.Context, method, target string, body []byte) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return nil, errors.New("signed request URL must not contain a query or fragment")
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate request nonce: %w", err)
	}
	timestamp := fmt.Sprintf("%d", signer.now().UTC().Unix())
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	digest := sha256.Sum256(body)
	message := []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s", method, request.URL.EscapedPath(), timestamp, nonce, hex.EncodeToString(digest[:])))
	signature := ed25519.Sign(signer.privateKey, message)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Upsilon-Workload-ID", signer.workloadID)
	request.Header.Set("X-Upsilon-Timestamp", timestamp)
	request.Header.Set("X-Upsilon-Nonce", nonce)
	request.Header.Set("X-Upsilon-Signature", base64.RawURLEncoding.EncodeToString(signature))
	return request, nil
}
