package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxAPIResponseBytes = 1 << 20

type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (err *APIError) Error() string {
	if err.Code == "" {
		return fmt.Sprintf("UpsilonAuth request failed with status %d", err.Status)
	}
	return "UpsilonAuth request failed: " + err.Code
}

type ControlPlane struct {
	baseURL *url.URL
	client  *http.Client
}

type LeaseRequest struct {
	Audience          string            `json:"audience"`
	Actions           []string          `json:"actions"`
	Resources         []string          `json:"resources"`
	Expiration        *time.Time        `json:"expiration,omitempty"`
	TTL               string            `json:"ttl,omitempty"`
	MaxDepth          int               `json:"max_depth"`
	ProofOfPossession bool              `json:"proof_of_possession"`
	MaxUses           int               `json:"max_uses"`
	Constraints       map[string]string `json:"constraints"`
}

type DelegationRequest struct {
	DelegateTo        string            `json:"delegate_to"`
	Actions           []string          `json:"actions"`
	Resources         []string          `json:"resources"`
	Expiration        *time.Time        `json:"expiration,omitempty"`
	TTL               string            `json:"ttl,omitempty"`
	ProofOfPossession bool              `json:"proof_of_possession"`
	MaxUses           int               `json:"max_uses"`
	Constraints       map[string]string `json:"constraints"`
}

type IssuedLease struct {
	ID                string            `json:"id"`
	Token             string            `json:"token"`
	WorkloadID        string            `json:"workload_id"`
	Audience          string            `json:"audience"`
	ParentLeaseID     *string           `json:"parent_lease_id,omitempty"`
	Expiration        time.Time         `json:"expiration"`
	Depth             int               `json:"depth"`
	MaxDepth          int               `json:"max_depth"`
	ProofOfPossession bool              `json:"proof_of_possession"`
	MaxUses           int               `json:"max_uses"`
	Constraints       map[string]string `json:"constraints"`
}

type WorkloadGrant struct {
	Audiences                []string          `json:"audiences"`
	Actions                  []string          `json:"actions"`
	Resources                []string          `json:"resources"`
	MaxTTL                   string            `json:"max_ttl,omitempty"`
	MaxTTLSeconds            int64             `json:"max_ttl_seconds,omitempty"`
	MaxDelegationDepth       int               `json:"max_delegation_depth"`
	CanDelegate              bool              `json:"can_delegate"`
	RequireProofOfPossession bool              `json:"require_proof_of_possession"`
	MaxUses                  int               `json:"max_uses"`
	Constraints              map[string]string `json:"constraints"`
	Version                  int64             `json:"version,omitempty"`
}

type RegisterWorkloadRequest struct {
	Name      string        `json:"name"`
	PublicKey string        `json:"public_key"`
	Grant     WorkloadGrant `json:"grant"`
}

func NewRegisterWorkloadRequest(name string, publicKey ed25519.PublicKey, grant WorkloadGrant) (RegisterWorkloadRequest, error) {
	if name == "" || len(publicKey) != ed25519.PublicKeySize {
		return RegisterWorkloadRequest{}, errors.New("invalid workload registration")
	}
	return RegisterWorkloadRequest{
		Name: name, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Grant: grant,
	}, nil
}

type Workload struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	DisabledAt    *time.Time    `json:"disabled_at,omitempty"`
	KeyThumbprint string        `json:"key_thumbprint"`
	Grant         WorkloadGrant `json:"grant"`
}

type LeaseInspection struct {
	ID                    string            `json:"id"`
	TokenID               string            `json:"token_id"`
	WorkloadID            string            `json:"workload_id"`
	RootWorkloadID        string            `json:"root_workload_id"`
	Audience              string            `json:"audience"`
	ParentLeaseID         *string           `json:"parent_lease_id,omitempty"`
	RootLeaseID           string            `json:"root_lease_id"`
	DelegatedByWorkloadID *string           `json:"delegated_by_workload_id,omitempty"`
	Actions               []string          `json:"actions"`
	Resources             []string          `json:"resources"`
	Expiration            time.Time         `json:"expiration"`
	IssuedAt              time.Time         `json:"issued_at"`
	RevokedAt             *time.Time        `json:"revoked_at,omitempty"`
	Depth                 int               `json:"depth"`
	MaxDepth              int               `json:"max_depth"`
	MaxUses               int               `json:"max_uses"`
	UsesConsumed          int               `json:"uses_consumed"`
	ProofOfPossession     bool              `json:"proof_of_possession"`
	Constraints           map[string]string `json:"constraints"`
}

func NewControlPlane(baseURL string, httpClient *http.Client, allowInsecureHTTP bool) (*ControlPlane, error) {
	parsed, err := parseBaseURL(baseURL, allowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &ControlPlane{baseURL: parsed, client: httpClient}, nil
}

func (control *ControlPlane) RegisterWorkload(ctx context.Context, adminToken string, registration RegisterWorkloadRequest) (Workload, error) {
	var result Workload
	err := control.adminJSON(ctx, http.MethodPost, "/v1/workloads", adminToken, registration, &result)
	return result, err
}

func (control *ControlPlane) RequestLease(ctx context.Context, signer *Signer, request LeaseRequest) (IssuedLease, error) {
	var result IssuedLease
	if signer == nil {
		return result, errors.New("workload signer is required")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	httpRequest, err := signer.NewJSONRequest(ctx, http.MethodPost, control.target("/v1/leases"), body)
	if err != nil {
		return result, err
	}
	err = control.do(httpRequest, http.StatusCreated, &result)
	return result, err
}

func (control *ControlPlane) DelegateLease(ctx context.Context, signer *Signer, parentLeaseID, parentToken string, request DelegationRequest) (IssuedLease, error) {
	var result IssuedLease
	if signer == nil || parentLeaseID == "" || parentToken == "" {
		return result, errors.New("signer, parent lease, and parent token are required")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	httpRequest, err := signer.NewJSONRequest(ctx, http.MethodPost, control.target("/v1/leases/"+url.PathEscape(parentLeaseID)+"/delegate"), body)
	if err != nil {
		return result, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+parentToken)
	err = control.do(httpRequest, http.StatusCreated, &result)
	return result, err
}

func (control *ControlPlane) RevokeLease(ctx context.Context, adminToken, leaseID string) (int64, error) {
	var result struct {
		Revoked int64 `json:"revoked"`
	}
	err := control.adminJSON(ctx, http.MethodPost, "/v1/leases/"+url.PathEscape(leaseID)+"/revoke", adminToken, nil, &result)
	return result.Revoked, err
}

func (control *ControlPlane) GetLease(ctx context.Context, adminToken, leaseID string) (LeaseInspection, error) {
	var result LeaseInspection
	err := control.adminJSON(ctx, http.MethodGet, "/v1/leases/"+url.PathEscape(leaseID), adminToken, nil, &result)
	return result, err
}

func (control *ControlPlane) TraceLease(ctx context.Context, adminToken, leaseID string) ([]LeaseInspection, error) {
	var result struct {
		Lineage []LeaseInspection `json:"lineage"`
	}
	err := control.adminJSON(ctx, http.MethodGet, "/v1/leases/"+url.PathEscape(leaseID)+"/trace", adminToken, nil, &result)
	return result.Lineage, err
}

func (control *ControlPlane) adminJSON(ctx context.Context, method, path, adminToken string, body, destination any) error {
	if adminToken == "" {
		return errors.New("admin token is required")
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, control.target(path), bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	expected := http.StatusOK
	if method == http.MethodPost && path == "/v1/workloads" {
		expected = http.StatusCreated
	}
	return control.do(request, expected, destination)
}

func (control *ControlPlane) do(request *http.Request, expectedStatus int, destination any) error {
	requestClient := *control.client
	requestClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := requestClient.Do(request)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseBytes+1))
	if err != nil {
		_ = response.Body.Close()
		return err
	}
	if err := response.Body.Close(); err != nil {
		return err
	}
	if len(data) > maxAPIResponseBytes {
		return errors.New("UpsilonAuth response is too large")
	}
	if response.StatusCode != expectedStatus {
		return decodeAPIError(response.StatusCode, data)
	}
	if destination == nil || len(data) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func (control *ControlPlane) target(path string) string {
	target := *control.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawQuery = ""
	target.Fragment = ""
	return target.String()
}

func parseBaseURL(value string, allowInsecureHTTP bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	secureScheme := parsed != nil && (parsed.Scheme == "https" || allowInsecureHTTP && parsed.Scheme == "http")
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !secureScheme {
		return nil, errors.New("invalid UpsilonAuth base URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func decodeAPIError(status int, data []byte) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(data, &envelope)
	return &APIError{Status: status, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.RequestID}
}
