package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
	"github.com/yonathanalulam/upsilonAuth/internal/requestid"
)

const maxRequestBodyBytes int64 = 64 << 10

type Config struct {
	Usecase             domain.LeaseUsecase
	PublicKeys          []ed25519.PublicKey
	AdminToken          string
	ConsumptionToken    string
	RequireTLS          bool
	TrustForwardedProto bool
	TrustedProxies      []string
	RateLimitPerMinute  float64
	RateLimitBurst      int
	Readiness           func(context.Context) error
}

type Handler struct {
	usecase              domain.LeaseUsecase
	publicKeys           []ed25519.PublicKey
	adminTokenHash       [sha256.Size]byte
	consumptionTokenHash [sha256.Size]byte
	requireTLS           bool
	trustForwardedProto  bool
	trustedProxies       []string
	trustedProxyNets     []*net.IPNet
	limiter              *ipLimiter
	readiness            func(context.Context) error
	metrics              metricsState
}

type metricsState struct {
	requests      atomic.Uint64
	denials       atomic.Uint64
	issued        atomic.Uint64
	delegated     atomic.Uint64
	revocations   atomic.Uint64
	latencyMicros atomic.Uint64
}

type leaseRequest struct {
	Audience          string            `json:"audience"`
	Actions           []string          `json:"actions"`
	Resources         []string          `json:"resources"`
	Expiration        time.Time         `json:"expiration"`
	TTL               string            `json:"ttl"`
	MaxDepth          int               `json:"max_depth"`
	ProofOfPossession bool              `json:"proof_of_possession"`
	MaxUses           int               `json:"max_uses"`
	Constraints       map[string]string `json:"constraints"`
}

type delegateRequest struct {
	DelegateTo        string            `json:"delegate_to"`
	Actions           []string          `json:"actions"`
	Resources         []string          `json:"resources"`
	Expiration        time.Time         `json:"expiration"`
	TTL               string            `json:"ttl"`
	ProofOfPossession bool              `json:"proof_of_possession"`
	MaxUses           int               `json:"max_uses"`
	Constraints       map[string]string `json:"constraints"`
}

type rotateWorkloadKeyRequest struct {
	PublicKey         string `json:"public_key"`
	Overlap           string `json:"overlap"`
	RevokeOutstanding bool   `json:"revoke_outstanding"`
}

type workloadRequest struct {
	Name      string               `json:"name"`
	PublicKey string               `json:"public_key"`
	Grant     workloadGrantRequest `json:"grant"`
}

type workloadGrantRequest struct {
	Audiences                []string          `json:"audiences"`
	Actions                  []string          `json:"actions"`
	Resources                []string          `json:"resources"`
	MaxTTL                   string            `json:"max_ttl"`
	MaxDelegationDepth       int               `json:"max_delegation_depth"`
	CanDelegate              bool              `json:"can_delegate"`
	RequireProofOfPossession bool              `json:"require_proof_of_possession"`
	MaxUses                  int               `json:"max_uses"`
	Constraints              map[string]string `json:"constraints"`
}

type leaseResponse struct {
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

type workloadResponse struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	DisabledAt    *time.Time            `json:"disabled_at,omitempty"`
	KeyThumbprint string                `json:"key_thumbprint"`
	Grant         workloadGrantResponse `json:"grant"`
}

type leaseInspectionResponse struct {
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

type auditEventResponse struct {
	ID         int64          `json:"id"`
	WorkloadID *string        `json:"workload_id,omitempty"`
	LeaseID    *string        `json:"lease_id,omitempty"`
	EventType  string         `json:"event_type"`
	Actor      string         `json:"actor"`
	Details    map[string]any `json:"details"`
	OccurredAt time.Time      `json:"occurred_at"`
	RequestID  string         `json:"request_id,omitempty"`
}

type workloadGrantResponse struct {
	Audiences                []string          `json:"audiences"`
	Actions                  []string          `json:"actions"`
	Resources                []string          `json:"resources"`
	MaxTTLSeconds            int64             `json:"max_ttl_seconds"`
	MaxDelegationDepth       int               `json:"max_delegation_depth"`
	CanDelegate              bool              `json:"can_delegate"`
	RequireProofOfPossession bool              `json:"require_proof_of_possession"`
	MaxUses                  int               `json:"max_uses"`
	Constraints              map[string]string `json:"constraints"`
	Version                  int64             `json:"version"`
}

type rateVisitor struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type ipLimiter struct {
	mu       sync.Mutex
	visitors map[string]rateVisitor
	rate     float64
	burst    float64
	requests uint64
}

func NewHandler(config Config) (*Handler, error) {
	if config.Usecase == nil || len(config.PublicKeys) == 0 || !validAdminToken(config.AdminToken) || !validAdminToken(config.ConsumptionToken) || config.AdminToken == config.ConsumptionToken || config.RateLimitPerMinute <= 0 || config.RateLimitBurst <= 0 {
		return nil, errors.New("invalid delivery configuration")
	}
	publicKeys := make([]ed25519.PublicKey, 0, len(config.PublicKeys))
	for _, key := range config.PublicKeys {
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid delivery public key")
		}
		publicKeys = append(publicKeys, append(ed25519.PublicKey(nil), key...))
	}
	trustedProxies, trustedProxyNets, err := parseTrustedProxies(config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if config.TrustForwardedProto && len(trustedProxyNets) == 0 {
		return nil, errors.New("forwarded protocol trust requires trusted proxies")
	}
	return &Handler{
		usecase:              config.Usecase,
		publicKeys:           publicKeys,
		adminTokenHash:       sha256.Sum256([]byte(config.AdminToken)),
		consumptionTokenHash: sha256.Sum256([]byte(config.ConsumptionToken)),
		requireTLS:           config.RequireTLS,
		trustForwardedProto:  config.TrustForwardedProto,
		trustedProxies:       trustedProxies,
		trustedProxyNets:     trustedProxyNets,
		limiter: &ipLimiter{
			visitors: make(map[string]rateVisitor),
			rate:     config.RateLimitPerMinute / 60,
			burst:    float64(config.RateLimitBurst),
		},
		readiness: config.Readiness,
	}, nil
}

func (handler *Handler) Router() *gin.Engine {
	router := gin.New()
	if err := router.SetTrustedProxies(handler.trustedProxies); err != nil {
		panic(err)
	}
	router.Use(handler.requestContext, handler.safeRecovery, handler.requestLogger, handler.securityHeaders, handler.enforceTLS, handler.rateLimit)
	router.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.GET("/readyz", handler.ready)
	router.GET("/metrics", handler.requireAdmin, handler.serveMetrics)
	router.GET("/.well-known/jwks.json", handler.jwks)
	router.GET("/.well-known/revocations.json", handler.revocations)
	router.POST("/v1/workloads", handler.requireAdmin, handler.registerWorkload)
	router.GET("/v1/workloads/:id", handler.requireAdmin, handler.getWorkload)
	router.POST("/v1/workloads/:id/disable", handler.requireAdmin, handler.disableWorkload)
	router.POST("/v1/workloads/:id/rotate-key", handler.requireAdmin, handler.rotateWorkloadKey)
	router.POST("/v1/leases", handler.mintRootLease)
	router.GET("/v1/leases/:id", handler.requireAdmin, handler.getLease)
	router.GET("/v1/leases/:id/trace", handler.requireAdmin, handler.traceLease)
	router.POST("/v1/leases/:id/delegate", handler.delegateLease)
	router.POST("/v1/leases/:id/consume", handler.requireConsumer, handler.consumeLease)
	router.POST("/v1/leases/:id/revoke", handler.requireAdmin, handler.revokeLease)
	router.GET("/v1/audit-events", handler.requireAdmin, handler.listAuditEvents)
	return router
}

func (handler *Handler) requestContext(c *gin.Context) {
	identifier := c.GetHeader("X-Request-ID")
	if !validRequestID(identifier) {
		buffer := make([]byte, 18)
		if _, err := rand.Read(buffer); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		identifier = base64.RawURLEncoding.EncodeToString(buffer)
	}
	c.Header("X-Request-ID", identifier)
	c.Request = c.Request.WithContext(requestid.With(c.Request.Context(), identifier))
	c.Set("upsilon.request_id", identifier)
	c.Next()
}

func (handler *Handler) safeRecovery(c *gin.Context) {
	defer func() {
		if recover() == nil {
			return
		}
		record := map[string]any{
			"event":      "http.panic_recovered",
			"request_id": requestid.FromContext(c.Request.Context()),
			"method":     c.Request.Method,
			"path":       c.FullPath(),
		}
		if encoded, err := json.Marshal(record); err == nil {
			log.Print(string(encoded))
		}
		if c.Writer.Written() {
			c.Abort()
			return
		}
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
	}()
	c.Next()
}

func (handler *Handler) requestLogger(c *gin.Context) {
	started := time.Now()
	c.Next()
	latency := time.Since(started)
	handler.metrics.requests.Add(1)
	handler.metrics.latencyMicros.Add(uint64(max(0, latency.Microseconds())))
	status := c.Writer.Status()
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		handler.metrics.denials.Add(1)
	}
	if status == http.StatusCreated && c.FullPath() == "/v1/leases" {
		handler.metrics.issued.Add(1)
	}
	if status == http.StatusCreated && c.FullPath() == "/v1/leases/:id/delegate" {
		handler.metrics.delegated.Add(1)
	}
	if status == http.StatusOK && c.FullPath() == "/v1/leases/:id/revoke" {
		handler.metrics.revocations.Add(1)
	}
	record := map[string]any{
		"event": "http.request", "request_id": requestid.FromContext(c.Request.Context()), "method": c.Request.Method,
		"path": c.FullPath(), "status": status, "latency_ms": latency.Milliseconds(),
	}
	encoded, err := json.Marshal(record)
	if err == nil {
		log.Print(string(encoded))
	}
}

func (handler *Handler) ready(c *gin.Context) {
	if handler.readiness == nil {
		c.Status(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if err := handler.readiness(ctx); err != nil {
		respondError(c, http.StatusServiceUnavailable, "NOT_READY", "service not ready")
		return
	}
	c.Status(http.StatusNoContent)
}

func (handler *Handler) serveMetrics(c *gin.Context) {
	body := fmt.Sprintf(
		"# TYPE upsilon_http_requests_total counter\nupsilon_http_requests_total %d\n"+
			"# TYPE upsilon_authorization_denials_total counter\nupsilon_authorization_denials_total %d\n"+
			"# TYPE upsilon_lease_issuance_total counter\nupsilon_lease_issuance_total %d\n"+
			"# TYPE upsilon_delegation_total counter\nupsilon_delegation_total %d\n"+
			"# TYPE upsilon_revocation_operations_total counter\nupsilon_revocation_operations_total %d\n"+
			"# TYPE upsilon_http_latency_seconds_sum counter\nupsilon_http_latency_seconds_sum %.6f\n",
		handler.metrics.requests.Load(), handler.metrics.denials.Load(), handler.metrics.issued.Load(),
		handler.metrics.delegated.Load(), handler.metrics.revocations.Load(), float64(handler.metrics.latencyMicros.Load())/1_000_000,
	)
	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(body))
}

func (handler *Handler) securityHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	c.Header("Cross-Origin-Resource-Policy", "same-site")
	c.Header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Permitted-Cross-Domain-Policies", "none")
	if handler.requireTLS {
		c.Header("Strict-Transport-Security", "max-age=31536000")
	}
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Next()
}

func (handler *Handler) enforceTLS(c *gin.Context) {
	secure := c.Request.TLS != nil
	if handler.trustForwardedProto && handler.isTrustedProxy(c.Request.RemoteAddr) {
		secure = secure || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	}
	if handler.requireTLS && !secure {
		respondError(c, http.StatusUpgradeRequired, "TLS_REQUIRED", "tls is required")
		return
	}
	c.Next()
}

func (handler *Handler) rateLimit(c *gin.Context) {
	if !handler.limiter.allow(c.ClientIP(), time.Now()) {
		c.Header("Retry-After", "60")
		respondError(c, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
		return
	}
	c.Next()
}

func (handler *Handler) requireAdmin(c *gin.Context) {
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	digest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(digest[:], handler.adminTokenHash[:]) != 1 {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	c.Next()
}

func (handler *Handler) requireConsumer(c *gin.Context) {
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	digest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(digest[:], handler.consumptionTokenHash[:]) != 1 {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	c.Next()
}

func (handler *Handler) jwks(c *gin.Context) {
	data, err := authcrypto.PublicKeysJWKS(handler.publicKeys)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
		return
	}
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=60, must-revalidate")
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

func (handler *Handler) revocations(c *gin.Context) {
	ids, err := handler.usecase.ListActiveRevocations(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
		return
	}
	digest := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	c.Header("Cache-Control", "private, max-age=0, must-revalidate")
	c.Header("ETag", etag)
	if c.GetHeader("If-None-Match") == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": ids, "generated_at": time.Now().UTC()})
}

func (handler *Handler) registerWorkload(c *gin.Context) {
	var request workloadRequest
	if _, err := readJSON(c, &request); err != nil {
		writeJSONError(c, err)
		return
	}
	publicKey, err := decodePublicKey(request.PublicKey)
	if err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_PUBLIC_KEY", "invalid public key")
		return
	}
	maxTTL, err := time.ParseDuration(request.Grant.MaxTTL)
	if err != nil || maxTTL <= 0 {
		respondError(c, http.StatusBadRequest, "INVALID_GRANT", "invalid workload grant ttl")
		return
	}
	workload, err := handler.usecase.RegisterWorkload(c.Request.Context(), domain.RegisterWorkloadRequest{
		Name: request.Name, PublicKey: publicKey, Actor: "control-plane-admin",
		Grant: domain.AuthorityGrant{
			Audiences: request.Grant.Audiences, Actions: request.Grant.Actions, Resources: request.Grant.Resources,
			MaxTTL: maxTTL, MaxDelegationDepth: request.Grant.MaxDelegationDepth, CanDelegate: request.Grant.CanDelegate,
			RequireProofOfPossession: request.Grant.RequireProofOfPossession,
			MaxUses:                  request.Grant.MaxUses,
			Constraints:              request.Grant.Constraints,
		},
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, workloadResponse{
		ID: workload.ID, Name: workload.Name, CreatedAt: workload.CreatedAt, UpdatedAt: workload.UpdatedAt,
		KeyThumbprint: keyThumbprint(workload.PublicKey),
		Grant: workloadGrantResponse{
			Audiences: workload.Grant.Audiences, Actions: workload.Grant.Actions, Resources: workload.Grant.Resources,
			MaxTTLSeconds: int64(workload.Grant.MaxTTL / time.Second), MaxDelegationDepth: workload.Grant.MaxDelegationDepth,
			CanDelegate: workload.Grant.CanDelegate, RequireProofOfPossession: workload.Grant.RequireProofOfPossession,
			MaxUses: workload.Grant.MaxUses, Constraints: workload.Grant.Constraints, Version: workload.Grant.Version,
		},
	})
}

func (handler *Handler) getWorkload(c *gin.Context) {
	workload, err := handler.usecase.GetWorkload(c.Request.Context(), c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, workloadResponse{
		ID: workload.ID, Name: workload.Name, CreatedAt: workload.CreatedAt, UpdatedAt: workload.UpdatedAt,
		DisabledAt: workload.DisabledAt, KeyThumbprint: keyThumbprint(workload.PublicKey),
		Grant: workloadGrantResponse{
			Audiences: workload.Grant.Audiences, Actions: workload.Grant.Actions, Resources: workload.Grant.Resources,
			MaxTTLSeconds: int64(workload.Grant.MaxTTL / time.Second), MaxDelegationDepth: workload.Grant.MaxDelegationDepth,
			CanDelegate: workload.Grant.CanDelegate, RequireProofOfPossession: workload.Grant.RequireProofOfPossession,
			MaxUses: workload.Grant.MaxUses, Constraints: workload.Grant.Constraints, Version: workload.Grant.Version,
		},
	})
}

func (handler *Handler) disableWorkload(c *gin.Context) {
	workloadID := c.Param("id")
	if workloadID == "" {
		respondError(c, http.StatusBadRequest, "INVALID_WORKLOAD", "invalid workload id")
		return
	}
	revoked, err := handler.usecase.DisableWorkload(c.Request.Context(), workloadID, "control-plane-admin")
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": revoked})
}

func (handler *Handler) rotateWorkloadKey(c *gin.Context) {
	workloadID := c.Param("id")
	var request rotateWorkloadKeyRequest
	if workloadID == "" {
		respondError(c, http.StatusBadRequest, "INVALID_WORKLOAD", "invalid workload id")
		return
	}
	if _, err := readJSON(c, &request); err != nil {
		writeJSONError(c, err)
		return
	}
	publicKey, err := decodePublicKey(request.PublicKey)
	if err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_PUBLIC_KEY", "invalid public key")
		return
	}
	overlap := time.Duration(0)
	if request.Overlap != "" {
		overlap, err = time.ParseDuration(request.Overlap)
		if err != nil || overlap < 0 {
			respondError(c, http.StatusBadRequest, "INVALID_KEY_OVERLAP", "invalid key overlap")
			return
		}
	}
	workload, revoked, err := handler.usecase.RotateWorkloadKey(c.Request.Context(), domain.RotateWorkloadKeyRequest{
		WorkloadID: workloadID, PublicKey: publicKey, Overlap: overlap,
		RevokeOutstanding: request.RevokeOutstanding, Actor: "control-plane-admin",
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": workload.ID, "updated_at": workload.UpdatedAt, "previous_key_expires_at": workload.PreviousKeyExpiresAt,
		"revoked": revoked,
	})
}

func (handler *Handler) mintRootLease(c *gin.Context) {
	var request leaseRequest
	body, err := readJSON(c, &request)
	if err != nil {
		writeJSONError(c, err)
		return
	}
	workload, err := handler.authenticateWorkload(c, body)
	if err != nil {
		writeError(c, err)
		return
	}
	ttl, err := parseTTL(request.TTL, request.Expiration)
	if err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_TTL", "invalid ttl")
		return
	}
	issued, err := handler.usecase.MintRootLease(c.Request.Context(), domain.MintRootLeaseRequest{
		WorkloadID: workload.ID, Audience: request.Audience, Actions: request.Actions, Resources: request.Resources,
		Expiration: request.Expiration, TTL: ttl, MaxDepth: request.MaxDepth,
		ProofOfPossession:          request.ProofOfPossession,
		MaxUses:                    request.MaxUses,
		Constraints:                request.Constraints,
		AuthenticatedKeyThumbprint: workload.AuthenticatedKeyThumbprint,
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, responseFromIssued(issued))
}

func (handler *Handler) delegateLease(c *gin.Context) {
	parentID := c.Param("id")
	parentToken, ok := bearerToken(c.GetHeader("Authorization"))
	if parentID == "" || !ok {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	var request delegateRequest
	body, err := readJSON(c, &request)
	if err != nil {
		writeJSONError(c, err)
		return
	}
	workload, err := handler.authenticateWorkload(c, body)
	if err != nil {
		writeError(c, err)
		return
	}
	ttl, err := parseTTL(request.TTL, request.Expiration)
	if err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_TTL", "invalid ttl")
		return
	}
	issued, err := handler.usecase.DelegateLease(c.Request.Context(), domain.DelegateLeaseRequest{
		ParentLeaseID: parentID, ParentToken: parentToken, DelegatingWorkloadID: workload.ID, DelegateToWorkloadID: request.DelegateTo,
		Actions: request.Actions, Resources: request.Resources,
		Expiration: request.Expiration, TTL: ttl,
		ProofOfPossession:          request.ProofOfPossession,
		MaxUses:                    request.MaxUses,
		Constraints:                request.Constraints,
		AuthenticatedKeyThumbprint: workload.AuthenticatedKeyThumbprint,
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, responseFromIssued(issued))
}

func (handler *Handler) revokeLease(c *gin.Context) {
	leaseID := c.Param("id")
	if leaseID == "" {
		respondError(c, http.StatusBadRequest, "INVALID_LEASE", "invalid lease id")
		return
	}
	count, err := handler.usecase.RevokeLease(c.Request.Context(), domain.RevokeLeaseRequest{LeaseID: leaseID, Actor: "control-plane-admin"})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": count})
}

func (handler *Handler) getLease(c *gin.Context) {
	lease, err := handler.usecase.GetLease(c.Request.Context(), c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, inspectLease(lease))
}

func (handler *Handler) traceLease(c *gin.Context) {
	lineage, err := handler.usecase.TraceLease(c.Request.Context(), c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	response := make([]leaseInspectionResponse, 0, len(lineage))
	for _, lease := range lineage {
		response = append(response, inspectLease(lease))
	}
	c.JSON(http.StatusOK, gin.H{"lineage": response})
}

func (handler *Handler) listAuditEvents(c *gin.Context) {
	limit := 100
	if value := c.Query("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			respondError(c, http.StatusBadRequest, "INVALID_LIMIT", "invalid limit")
			return
		}
		limit = parsed
	}
	events, err := handler.usecase.ListAuditEvents(c.Request.Context(), c.Query("workload_id"), c.Query("lease_id"), limit)
	if err != nil {
		writeError(c, err)
		return
	}
	response := make([]auditEventResponse, 0, len(events))
	for _, event := range events {
		response = append(response, auditEventResponse{
			ID: event.ID, WorkloadID: event.WorkloadID, LeaseID: event.LeaseID, EventType: event.EventType,
			Actor: event.Actor, Details: event.Details, OccurredAt: event.OccurredAt, RequestID: event.RequestID,
		})
	}
	c.JSON(http.StatusOK, gin.H{"events": response})
}

func (handler *Handler) consumeLease(c *gin.Context) {
	leaseID := c.Param("id")
	token := c.GetHeader("Upsilon-Capability")
	idempotencyKey := c.GetHeader("Idempotency-Key")
	if leaseID == "" || token == "" || len(token) > authcrypto.MaxLeaseTokenBytes || idempotencyKey == "" {
		respondError(c, http.StatusBadRequest, "INVALID_CONSUMPTION", "invalid capability consumption request")
		return
	}
	consumption, err := handler.usecase.ConsumeLease(c.Request.Context(), domain.ConsumeLeaseRequest{
		LeaseID: leaseID, Token: token, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"lease_id": consumption.LeaseID, "idempotency_key": consumption.IdempotencyKey,
		"use_number": consumption.UseNumber, "max_uses": consumption.MaxUses, "replayed": consumption.Replayed,
	})
}

func (handler *Handler) authenticateWorkload(c *gin.Context, body []byte) (domain.Workload, error) {
	if c.Request.URL.RawQuery != "" {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	workloadID := c.GetHeader("X-Upsilon-Workload-ID")
	timestampValue := c.GetHeader("X-Upsilon-Timestamp")
	nonce := c.GetHeader("X-Upsilon-Nonce")
	signatureValue := c.GetHeader("X-Upsilon-Signature")
	timestampUnix, err := strconv.ParseInt(timestampValue, 10, 64)
	if err != nil {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureValue)
	if err != nil {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	message := signedRequestMessage(c.Request.Method, c.Request.URL.EscapedPath(), timestampValue, nonce, body)
	return handler.usecase.AuthenticateWorkload(c.Request.Context(), domain.AuthenticateWorkloadRequest{
		WorkloadID: workloadID, Timestamp: time.Unix(timestampUnix, 0).UTC(), Nonce: nonce, Message: message, Signature: signature,
	})
}

func parseTrustedProxies(values []string) ([]string, []*net.IPNet, error) {
	proxies := make([]string, 0, len(values))
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			proxies = append(proxies, value)
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, nil, errors.New("invalid trusted proxy")
		}
		proxies = append(proxies, value)
		networks = append(networks, network)
	}
	return proxies, networks, nil
}

func (handler *Handler) isTrustedProxy(remoteAddress string) bool {
	address := net.ParseIP(clientAddress(remoteAddress))
	if address == nil {
		return false
	}
	for _, network := range handler.trustedProxyNets {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

func readJSON(c *gin.Context, destination any) ([]byte, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("request body must contain one JSON object")
	}
	return body, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return err
	}
	return nil
}

func writeJSONError(c *gin.Context, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		respondError(c, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request body too large")
		return
	}
	respondError(c, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
}

func writeError(c *gin.Context, err error) {
	if errors.Is(err, domain.ErrUnauthenticated) || errors.Is(err, domain.ErrReplayDetected) || errors.Is(err, domain.ErrLeaseRevoked) {
		c.Header("WWW-Authenticate", "Bearer")
		respondError(c, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "authentication failed")
		return
	}
	if errors.Is(err, domain.ErrLeaseNotFound) || errors.Is(err, domain.ErrWorkloadNotFound) {
		respondError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "resource not found")
		return
	}
	if errors.Is(err, domain.ErrConflict) {
		respondError(c, http.StatusConflict, "RESOURCE_CONFLICT", "resource conflict")
		return
	}
	if errors.Is(err, domain.ErrMaxUsesExceeded) {
		respondError(c, http.StatusForbidden, "MAX_USES_EXCEEDED", "capability use limit exceeded")
		return
	}
	if errors.Is(err, domain.ErrAuthorityEscalation) || errors.Is(err, domain.ErrInvalidAttenuation) {
		respondError(c, http.StatusUnprocessableEntity, "AUTHORITY_ESCALATION", "request violates authorization policy")
		return
	}
	if errors.Is(err, domain.ErrInvalidLease) || errors.Is(err, domain.ErrInvalidWorkload) {
		respondError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST", "request violates authorization policy")
		return
	}
	respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
}

func respondError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{
		"error":      gin.H{"code": code, "message": message},
		"request_id": requestid.FromContext(c.Request.Context()),
	})
}

func responseFromIssued(issued domain.IssuedLease) leaseResponse {
	return leaseResponse{
		ID: issued.Lease.ID, Token: issued.Token, WorkloadID: issued.Lease.WorkloadID, Audience: issued.Lease.Audience,
		ParentLeaseID: issued.Lease.ParentLeaseID, Expiration: issued.Lease.Expiration, Depth: issued.Lease.Depth, MaxDepth: issued.Lease.MaxDepth,
		ProofOfPossession: issued.Lease.ConfirmationThumbprint != "",
		MaxUses:           issued.Lease.MaxUses,
		Constraints:       issued.Lease.Constraints,
	}
}

func inspectLease(lease domain.Lease) leaseInspectionResponse {
	return leaseInspectionResponse{
		ID: lease.ID, TokenID: lease.TokenID, WorkloadID: lease.WorkloadID, RootWorkloadID: lease.RootWorkloadID,
		Audience: lease.Audience, ParentLeaseID: lease.ParentLeaseID, RootLeaseID: lease.RootLeaseID,
		DelegatedByWorkloadID: lease.DelegatedByWorkloadID, Actions: lease.Actions, Resources: lease.Resources,
		Expiration: lease.Expiration, IssuedAt: lease.IssuedAt, RevokedAt: lease.RevokedAt, Depth: lease.Depth,
		MaxDepth: lease.MaxDepth, MaxUses: lease.MaxUses, UsesConsumed: lease.UsesConsumed,
		ProofOfPossession: lease.ConfirmationThumbprint != "",
		Constraints:       lease.Constraints,
	}
}

func keyThumbprint(publicKey []byte) string {
	value, _ := authcrypto.JWKThumbprint(ed25519.PublicKey(publicKey))
	return value
}

func parseTTL(value string, expiration time.Time) (time.Duration, error) {
	if value == "" {
		if expiration.IsZero() {
			return 0, errors.New("ttl or expiration is required")
		}
		return 0, nil
	}
	if !expiration.IsZero() {
		return 0, errors.New("ttl and expiration are mutually exclusive")
	}
	ttl, err := time.ParseDuration(value)
	if err != nil || ttl <= 0 {
		return 0, errors.New("ttl must be a positive duration")
	}
	return ttl, nil
}

func signedRequestMessage(method, path, timestamp, nonce string, body []byte) []byte {
	digest := sha256.Sum256(body)
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s", method, path, timestamp, nonce, hex.EncodeToString(digest[:])))
}

func decodePublicKey(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	return decoded, nil
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	returnValue := ""
	valid := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != ""
	if valid {
		returnValue = parts[1]
	}
	return returnValue, valid
}

func validAdminToken(value string) bool {
	if len(value) < 32 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < 24 {
		return false
	}
	counts := make(map[rune]int)
	maximum := 0
	for _, character := range value {
		counts[character]++
		if counts[character] > maximum {
			maximum = counts[character]
		}
	}
	return len(counts) >= 8 && maximum*2 <= len(value)
}

func validRequestID(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func clientAddress(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil && host != "" {
		return host
	}
	return remoteAddress
}

func (limiter *ipLimiter) allow(address string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.requests++
	if limiter.requests%1024 == 0 {
		for key, visitor := range limiter.visitors {
			if now.Sub(visitor.lastSeen) > 10*time.Minute {
				delete(limiter.visitors, key)
			}
		}
	}
	visitor, exists := limiter.visitors[address]
	if !exists {
		if len(limiter.visitors) >= 10000 {
			return false
		}
		visitor = rateVisitor{tokens: limiter.burst, updated: now}
	}
	elapsed := now.Sub(visitor.updated).Seconds()
	visitor.tokens = min(limiter.burst, visitor.tokens+elapsed*limiter.rate)
	visitor.updated = now
	visitor.lastSeen = now
	allowed := visitor.tokens >= 1
	if allowed {
		visitor.tokens--
	}
	limiter.visitors[address] = visitor
	return allowed
}
