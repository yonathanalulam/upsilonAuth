package delivery

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/domain"
)

type Handler struct {
	usecase   domain.LeaseUsecase
	publicKey ed25519.PublicKey
}

type leaseRequest struct {
	WorkloadID string    `json:"workload_id"`
	Audience   string    `json:"audience"`
	Actions    []string  `json:"actions" binding:"required"`
	Resources  []string  `json:"resources" binding:"required"`
	Expiration time.Time `json:"expiration"`
	TTL        string    `json:"ttl"`
	MaxDepth   int       `json:"max_depth"`
}

type delegateRequest struct {
	Actions    []string  `json:"actions" binding:"required"`
	Resources  []string  `json:"resources" binding:"required"`
	Expiration time.Time `json:"expiration"`
	TTL        string    `json:"ttl"`
}

type leaseResponse struct {
	ID            string    `json:"id"`
	Token         string    `json:"token"`
	WorkloadID    string    `json:"workload_id"`
	Audience      string    `json:"audience"`
	ParentLeaseID *string   `json:"parent_lease_id,omitempty"`
	Expiration    time.Time `json:"expiration"`
	Depth         int       `json:"depth"`
	MaxDepth      int       `json:"max_depth"`
}

func NewHandler(usecase domain.LeaseUsecase, publicKey ed25519.PublicKey) *Handler {
	return &Handler{
		usecase:   usecase,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
	}
}

func (handler *Handler) Router() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/.well-known/jwks.json", handler.jwks)
	router.POST("/v1/leases", handler.mintRootLease)
	router.POST("/v1/leases/:id/delegate", handler.delegateLease)
	return router
}

func (handler *Handler) jwks(c *gin.Context) {
	data, err := authcrypto.PublicKeyJWKS(handler.publicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

func (handler *Handler) mintRootLease(c *gin.Context) {
	var request leaseRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ttl, err := parseTTL(request.TTL, request.Expiration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ttl"})
		return
	}

	issued, err := handler.usecase.MintRootLease(c.Request.Context(), domain.MintRootLeaseRequest{
		WorkloadID: request.WorkloadID,
		Audience:   request.Audience,
		Actions:    request.Actions,
		Resources:  request.Resources,
		Expiration: request.Expiration,
		TTL:        ttl,
		MaxDepth:   request.MaxDepth,
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, responseFromIssued(issued))
}

func (handler *Handler) delegateLease(c *gin.Context) {
	parentID := c.Param("id")
	if parentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid parent lease id"})
		return
	}

	var request delegateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ttl, err := parseTTL(request.TTL, request.Expiration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ttl"})
		return
	}

	issued, err := handler.usecase.DelegateLease(c.Request.Context(), domain.DelegateLeaseRequest{
		ParentLeaseID: parentID,
		Actions:       request.Actions,
		Resources:     request.Resources,
		Expiration:    request.Expiration,
		TTL:           ttl,
	})
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, responseFromIssued(issued))
}

func writeError(c *gin.Context, err error) {
	if errors.Is(err, domain.ErrLeaseNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "lease not found"})
		return
	}
	if errors.Is(err, domain.ErrInvalidLease) || errors.Is(err, domain.ErrInvalidAttenuation) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	return
}

func responseFromIssued(issued domain.IssuedLease) leaseResponse {
	return leaseResponse{
		ID:            issued.Lease.ID,
		Token:         issued.Token,
		WorkloadID:    issued.Lease.WorkloadID,
		Audience:      issued.Lease.Audience,
		ParentLeaseID: issued.Lease.ParentLeaseID,
		Expiration:    issued.Lease.Expiration,
		Depth:         issued.Lease.Depth,
		MaxDepth:      issued.Lease.MaxDepth,
	}
}

func parseTTL(value string, expiration time.Time) (time.Duration, error) {
	if value == "" {
		if expiration.IsZero() {
			return 0, errors.New("ttl or expiration is required")
		}
		return 0, nil
	}
	ttl, err := time.ParseDuration(value)
	if err != nil || ttl <= 0 {
		return 0, errors.New("ttl must be a positive duration")
	}
	return ttl, nil
}
