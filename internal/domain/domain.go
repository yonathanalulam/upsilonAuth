package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrLeaseNotFound       = errors.New("lease not found")
	ErrWorkloadNotFound    = errors.New("workload not found")
	ErrInvalidLease        = errors.New("invalid lease")
	ErrInvalidWorkload     = errors.New("invalid workload")
	ErrInvalidAttenuation  = errors.New("invalid attenuation")
	ErrUnauthenticated     = errors.New("authentication failed")
	ErrReplayDetected      = errors.New("request replay detected")
	ErrLeaseRevoked        = errors.New("lease revoked")
	ErrConflict            = errors.New("resource conflict")
	ErrAuthorityEscalation = errors.New("authority escalation")
	ErrMaxUsesExceeded     = errors.New("maximum capability uses exceeded")
)

type AuthorityGrant struct {
	Audiences                []string
	Actions                  []string
	Resources                []string
	MaxTTL                   time.Duration
	MaxDelegationDepth       int
	CanDelegate              bool
	RequireProofOfPossession bool
	MaxUses                  int
	Constraints              map[string]string
	Version                  int64
}

type Workload struct {
	ID                   string
	Name                 string
	PublicKey            []byte
	PreviousPublicKey    []byte
	PreviousKeyExpiresAt *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DisabledAt           *time.Time
	Grant                AuthorityGrant
	// AuthenticatedKeyThumbprint is transient request-authentication context. It
	// is never persisted or returned by the control-plane API.
	AuthenticatedKeyThumbprint string
}

type Lease struct {
	ID                     string
	TokenID                string
	WorkloadID             string
	RootWorkloadID         string
	Audience               string
	ParentLeaseID          *string
	RootLeaseID            string
	DelegatedByWorkloadID  *string
	Actions                []string
	Resources              []string
	Expiration             time.Time
	Depth                  int
	MaxDepth               int
	TokenHash              []byte
	IssuedAt               time.Time
	RevokedAt              *time.Time
	GrantVersion           int64
	ConfirmationThumbprint string
	MaxUses                int
	UsesConsumed           int
	Constraints            map[string]string
	// AuthenticatedKeyThumbprint binds the database issuance transaction to the
	// exact workload key that authenticated the request. It is not persisted.
	AuthenticatedKeyThumbprint string
}

type AuditEvent struct {
	ID         int64
	WorkloadID *string
	LeaseID    *string
	EventType  string
	Actor      string
	Details    map[string]any
	OccurredAt time.Time
	RequestID  string
}

type RegisterWorkloadRequest struct {
	Name      string
	PublicKey []byte
	Actor     string
	Grant     AuthorityGrant
}

type AuthenticateWorkloadRequest struct {
	WorkloadID string
	Timestamp  time.Time
	Nonce      string
	Message    []byte
	Signature  []byte
}

type MintRootLeaseRequest struct {
	WorkloadID                 string
	Audience                   string
	Actions                    []string
	Resources                  []string
	Expiration                 time.Time
	TTL                        time.Duration
	MaxDepth                   int
	ProofOfPossession          bool
	MaxUses                    int
	Constraints                map[string]string
	AuthenticatedKeyThumbprint string
}

type DelegateLeaseRequest struct {
	ParentLeaseID              string
	ParentToken                string
	DelegatingWorkloadID       string
	DelegateToWorkloadID       string
	Actions                    []string
	Resources                  []string
	Expiration                 time.Time
	TTL                        time.Duration
	ProofOfPossession          bool
	MaxUses                    int
	Constraints                map[string]string
	AuthenticatedKeyThumbprint string
}

type RotateWorkloadKeyRequest struct {
	WorkloadID        string
	PublicKey         []byte
	Overlap           time.Duration
	RevokeOutstanding bool
	Actor             string
}

type RevokeLeaseRequest struct {
	LeaseID string
	Actor   string
}

type ConsumeLeaseRequest struct {
	LeaseID        string
	Token          string
	IdempotencyKey string
}

type LeaseConsumption struct {
	LeaseID        string
	IdempotencyKey string
	UseNumber      int
	MaxUses        int
	Replayed       bool
}

type IssuedLease struct {
	Lease Lease
	Token string
}

type LeaseRepository interface {
	CreateWorkload(context.Context, Workload, AuditEvent) error
	GetWorkloadByID(context.Context, string) (Workload, error)
	ConsumeWorkloadNonce(context.Context, string, []byte, time.Time) error
	DisableWorkload(context.Context, string, string, time.Time) (int64, error)
	RotateWorkloadKey(context.Context, RotateWorkloadKeyRequest, time.Time) (Workload, int64, error)
	CreateLease(context.Context, Lease, AuditEvent) error
	GetLeaseByID(context.Context, string) (Lease, error)
	TraceLease(context.Context, string) ([]Lease, error)
	ListAuditEvents(context.Context, string, string, int) ([]AuditEvent, error)
	ConsumeLeaseUse(context.Context, string, []byte, string, time.Time) (LeaseConsumption, error)
	RevokeLeaseLineage(context.Context, string, string, time.Time) (int64, error)
	ListActiveRevocations(context.Context, time.Time) ([]string, error)
}

type LeaseUsecase interface {
	RegisterWorkload(context.Context, RegisterWorkloadRequest) (Workload, error)
	GetWorkload(context.Context, string) (Workload, error)
	DisableWorkload(context.Context, string, string) (int64, error)
	RotateWorkloadKey(context.Context, RotateWorkloadKeyRequest) (Workload, int64, error)
	AuthenticateWorkload(context.Context, AuthenticateWorkloadRequest) (Workload, error)
	MintRootLease(context.Context, MintRootLeaseRequest) (IssuedLease, error)
	GetLease(context.Context, string) (Lease, error)
	TraceLease(context.Context, string) ([]Lease, error)
	ListAuditEvents(context.Context, string, string, int) ([]AuditEvent, error)
	DelegateLease(context.Context, DelegateLeaseRequest) (IssuedLease, error)
	ConsumeLease(context.Context, ConsumeLeaseRequest) (LeaseConsumption, error)
	RevokeLease(context.Context, RevokeLeaseRequest) (int64, error)
	ListActiveRevocations(context.Context) ([]string, error)
}
