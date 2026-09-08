package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrLeaseNotFound      = errors.New("lease not found")
	ErrInvalidLease       = errors.New("invalid lease")
	ErrInvalidAttenuation = errors.New("invalid attenuation")
)

type Workload struct {
	ID        string
	Name      string
	PublicKey []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Lease struct {
	ID            string
	WorkloadID    string
	Audience      string
	ParentLeaseID *string
	Actions       []string
	Resources     []string
	Expiration    time.Time
	Depth         int
	MaxDepth      int
	TokenHash     []byte
	IssuedAt      time.Time
	RevokedAt     *time.Time
}

type MintRootLeaseRequest struct {
	WorkloadID string
	Audience   string
	Actions    []string
	Resources  []string
	Expiration time.Time
	TTL        time.Duration
	MaxDepth   int
}

type DelegateLeaseRequest struct {
	ParentLeaseID string
	Actions       []string
	Resources     []string
	Expiration    time.Time
	TTL           time.Duration
}

type IssuedLease struct {
	Lease Lease
	Token string
}

type LeaseRepository interface {
	CreateLease(context.Context, Lease) error
	GetLeaseByID(context.Context, string) (Lease, error)
}

type LeaseUsecase interface {
	MintRootLease(context.Context, MintRootLeaseRequest) (IssuedLease, error)
	DelegateLease(context.Context, DelegateLeaseRequest) (IssuedLease, error)
}
