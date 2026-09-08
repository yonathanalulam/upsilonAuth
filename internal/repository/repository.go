package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"upsilonAuth/internal/domain"
)

type LeaseRepository struct {
	pool *pgxpool.Pool
}

func NewLeaseRepository(pool *pgxpool.Pool) *LeaseRepository {
	return &LeaseRepository{pool: pool}
}

func (repository *LeaseRepository) CreateLease(ctx context.Context, lease domain.Lease) error {
	actions, err := json.Marshal(lease.Actions)
	if err != nil {
		return fmt.Errorf("marshal lease actions: %w", err)
	}
	resources, err := json.Marshal(lease.Resources)
	if err != nil {
		return fmt.Errorf("marshal lease resources: %w", err)
	}
	var workloadID any
	if lease.WorkloadID != "" {
		workloadID = lease.WorkloadID
	}

	_, err = repository.pool.Exec(
		ctx,
		`INSERT INTO leases (id, workload_id, audience, parent_lease_id, actions, resources, expires_at, depth, max_depth, token_hash, issued_at, revoked_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		lease.ID,
		workloadID,
		lease.Audience,
		lease.ParentLeaseID,
		actions,
		resources,
		lease.Expiration,
		lease.Depth,
		lease.MaxDepth,
		lease.TokenHash,
		lease.IssuedAt,
		lease.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("insert lease: %w", err)
	}
	return nil
}

func (repository *LeaseRepository) GetLeaseByID(ctx context.Context, id string) (domain.Lease, error) {
	var lease domain.Lease
	var actions []byte
	var resources []byte
	var workloadID *string

	err := repository.pool.QueryRow(
		ctx,
		`SELECT id, workload_id, audience, parent_lease_id, actions, resources, expires_at, depth, max_depth, token_hash, issued_at, revoked_at
		 FROM leases
		 WHERE id = $1`,
		id,
	).Scan(
		&lease.ID,
		&workloadID,
		&lease.Audience,
		&lease.ParentLeaseID,
		&actions,
		&resources,
		&lease.Expiration,
		&lease.Depth,
		&lease.MaxDepth,
		&lease.TokenHash,
		&lease.IssuedAt,
		&lease.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Lease{}, domain.ErrLeaseNotFound
	}
	if err != nil {
		return domain.Lease{}, fmt.Errorf("query lease: %w", err)
	}
	if err := json.Unmarshal(actions, &lease.Actions); err != nil {
		return domain.Lease{}, fmt.Errorf("decode lease actions: %w", err)
	}
	if err := json.Unmarshal(resources, &lease.Resources); err != nil {
		return domain.Lease{}, fmt.Errorf("decode lease resources: %w", err)
	}
	if workloadID != nil {
		lease.WorkloadID = *workloadID
	}
	return lease, nil
}
