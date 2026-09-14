package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
	"github.com/yonathanalulam/upsilonAuth/internal/requestid"
)

type LeaseRepository struct {
	pool *pgxpool.Pool
}

const workloadKeyLockID int64 = 782347923488

func NewLeaseRepository(pool *pgxpool.Pool) *LeaseRepository {
	return &LeaseRepository{pool: pool}
}

func (repository *LeaseRepository) CreateWorkload(ctx context.Context, workload domain.Workload, event domain.AuditEvent) error {
	return pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workloadKeyLockID); err != nil {
			return fmt.Errorf("lock workload keys: %w", err)
		}
		var keyExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM workloads WHERE public_key = $1 OR (previous_public_key = $1 AND previous_key_expires_at > $2))`,
			workload.PublicKey, workload.CreatedAt,
		).Scan(&keyExists); err != nil {
			return fmt.Errorf("check workload key: %w", err)
		}
		if keyExists {
			return domain.ErrConflict
		}
		audiences, err := json.Marshal(workload.Grant.Audiences)
		if err != nil {
			return fmt.Errorf("marshal workload audiences: %w", err)
		}
		actions, err := json.Marshal(workload.Grant.Actions)
		if err != nil {
			return fmt.Errorf("marshal workload actions: %w", err)
		}
		resources, err := json.Marshal(workload.Grant.Resources)
		if err != nil {
			return fmt.Errorf("marshal workload resources: %w", err)
		}
		constraints, err := json.Marshal(workload.Grant.Constraints)
		if err != nil {
			return fmt.Errorf("marshal workload constraints: %w", err)
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO workloads (
				id, name, public_key, previous_public_key, previous_key_expires_at, created_at, updated_at, disabled_at, allowed_audiences, allowed_actions,
				allowed_resources, max_ttl_seconds, max_delegation_depth, can_delegate, require_proof_of_possession, grant_version, max_uses, grant_constraints
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			workload.ID, workload.Name, workload.PublicKey, workload.PreviousPublicKey, workload.PreviousKeyExpiresAt,
			workload.CreatedAt, workload.UpdatedAt, workload.DisabledAt,
			audiences, actions, resources, int64(workload.Grant.MaxTTL/time.Second), workload.Grant.MaxDelegationDepth,
			workload.Grant.CanDelegate, workload.Grant.RequireProofOfPossession, workload.Grant.Version, workload.Grant.MaxUses, constraints,
		)
		if err != nil {
			if postgresCode(err) == "23505" {
				return domain.ErrConflict
			}
			return fmt.Errorf("insert workload: %w", err)
		}
		return insertAuditEvent(ctx, tx, event)
	})
}

func (repository *LeaseRepository) GetWorkloadByID(ctx context.Context, id string) (domain.Workload, error) {
	var workload domain.Workload
	var audiences, actions, resources, constraints []byte
	var maxTTLSeconds int64
	err := repository.pool.QueryRow(ctx,
		`SELECT id, name, public_key, previous_public_key, previous_key_expires_at, created_at, updated_at, disabled_at, allowed_audiences, allowed_actions,
		        allowed_resources, max_ttl_seconds, max_delegation_depth, can_delegate, require_proof_of_possession, grant_version, max_uses, grant_constraints
		 FROM workloads
		 WHERE id = $1`, id,
	).Scan(
		&workload.ID, &workload.Name, &workload.PublicKey, &workload.PreviousPublicKey, &workload.PreviousKeyExpiresAt,
		&workload.CreatedAt, &workload.UpdatedAt, &workload.DisabledAt,
		&audiences, &actions, &resources, &maxTTLSeconds, &workload.Grant.MaxDelegationDepth, &workload.Grant.CanDelegate,
		&workload.Grant.RequireProofOfPossession, &workload.Grant.Version, &workload.Grant.MaxUses, &constraints,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Workload{}, domain.ErrWorkloadNotFound
	}
	if err != nil {
		return domain.Workload{}, fmt.Errorf("query workload: %w", err)
	}
	if err := json.Unmarshal(audiences, &workload.Grant.Audiences); err != nil {
		return domain.Workload{}, fmt.Errorf("decode workload audiences: %w", err)
	}
	if err := json.Unmarshal(actions, &workload.Grant.Actions); err != nil {
		return domain.Workload{}, fmt.Errorf("decode workload actions: %w", err)
	}
	if err := json.Unmarshal(resources, &workload.Grant.Resources); err != nil {
		return domain.Workload{}, fmt.Errorf("decode workload resources: %w", err)
	}
	if err := json.Unmarshal(constraints, &workload.Grant.Constraints); err != nil {
		return domain.Workload{}, fmt.Errorf("decode workload constraints: %w", err)
	}
	workload.Grant.MaxTTL = time.Duration(maxTTLSeconds) * time.Second
	return workload, nil
}

func (repository *LeaseRepository) RotateWorkloadKey(ctx context.Context, request domain.RotateWorkloadKeyRequest, rotatedAt time.Time) (domain.Workload, int64, error) {
	var workload domain.Workload
	var revoked int64
	err := pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workloadKeyLockID); err != nil {
			return fmt.Errorf("lock workload keys: %w", err)
		}
		var audiences, actions, resources, constraints []byte
		var maxTTLSeconds int64
		err := tx.QueryRow(ctx,
			`SELECT id, name, public_key, previous_public_key, previous_key_expires_at, created_at, updated_at, disabled_at,
			        allowed_audiences, allowed_actions, allowed_resources, max_ttl_seconds, max_delegation_depth,
			        can_delegate, require_proof_of_possession, grant_version, max_uses, grant_constraints
			 FROM workloads WHERE id = $1 FOR UPDATE`, request.WorkloadID,
		).Scan(
			&workload.ID, &workload.Name, &workload.PublicKey, &workload.PreviousPublicKey, &workload.PreviousKeyExpiresAt,
			&workload.CreatedAt, &workload.UpdatedAt, &workload.DisabledAt, &audiences, &actions, &resources, &maxTTLSeconds,
			&workload.Grant.MaxDelegationDepth, &workload.Grant.CanDelegate, &workload.Grant.RequireProofOfPossession, &workload.Grant.Version,
			&workload.Grant.MaxUses, &constraints,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrWorkloadNotFound
		}
		if err != nil {
			return fmt.Errorf("lock workload: %w", err)
		}
		if workload.DisabledAt != nil {
			return domain.ErrInvalidWorkload
		}
		var keyExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(
				SELECT 1 FROM workloads
				WHERE id <> $1 AND (public_key = $2 OR (previous_public_key = $2 AND previous_key_expires_at > $3))
			)`, request.WorkloadID, request.PublicKey, rotatedAt,
		).Scan(&keyExists); err != nil {
			return fmt.Errorf("check workload key: %w", err)
		}
		if keyExists {
			return domain.ErrConflict
		}
		var previousKey []byte
		var previousExpires *time.Time
		if request.Overlap > 0 {
			previousKey = append([]byte(nil), workload.PublicKey...)
			expires := rotatedAt.Add(request.Overlap)
			previousExpires = &expires
		}
		if _, err := tx.Exec(ctx,
			`UPDATE workloads SET public_key = $2, previous_public_key = $3, previous_key_expires_at = $4, updated_at = $5 WHERE id = $1`,
			request.WorkloadID, request.PublicKey, previousKey, previousExpires, rotatedAt,
		); err != nil {
			if postgresCode(err) == "23505" {
				return domain.ErrConflict
			}
			return fmt.Errorf("rotate workload key: %w", err)
		}
		if request.RevokeOutstanding {
			command, err := tx.Exec(ctx,
				`WITH RECURSIVE affected AS (
					SELECT id FROM leases WHERE workload_id = $1
					UNION
					SELECT child.id FROM leases child JOIN affected parent ON child.parent_lease_id = parent.id
				)
				UPDATE leases SET revoked_at = $2 WHERE id IN (SELECT id FROM affected) AND revoked_at IS NULL`,
				request.WorkloadID, rotatedAt,
			)
			if err != nil {
				return fmt.Errorf("revoke workload leases: %w", err)
			}
			revoked = command.RowsAffected()
		}
		if err := json.Unmarshal(audiences, &workload.Grant.Audiences); err != nil {
			return fmt.Errorf("decode workload audiences: %w", err)
		}
		if err := json.Unmarshal(actions, &workload.Grant.Actions); err != nil {
			return fmt.Errorf("decode workload actions: %w", err)
		}
		if err := json.Unmarshal(resources, &workload.Grant.Resources); err != nil {
			return fmt.Errorf("decode workload resources: %w", err)
		}
		if err := json.Unmarshal(constraints, &workload.Grant.Constraints); err != nil {
			return fmt.Errorf("decode workload constraints: %w", err)
		}
		workload.Grant.MaxTTL = time.Duration(maxTTLSeconds) * time.Second
		workload.PreviousPublicKey = previousKey
		workload.PreviousKeyExpiresAt = previousExpires
		workload.PublicKey = append([]byte(nil), request.PublicKey...)
		workload.UpdatedAt = rotatedAt
		event := domain.AuditEvent{
			WorkloadID: &workload.ID, EventType: "workload.key_rotated", Actor: request.Actor,
			Details: map[string]any{"overlap_seconds": int64(request.Overlap / time.Second), "revoked_count": revoked}, OccurredAt: rotatedAt,
		}
		return insertAuditEvent(ctx, tx, event)
	})
	return workload, revoked, err
}

func (repository *LeaseRepository) ConsumeWorkloadNonce(ctx context.Context, workloadID string, nonceHash []byte, expiresAt time.Time) error {
	return pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx,
			`INSERT INTO workload_nonces (workload_id, nonce_hash, expires_at) VALUES ($1, $2, $3)
			 ON CONFLICT (workload_id, nonce_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
			 WHERE workload_nonces.expires_at <= NOW()`,
			workloadID, nonceHash, expiresAt,
		)
		if err != nil {
			return fmt.Errorf("insert workload nonce: %w", err)
		}
		if command.RowsAffected() != 1 {
			return domain.ErrReplayDetected
		}
		return nil
	})
}

func (repository *LeaseRepository) DisableWorkload(ctx context.Context, workloadID, actor string, disabledAt time.Time) (int64, error) {
	var revoked int64
	err := pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx,
			`UPDATE workloads SET disabled_at = COALESCE(disabled_at, $2), updated_at = $2 WHERE id = $1`,
			workloadID, disabledAt,
		)
		if err != nil {
			return fmt.Errorf("disable workload: %w", err)
		}
		if command.RowsAffected() == 0 {
			return domain.ErrWorkloadNotFound
		}
		command, err = tx.Exec(ctx,
			`WITH RECURSIVE affected AS (
				SELECT id FROM leases WHERE workload_id = $1
				UNION
				SELECT child.id FROM leases child JOIN affected parent ON child.parent_lease_id = parent.id
			)
			UPDATE leases SET revoked_at = $2 WHERE id IN (SELECT id FROM affected) AND revoked_at IS NULL`,
			workloadID, disabledAt,
		)
		if err != nil {
			return fmt.Errorf("revoke workload leases: %w", err)
		}
		revoked = command.RowsAffected()
		event := domain.AuditEvent{
			WorkloadID: &workloadID, EventType: "workload.disabled", Actor: actor,
			Details: map[string]any{"revoked_count": revoked}, OccurredAt: disabledAt,
		}
		return insertAuditEvent(ctx, tx, event)
	})
	return revoked, err
}

func (repository *LeaseRepository) CreateLease(ctx context.Context, lease domain.Lease, event domain.AuditEvent) error {
	return pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		var disabledAt, previousKeyExpiresAt *time.Time
		var grantVersion int64
		var currentPublicKey, previousPublicKey []byte
		err := tx.QueryRow(ctx, `SELECT disabled_at, grant_version, public_key, previous_public_key, previous_key_expires_at FROM workloads WHERE id = $1 FOR SHARE`, lease.WorkloadID).Scan(&disabledAt, &grantVersion, &currentPublicKey, &previousPublicKey, &previousKeyExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrWorkloadNotFound
		}
		if err != nil {
			return fmt.Errorf("lock workload: %w", err)
		}
		if disabledAt != nil {
			return domain.ErrUnauthenticated
		}
		if lease.ParentLeaseID == nil && !acceptedWorkloadKey(currentPublicKey, previousPublicKey, previousKeyExpiresAt, lease.AuthenticatedKeyThumbprint, lease.IssuedAt) {
			return domain.ErrUnauthenticated
		}
		if lease.ParentLeaseID == nil && grantVersion != lease.GrantVersion {
			return domain.ErrAuthorityEscalation
		}
		if lease.ParentLeaseID != nil {
			if lease.DelegatedByWorkloadID == nil {
				return domain.ErrInvalidLease
			}
			var delegatorDisabledAt, delegatorPreviousKeyExpiresAt *time.Time
			var delegatorPublicKey, delegatorPreviousPublicKey []byte
			if err := tx.QueryRow(ctx, `SELECT disabled_at, public_key, previous_public_key, previous_key_expires_at FROM workloads WHERE id = $1 FOR SHARE`, *lease.DelegatedByWorkloadID).Scan(&delegatorDisabledAt, &delegatorPublicKey, &delegatorPreviousPublicKey, &delegatorPreviousKeyExpiresAt); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return domain.ErrWorkloadNotFound
				}
				return fmt.Errorf("lock delegating workload: %w", err)
			}
			if delegatorDisabledAt != nil {
				return domain.ErrUnauthenticated
			}
			if !acceptedWorkloadKey(delegatorPublicKey, delegatorPreviousPublicKey, delegatorPreviousKeyExpiresAt, lease.AuthenticatedKeyThumbprint, lease.IssuedAt) {
				return domain.ErrUnauthenticated
			}
			if err := lockLineage(ctx, tx, *lease.ParentLeaseID); err != nil {
				return err
			}
			var revokedAt *time.Time
			var expiration time.Time
			var parentWorkloadID, rootLeaseID, rootWorkloadID string
			var parentDepth, parentMaxDepth, parentMaxUses int
			err := tx.QueryRow(ctx,
				`SELECT revoked_at, expires_at, workload_id, root_lease_id, root_workload_id, depth, max_depth, max_uses
				 FROM leases WHERE id = $1 FOR SHARE`, *lease.ParentLeaseID,
			).Scan(&revokedAt, &expiration, &parentWorkloadID, &rootLeaseID, &rootWorkloadID, &parentDepth, &parentMaxDepth, &parentMaxUses)
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrLeaseNotFound
			}
			if err != nil {
				return fmt.Errorf("lock parent lease: %w", err)
			}
			if revokedAt != nil {
				return domain.ErrLeaseRevoked
			}
			if !expiration.After(lease.IssuedAt) {
				return domain.ErrInvalidLease
			}
			if parentMaxUses > 0 {
				return domain.ErrAuthorityEscalation
			}
			if parentWorkloadID != *lease.DelegatedByWorkloadID || rootLeaseID != lease.RootLeaseID || rootWorkloadID != lease.RootWorkloadID || lease.Depth != parentDepth+1 || lease.MaxDepth > parentMaxDepth {
				return domain.ErrInvalidLease
			}
		} else if lease.RootLeaseID != lease.ID || lease.RootWorkloadID != lease.WorkloadID || lease.DelegatedByWorkloadID != nil || lease.Depth != 0 {
			return domain.ErrInvalidLease
		}

		actions, err := json.Marshal(lease.Actions)
		if err != nil {
			return fmt.Errorf("marshal lease actions: %w", err)
		}
		resources, err := json.Marshal(lease.Resources)
		if err != nil {
			return fmt.Errorf("marshal lease resources: %w", err)
		}
		constraints, err := json.Marshal(lease.Constraints)
		if err != nil {
			return fmt.Errorf("marshal lease constraints: %w", err)
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO leases (
				id, token_id, workload_id, root_workload_id, audience, parent_lease_id, root_lease_id,
				delegated_by_workload_id, actions, resources, expires_at, depth, max_depth, token_hash,
				issued_at, revoked_at, grant_version, confirmation_thumbprint, max_uses, uses_consumed, constraints
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NULLIF($18, ''), $19, $20, $21)`,
			lease.ID, lease.TokenID, lease.WorkloadID, lease.RootWorkloadID, lease.Audience, lease.ParentLeaseID,
			lease.RootLeaseID, lease.DelegatedByWorkloadID, actions, resources, lease.Expiration, lease.Depth,
			lease.MaxDepth, lease.TokenHash, lease.IssuedAt, lease.RevokedAt, lease.GrantVersion, lease.ConfirmationThumbprint,
			lease.MaxUses, lease.UsesConsumed, constraints,
		)
		if err != nil {
			if postgresCode(err) == "23503" {
				return domain.ErrInvalidLease
			}
			return fmt.Errorf("insert lease: %w", err)
		}
		return insertAuditEvent(ctx, tx, event)
	})
}

func (repository *LeaseRepository) GetLeaseByID(ctx context.Context, id string) (domain.Lease, error) {
	var lease domain.Lease
	var actions []byte
	var resources []byte
	var constraints []byte
	err := repository.pool.QueryRow(ctx,
		`SELECT id, token_id, workload_id, root_workload_id, audience, parent_lease_id, root_lease_id,
		        delegated_by_workload_id, actions, resources, expires_at, depth, max_depth, token_hash, issued_at, revoked_at, grant_version,
		        COALESCE(confirmation_thumbprint, ''), max_uses, uses_consumed, constraints
		 FROM leases
		 WHERE id = $1`, id,
	).Scan(
		&lease.ID, &lease.TokenID, &lease.WorkloadID, &lease.RootWorkloadID, &lease.Audience, &lease.ParentLeaseID,
		&lease.RootLeaseID, &lease.DelegatedByWorkloadID, &actions, &resources, &lease.Expiration, &lease.Depth,
		&lease.MaxDepth, &lease.TokenHash, &lease.IssuedAt, &lease.RevokedAt, &lease.GrantVersion, &lease.ConfirmationThumbprint,
		&lease.MaxUses, &lease.UsesConsumed, &constraints,
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
	if err := json.Unmarshal(constraints, &lease.Constraints); err != nil {
		return domain.Lease{}, fmt.Errorf("decode lease constraints: %w", err)
	}
	return lease, nil
}

func (repository *LeaseRepository) TraceLease(ctx context.Context, leaseID string) ([]domain.Lease, error) {
	rows, err := repository.pool.Query(ctx,
		`WITH RECURSIVE ancestors AS (
			SELECT id, parent_lease_id FROM leases WHERE id = $1
			UNION ALL
			SELECT parent.id, parent.parent_lease_id
			FROM leases parent JOIN ancestors child ON child.parent_lease_id = parent.id
		)
		SELECT lease.id, lease.token_id, lease.workload_id, lease.root_workload_id, lease.audience,
		       lease.parent_lease_id, lease.root_lease_id, lease.delegated_by_workload_id,
		       lease.actions, lease.resources, lease.expires_at, lease.depth, lease.max_depth,
		       lease.token_hash, lease.issued_at, lease.revoked_at, lease.grant_version,
		       COALESCE(lease.confirmation_thumbprint, ''), lease.max_uses, lease.uses_consumed, lease.constraints
		FROM leases lease JOIN ancestors ON ancestors.id = lease.id
		ORDER BY lease.depth`, leaseID,
	)
	if err != nil {
		return nil, fmt.Errorf("trace lease: %w", err)
	}
	defer rows.Close()
	lineage := make([]domain.Lease, 0)
	for rows.Next() {
		var lease domain.Lease
		var actions, resources, constraints []byte
		if err := rows.Scan(
			&lease.ID, &lease.TokenID, &lease.WorkloadID, &lease.RootWorkloadID, &lease.Audience,
			&lease.ParentLeaseID, &lease.RootLeaseID, &lease.DelegatedByWorkloadID, &actions, &resources,
			&lease.Expiration, &lease.Depth, &lease.MaxDepth, &lease.TokenHash, &lease.IssuedAt,
			&lease.RevokedAt, &lease.GrantVersion, &lease.ConfirmationThumbprint, &lease.MaxUses, &lease.UsesConsumed, &constraints,
		); err != nil {
			return nil, fmt.Errorf("scan lease lineage: %w", err)
		}
		if err := json.Unmarshal(actions, &lease.Actions); err != nil {
			return nil, fmt.Errorf("decode lineage actions: %w", err)
		}
		if err := json.Unmarshal(resources, &lease.Resources); err != nil {
			return nil, fmt.Errorf("decode lineage resources: %w", err)
		}
		if err := json.Unmarshal(constraints, &lease.Constraints); err != nil {
			return nil, fmt.Errorf("decode lineage constraints: %w", err)
		}
		lineage = append(lineage, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lease lineage: %w", err)
	}
	if len(lineage) == 0 {
		return nil, domain.ErrLeaseNotFound
	}
	return lineage, nil
}

func (repository *LeaseRepository) ListAuditEvents(ctx context.Context, workloadID, leaseID string, limit int) ([]domain.AuditEvent, error) {
	rows, err := repository.pool.Query(ctx,
		`SELECT id, workload_id, lease_id, event_type, actor, details, occurred_at, COALESCE(request_id, '')
		 FROM audit_events
		 WHERE ($1 = '' OR workload_id::text = $1) AND ($2 = '' OR lease_id::text = $2)
		 ORDER BY id DESC LIMIT $3`, workloadID, leaseID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		var event domain.AuditEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.WorkloadID, &event.LeaseID, &event.EventType, &event.Actor, &details, &event.OccurredAt, &event.RequestID); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return nil, fmt.Errorf("decode audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

func (repository *LeaseRepository) ConsumeLeaseUse(ctx context.Context, leaseID string, tokenHash []byte, idempotencyKey string, consumedAt time.Time) (domain.LeaseConsumption, error) {
	var result domain.LeaseConsumption
	err := pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		var storedHash []byte
		var expiresAt time.Time
		var revokedAt, disabledAt *time.Time
		var maxUses, usesConsumed int
		err := tx.QueryRow(ctx,
			`SELECT lease.token_hash, lease.expires_at, lease.revoked_at, lease.max_uses, lease.uses_consumed, workload.disabled_at
			 FROM leases lease
			 JOIN workloads workload ON workload.id = lease.workload_id
			 WHERE lease.id = $1
			 FOR UPDATE OF lease`, leaseID,
		).Scan(&storedHash, &expiresAt, &revokedAt, &maxUses, &usesConsumed, &disabledAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrLeaseNotFound
		}
		if err != nil {
			return fmt.Errorf("lock lease consumption: %w", err)
		}
		if len(tokenHash) != 32 || len(storedHash) != 32 || subtle.ConstantTimeCompare(tokenHash, storedHash) != 1 {
			return domain.ErrUnauthenticated
		}
		if revokedAt != nil || disabledAt != nil {
			return domain.ErrLeaseRevoked
		}
		if !expiresAt.After(consumedAt) || maxUses <= 0 {
			return domain.ErrInvalidLease
		}

		var existingUse int
		err = tx.QueryRow(ctx,
			`SELECT use_number FROM lease_consumptions WHERE lease_id = $1 AND idempotency_key = $2`,
			leaseID, idempotencyKey,
		).Scan(&existingUse)
		if err == nil {
			result = domain.LeaseConsumption{LeaseID: leaseID, IdempotencyKey: idempotencyKey, UseNumber: existingUse, MaxUses: maxUses, Replayed: true}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("query lease consumption: %w", err)
		}
		if usesConsumed >= maxUses {
			return domain.ErrMaxUsesExceeded
		}
		useNumber := usesConsumed + 1
		if _, err := tx.Exec(ctx,
			`INSERT INTO lease_consumptions (lease_id, idempotency_key, use_number, consumed_at) VALUES ($1, $2, $3, $4)`,
			leaseID, idempotencyKey, useNumber, consumedAt,
		); err != nil {
			return fmt.Errorf("insert lease consumption: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE leases SET uses_consumed = $2 WHERE id = $1`, leaseID, useNumber); err != nil {
			return fmt.Errorf("update lease consumption: %w", err)
		}
		result = domain.LeaseConsumption{LeaseID: leaseID, IdempotencyKey: idempotencyKey, UseNumber: useNumber, MaxUses: maxUses}
		return nil
	})
	return result, err
}

func (repository *LeaseRepository) RevokeLeaseLineage(ctx context.Context, leaseID, actor string, revokedAt time.Time) (int64, error) {
	var affected int64
	err := pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		if err := lockLineage(ctx, tx, leaseID); err != nil {
			return err
		}
		command, err := tx.Exec(ctx,
			`WITH RECURSIVE lineage AS (
				SELECT id FROM leases WHERE id = $1
				UNION ALL
				SELECT child.id FROM leases child JOIN lineage parent ON child.parent_lease_id = parent.id
			)
			UPDATE leases SET revoked_at = $2 WHERE id IN (SELECT id FROM lineage) AND revoked_at IS NULL`,
			leaseID, revokedAt,
		)
		if err != nil {
			return fmt.Errorf("revoke lease lineage: %w", err)
		}
		affected = command.RowsAffected()
		if affected == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM leases WHERE id = $1)`, leaseID).Scan(&exists); err != nil {
				return fmt.Errorf("check lease: %w", err)
			}
			if !exists {
				return domain.ErrLeaseNotFound
			}
		}
		event := domain.AuditEvent{
			LeaseID: &leaseID, EventType: "lease.lineage_revoked", Actor: actor,
			Details: map[string]any{"revoked_count": affected}, OccurredAt: revokedAt,
		}
		return insertAuditEvent(ctx, tx, event)
	})
	return affected, err
}

func (repository *LeaseRepository) ListActiveRevocations(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := repository.pool.Query(ctx, `SELECT id FROM leases WHERE revoked_at IS NOT NULL AND expires_at > $1 ORDER BY id`, now)
	if err != nil {
		return nil, fmt.Errorf("query active revocations: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan active revocation: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active revocations: %w", err)
	}
	return ids, nil
}

func lockLineage(ctx context.Context, tx pgx.Tx, leaseID string) error {
	var rootID string
	err := tx.QueryRow(ctx,
		`WITH RECURSIVE ancestors AS (
			SELECT id, parent_lease_id FROM leases WHERE id = $1
			UNION ALL
			SELECT parent.id, parent.parent_lease_id FROM leases parent JOIN ancestors child ON child.parent_lease_id = parent.id
		)
		SELECT id::text FROM ancestors WHERE parent_lease_id IS NULL`,
		leaseID,
	).Scan(&rootID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrLeaseNotFound
	}
	if err != nil {
		return fmt.Errorf("lock lease lineage: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, rootID); err != nil {
		return fmt.Errorf("lock lease lineage: %w", err)
	}
	return nil
}

func insertAuditEvent(ctx context.Context, tx pgx.Tx, event domain.AuditEvent) error {
	details, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	if event.RequestID == "" {
		event.RequestID = requestid.FromContext(ctx)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_events (workload_id, lease_id, event_type, actor, details, occurred_at, request_id)
		 VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))`,
		event.WorkloadID, event.LeaseID, event.EventType, event.Actor, details, event.OccurredAt, event.RequestID,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func postgresCode(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return postgresError.Code
	}
	return ""
}

func acceptedWorkloadKey(current, previous []byte, previousExpiresAt *time.Time, expected string, at time.Time) bool {
	if len(expected) != 43 {
		return false
	}
	currentThumbprint, err := authcrypto.JWKThumbprint(ed25519.PublicKey(current))
	if err == nil && subtle.ConstantTimeCompare([]byte(currentThumbprint), []byte(expected)) == 1 {
		return true
	}
	if previousExpiresAt == nil || !at.Before(*previousExpiresAt) {
		return false
	}
	previousThumbprint, err := authcrypto.JWKThumbprint(ed25519.PublicKey(previous))
	return err == nil && subtle.ConstantTimeCompare([]byte(previousThumbprint), []byte(expected)) == 1
}
