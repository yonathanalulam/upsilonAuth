package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
)

func TestRepositoryAtomicSecurityOperations(t *testing.T) {
	databaseURL := os.Getenv("UPSILON_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("UPSILON_TEST_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := ApplyMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := VerifyMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("verify migrations: %v", err)
	}
	repository := NewLeaseRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	workload := domain.Workload{
		ID: "00000000-0000-4000-8000-000000000001", Name: "concurrency-worker", PublicKey: publicKey,
		CreatedAt: now, UpdatedAt: now,
		Grant: domain.AuthorityGrant{
			Audiences: []string{"service:test"}, Actions: []string{"read"}, Resources: []string{"item/*"},
			MaxTTL: time.Minute, MaxDelegationDepth: 0, MaxUses: 1, Constraints: map[string]string{}, Version: 1,
		},
	}
	if err := repository.CreateWorkload(ctx, workload, domain.AuditEvent{
		WorkloadID: &workload.ID, EventType: "workload.registered", Actor: "integration-test", Details: map[string]any{}, OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("nonce reuse has one winner", func(t *testing.T) {
		nonceHash := sha256.Sum256([]byte("one nonce used concurrently"))
		var accepted atomic.Int32
		var replayed atomic.Int32
		runConcurrent(32, func(index int) {
			err := repository.ConsumeWorkloadNonce(ctx, workload.ID, nonceHash[:], now.Add(time.Minute))
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, domain.ErrReplayDetected):
				replayed.Add(1)
			default:
				t.Errorf("consume nonce %d: %v", index, err)
			}
		})
		if accepted.Load() != 1 || replayed.Load() != 31 {
			t.Fatalf("accepted=%d replayed=%d", accepted.Load(), replayed.Load())
		}
	})

	t.Run("final use cannot be double spent", func(t *testing.T) {
		lease, tokenHash := createLimitedLease(t, repository, workload, now, "00000000-0000-4000-8000-000000000101")
		var accepted atomic.Int32
		var exhausted atomic.Int32
		runConcurrent(32, func(index int) {
			key := fmt.Sprintf("request-key-000000000000000000000000-%02d", index)
			_, err := repository.ConsumeLeaseUse(ctx, lease.ID, tokenHash, key, now)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, domain.ErrMaxUsesExceeded):
				exhausted.Add(1)
			default:
				t.Errorf("consume lease %d: %v", index, err)
			}
		})
		if accepted.Load() != 1 || exhausted.Load() != 31 {
			t.Fatalf("accepted=%d exhausted=%d", accepted.Load(), exhausted.Load())
		}
	})

	t.Run("same idempotency key returns one consumption", func(t *testing.T) {
		lease, tokenHash := createLimitedLease(t, repository, workload, now, "00000000-0000-4000-8000-000000000102")
		const key = "retry-key-0000000000000000000000000001"
		var first atomic.Int32
		var replayed atomic.Int32
		runConcurrent(32, func(index int) {
			consumption, err := repository.ConsumeLeaseUse(ctx, lease.ID, tokenHash, key, now)
			if err != nil {
				t.Errorf("consume lease %d: %v", index, err)
				return
			}
			if consumption.UseNumber != 1 {
				t.Errorf("use number = %d", consumption.UseNumber)
			}
			if consumption.Replayed {
				replayed.Add(1)
			} else {
				first.Add(1)
			}
		})
		if first.Load() != 1 || replayed.Load() != 31 {
			t.Fatalf("first=%d replayed=%d", first.Load(), replayed.Load())
		}
	})

	t.Run("revocation racing delegation leaves no active child", func(t *testing.T) {
		delegator := createIntegrationWorkload(t, repository, now, "00000000-0000-4000-8000-000000000011", "delegator", 2)
		recipient := createIntegrationWorkload(t, repository, now, "00000000-0000-4000-8000-000000000012", "recipient", 0)
		parent := integrationRootLease(t, delegator, now, "00000000-0000-4000-8000-000000000201", 2)
		if err := repository.CreateLease(ctx, parent, integrationLeaseEvent(parent, now)); err != nil {
			t.Fatal(err)
		}
		parentID := parent.ID
		delegatorID := delegator.ID
		child := domain.Lease{
			ID: "00000000-0000-4000-8000-000000000202", TokenID: "10000000-0000-4000-8000-000000000202",
			WorkloadID: recipient.ID, RootWorkloadID: delegator.ID, Audience: "service:test",
			ParentLeaseID: &parentID, RootLeaseID: parent.ID, DelegatedByWorkloadID: &delegatorID,
			Actions: []string{"read"}, Resources: []string{"item/1"}, Expiration: now.Add(30 * time.Second),
			Depth: 1, MaxDepth: 2, TokenHash: sha256Bytes("child-token"), IssuedAt: now,
			GrantVersion: 1, Constraints: map[string]string{}, AuthenticatedKeyThumbprint: parent.AuthenticatedKeyThumbprint,
		}
		ready := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		var createErr, revokeErr error
		go func() {
			defer group.Done()
			<-ready
			createErr = repository.CreateLease(ctx, child, integrationLeaseEvent(child, now))
		}()
		go func() {
			defer group.Done()
			<-ready
			_, revokeErr = repository.RevokeLeaseLineage(ctx, parent.ID, "integration-test", now)
		}()
		close(ready)
		group.Wait()
		if revokeErr != nil {
			t.Fatalf("revoke lineage: %v", revokeErr)
		}
		if createErr != nil && !errors.Is(createErr, domain.ErrLeaseRevoked) {
			t.Fatalf("create child race: %v", createErr)
		}
		if createErr == nil {
			persisted, err := repository.GetLeaseByID(ctx, child.ID)
			if err != nil || persisted.RevokedAt == nil {
				t.Fatalf("child survived parent revocation: lease=%+v err=%v", persisted, err)
			}
		}
	})

	t.Run("disable racing root issuance leaves no active lease", func(t *testing.T) {
		target := createIntegrationWorkload(t, repository, now, "00000000-0000-4000-8000-000000000021", "disable-race", 0)
		lease := integrationRootLease(t, target, now, "00000000-0000-4000-8000-000000000301", 0)
		ready := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		var createErr, disableErr error
		go func() {
			defer group.Done()
			<-ready
			createErr = repository.CreateLease(ctx, lease, integrationLeaseEvent(lease, now))
		}()
		go func() {
			defer group.Done()
			<-ready
			_, disableErr = repository.DisableWorkload(ctx, target.ID, "integration-test", now)
		}()
		close(ready)
		group.Wait()
		if disableErr != nil {
			t.Fatalf("disable workload: %v", disableErr)
		}
		if createErr != nil && !errors.Is(createErr, domain.ErrUnauthenticated) {
			t.Fatalf("create lease race: %v", createErr)
		}
		if createErr == nil {
			persisted, err := repository.GetLeaseByID(ctx, lease.ID)
			if err != nil || persisted.RevokedAt == nil {
				t.Fatalf("lease survived workload disable: lease=%+v err=%v", persisted, err)
			}
		}
	})

	t.Run("emergency rotation invalidates pre-rotation authentication", func(t *testing.T) {
		target := createIntegrationWorkload(t, repository, now, "00000000-0000-4000-8000-000000000031", "rotation-race", 0)
		lease := integrationRootLease(t, target, now, "00000000-0000-4000-8000-000000000401", 0)
		newPublicKey, _, err := authcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := repository.RotateWorkloadKey(ctx, domain.RotateWorkloadKeyRequest{
			WorkloadID: target.ID, PublicKey: newPublicKey, Actor: "integration-test",
		}, now); err != nil {
			t.Fatal(err)
		}
		if err := repository.CreateLease(ctx, lease, integrationLeaseEvent(lease, now)); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("lease authenticated with retired key error = %v", err)
		}
	})
}

func createIntegrationWorkload(t *testing.T, repository *LeaseRepository, now time.Time, id, name string, maxDepth int) domain.Workload {
	t.Helper()
	publicKey, _, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	workload := domain.Workload{
		ID: id, Name: name, PublicKey: publicKey, CreatedAt: now, UpdatedAt: now,
		Grant: domain.AuthorityGrant{
			Audiences: []string{"service:test"}, Actions: []string{"read"}, Resources: []string{"item/*"},
			MaxTTL: time.Minute, MaxDelegationDepth: maxDepth, CanDelegate: maxDepth > 0,
			Constraints: map[string]string{}, Version: 1,
		},
	}
	if err := repository.CreateWorkload(context.Background(), workload, domain.AuditEvent{
		WorkloadID: &workload.ID, EventType: "workload.registered", Actor: "integration-test", Details: map[string]any{}, OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return workload
}

func integrationRootLease(t *testing.T, workload domain.Workload, now time.Time, id string, maxDepth int) domain.Lease {
	t.Helper()
	thumbprint, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return domain.Lease{
		ID: id, TokenID: "1" + id[1:], WorkloadID: workload.ID, RootWorkloadID: workload.ID,
		Audience: "service:test", RootLeaseID: id, Actions: []string{"read"}, Resources: []string{"item/*"},
		Expiration: now.Add(time.Minute), Depth: 0, MaxDepth: maxDepth, TokenHash: sha256Bytes("token:" + id),
		IssuedAt: now, GrantVersion: 1, Constraints: map[string]string{}, AuthenticatedKeyThumbprint: thumbprint,
	}
}

func integrationLeaseEvent(lease domain.Lease, now time.Time) domain.AuditEvent {
	return domain.AuditEvent{
		WorkloadID: &lease.WorkloadID, LeaseID: &lease.ID, EventType: "lease.root_minted",
		Actor: "integration-test", Details: map[string]any{}, OccurredAt: now,
	}
}

func sha256Bytes(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func createLimitedLease(t *testing.T, repository *LeaseRepository, workload domain.Workload, now time.Time, id string) (domain.Lease, []byte) {
	t.Helper()
	tokenHash := sha256.Sum256([]byte("token:" + id))
	authenticatedKey, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	lease := domain.Lease{
		ID: id, TokenID: "10000000" + id[8:], WorkloadID: workload.ID, RootWorkloadID: workload.ID,
		Audience: "service:test", RootLeaseID: id, Actions: []string{"read"}, Resources: []string{"item/*"},
		Expiration: now.Add(time.Minute), Depth: 0, MaxDepth: 0, TokenHash: tokenHash[:], IssuedAt: now,
		GrantVersion: 1, MaxUses: 1, Constraints: map[string]string{}, AuthenticatedKeyThumbprint: authenticatedKey,
	}
	if err := repository.CreateLease(context.Background(), lease, domain.AuditEvent{
		WorkloadID: &workload.ID, LeaseID: &lease.ID, EventType: "lease.root_minted", Actor: workload.ID, Details: map[string]any{}, OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return lease, tokenHash[:]
}

func runConcurrent(count int, function func(int)) {
	ready := make(chan struct{})
	var group sync.WaitGroup
	group.Add(count)
	for index := 0; index < count; index++ {
		go func(index int) {
			defer group.Done()
			<-ready
			function(index)
		}(index)
	}
	close(ready)
	group.Wait()
}
