package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
)

const testAuthenticatedKeyThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type leaseRepositoryStub struct {
	workload domain.Workload
	parent   domain.Lease
	created  domain.Lease
	nonces   map[string]struct{}
	revoked  []string
}

func (repository *leaseRepositoryStub) CreateWorkload(_ context.Context, workload domain.Workload, _ domain.AuditEvent) error {
	repository.workload = workload
	return nil
}

func (repository *leaseRepositoryStub) GetWorkloadByID(_ context.Context, id string) (domain.Workload, error) {
	if id != repository.workload.ID {
		return domain.Workload{}, domain.ErrWorkloadNotFound
	}
	return repository.workload, nil
}

func (repository *leaseRepositoryStub) ConsumeWorkloadNonce(_ context.Context, _ string, nonce []byte, _ time.Time) error {
	if repository.nonces == nil {
		repository.nonces = make(map[string]struct{})
	}
	key := string(nonce)
	if _, exists := repository.nonces[key]; exists {
		return domain.ErrReplayDetected
	}
	repository.nonces[key] = struct{}{}
	return nil
}

func (repository *leaseRepositoryStub) DisableWorkload(context.Context, string, string, time.Time) (int64, error) {
	return 1, nil
}

func (repository *leaseRepositoryStub) RotateWorkloadKey(_ context.Context, request domain.RotateWorkloadKeyRequest, now time.Time) (domain.Workload, int64, error) {
	repository.workload.PreviousPublicKey = append([]byte(nil), repository.workload.PublicKey...)
	repository.workload.PublicKey = append([]byte(nil), request.PublicKey...)
	repository.workload.UpdatedAt = now
	return repository.workload, 0, nil
}

func (repository *leaseRepositoryStub) CreateLease(_ context.Context, lease domain.Lease, _ domain.AuditEvent) error {
	repository.created = lease
	return nil
}

func (repository *leaseRepositoryStub) GetLeaseByID(_ context.Context, id string) (domain.Lease, error) {
	if id != repository.parent.ID {
		return domain.Lease{}, domain.ErrLeaseNotFound
	}
	return repository.parent, nil
}

func (repository *leaseRepositoryStub) TraceLease(_ context.Context, id string) ([]domain.Lease, error) {
	if id != repository.parent.ID {
		return nil, domain.ErrLeaseNotFound
	}
	return []domain.Lease{repository.parent}, nil
}

func (repository *leaseRepositoryStub) ListAuditEvents(context.Context, string, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}

func (repository *leaseRepositoryStub) ConsumeLeaseUse(_ context.Context, leaseID string, _ []byte, idempotencyKey string, _ time.Time) (domain.LeaseConsumption, error) {
	return domain.LeaseConsumption{LeaseID: leaseID, IdempotencyKey: idempotencyKey, UseNumber: 1, MaxUses: repository.parent.MaxUses}, nil
}

func (repository *leaseRepositoryStub) RevokeLeaseLineage(_ context.Context, id, _ string, _ time.Time) (int64, error) {
	if id != repository.parent.ID {
		return 0, domain.ErrLeaseNotFound
	}
	return 1, nil
}

func (repository *leaseRepositoryStub) ListActiveRevocations(context.Context, time.Time) ([]string, error) {
	return append([]string(nil), repository.revoked...), nil
}

func TestAuthenticateWorkloadRejectsReplay(t *testing.T) {
	now := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	repository := &leaseRepositoryStub{workload: domain.Workload{ID: "workload-a", PublicKey: publicKey, Grant: testGrant()}}
	service, _ := newTestService(t, repository, now)
	message := []byte("signed request")
	request := domain.AuthenticateWorkloadRequest{
		WorkloadID: "workload-a", Timestamp: now, Nonce: "0123456789abcdef0123456789abcdef",
		Message: message, Signature: ed25519.Sign(privateKey, message),
	}
	authenticated, err := service.AuthenticateWorkload(context.Background(), request)
	if err != nil {
		t.Fatalf("AuthenticateWorkload() error = %v", err)
	}
	wantThumbprint, _ := authcrypto.JWKThumbprint(publicKey)
	if authenticated.AuthenticatedKeyThumbprint != wantThumbprint {
		t.Fatalf("authenticated key = %q, want %q", authenticated.AuthenticatedKeyThumbprint, wantThumbprint)
	}
	if _, err := service.AuthenticateWorkload(context.Background(), request); !errors.Is(err, domain.ErrReplayDetected) {
		t.Fatalf("AuthenticateWorkload() replay error = %v", err)
	}
}

func TestAuthenticateWorkloadHonorsPreviousKeyOverlap(t *testing.T) {
	now := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	currentPublic, _, _ := authcrypto.GenerateKeyPair()
	previousPublic, previousPrivate, _ := authcrypto.GenerateKeyPair()
	overlapEnds := now.Add(time.Minute)
	repository := &leaseRepositoryStub{workload: domain.Workload{
		ID: "workload-a", PublicKey: currentPublic, PreviousPublicKey: previousPublic,
		PreviousKeyExpiresAt: &overlapEnds, Grant: testGrant(),
	}}
	service, _ := newTestService(t, repository, now)
	message := []byte("signed with overlap key")
	request := domain.AuthenticateWorkloadRequest{
		WorkloadID: "workload-a", Timestamp: now, Nonce: "previous-key-overlap-nonce-000001",
		Message: message, Signature: ed25519.Sign(previousPrivate, message),
	}
	authenticated, err := service.AuthenticateWorkload(context.Background(), request)
	if err != nil {
		t.Fatalf("overlap key rejected: %v", err)
	}
	want, _ := authcrypto.JWKThumbprint(previousPublic)
	if authenticated.AuthenticatedKeyThumbprint != want {
		t.Fatalf("authenticated key = %q, want previous key %q", authenticated.AuthenticatedKeyThumbprint, want)
	}
	service.now = func() time.Time { return overlapEnds }
	request.Timestamp = overlapEnds
	request.Nonce = "expired-previous-key-nonce-000002"
	if _, err := service.AuthenticateWorkload(context.Background(), request); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("expired overlap key error = %v", err)
	}
}

func TestDelegateLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ancestorID := "1ff19763-bbda-4d40-ab4a-bb30552a4470"
	delegatedBy := "48ffd094-460a-4460-a76b-087660560390"
	repository := &leaseRepositoryStub{
		workload: domain.Workload{ID: "58ffd094-460a-4460-a76b-087660560390", Grant: testGrant()},
		// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
		// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
		parent: domain.Lease{
			ID: "3ff19763-bbda-4d40-ab4a-bb30552a4470", TokenID: "test-token-id",
			WorkloadID: "58ffd094-460a-4460-a76b-087660560390", RootWorkloadID: "58ffd094-460a-4460-a76b-087660560390",
			RootLeaseID: ancestorID, ParentLeaseID: &ancestorID, DelegatedByWorkloadID: &delegatedBy, GrantVersion: 1,
			Audience: "service:orders", Actions: []string{"read", "write"}, Resources: []string{"orders/*"},
			Expiration: now.Add(time.Hour), Depth: 1, MaxDepth: 3, IssuedAt: now.Add(-time.Minute),
		},
	}
	service, privateKey := newTestService(t, repository, now)
	parentToken := signParentToken(t, privateKey, repository.parent, "https://issuer.example")
	digest := sha256.Sum256([]byte(parentToken))
	repository.parent.TokenHash = digest[:]

	issued, err := service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID, ParentToken: parentToken, DelegatingWorkloadID: repository.parent.WorkloadID, DelegateToWorkloadID: repository.workload.ID,
		Actions:   []string{"read"},
		Resources: []string{"orders/123"}, TTL: 30 * time.Minute,
		AuthenticatedKeyThumbprint: testAuthenticatedKeyThumbprint,
	})
	if err != nil {
		t.Fatalf("DelegateLease() error = %v", err)
	}
	if issued.Token == "" || repository.created.ParentLeaseID == nil || repository.created.Depth != 2 || len(repository.created.TokenHash) != sha256.Size {
		t.Fatalf("unexpected issued lease: %+v", issued.Lease)
	}
}

func TestDelegateLeaseRejectsDifferentParentToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ancestorID := "1ff19763-bbda-4d40-ab4a-bb30552a4470"
	delegatedBy := "48ffd094-460a-4460-a76b-087660560390"
	repository := &leaseRepositoryStub{
		workload: domain.Workload{ID: "58ffd094-460a-4460-a76b-087660560390", Grant: testGrant()},
		// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
		parent: domain.Lease{
			ID: "3ff19763-bbda-4d40-ab4a-bb30552a4470", TokenID: "test-token-id",
			WorkloadID: "58ffd094-460a-4460-a76b-087660560390", RootWorkloadID: "58ffd094-460a-4460-a76b-087660560390",
			RootLeaseID: ancestorID, ParentLeaseID: &ancestorID, DelegatedByWorkloadID: &delegatedBy, GrantVersion: 1,
			Audience: "service:orders", Actions: []string{"read"}, Resources: []string{"orders"},
			Expiration: now.Add(time.Hour), MaxDepth: 2, IssuedAt: now,
		},
	}
	service, privateKey := newTestService(t, repository, now)
	token := signParentToken(t, privateKey, repository.parent, "https://issuer.example")
	repository.parent.TokenHash = make([]byte, sha256.Size)
	_, err := service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID, ParentToken: token, DelegatingWorkloadID: repository.parent.WorkloadID, DelegateToWorkloadID: repository.workload.ID,
		Actions: []string{"read"}, Resources: []string{"orders"}, TTL: time.Minute,
		AuthenticatedKeyThumbprint: testAuthenticatedKeyThumbprint,
	})
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("DelegateLease() error = %v", err)
	}
}

func TestDelegateLeaseRejectsWorkloadOtherThanParentSubject(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository := &leaseRepositoryStub{
		workload: domain.Workload{ID: "recipient-workload", Grant: testGrant()},
		// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
		parent: domain.Lease{
			ID: "3ff19763-bbda-4d40-ab4a-bb30552a4470", TokenID: "test-token-id",
			WorkloadID: "parent-workload", RootWorkloadID: "parent-workload", RootLeaseID: "3ff19763-bbda-4d40-ab4a-bb30552a4470",
			Audience: "service:orders", Actions: []string{"read"}, Resources: []string{"orders/*"},
			Expiration: now.Add(time.Hour), MaxDepth: 2, IssuedAt: now,
		},
	}
	service, privateKey := newTestService(t, repository, now)
	token := signParentToken(t, privateKey, repository.parent, "https://issuer.example")
	digest := sha256.Sum256([]byte(token))
	repository.parent.TokenHash = digest[:]
	_, err := service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID, ParentToken: token, DelegatingWorkloadID: "attacker-workload",
		DelegateToWorkloadID: repository.workload.ID, Actions: []string{"read"}, Resources: []string{"orders/1"}, TTL: time.Minute,
		AuthenticatedKeyThumbprint: testAuthenticatedKeyThumbprint,
	})
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("DelegateLease() error = %v, want unauthenticated", err)
	}
}

func TestDelegatePoPLeaseRequiresBoundAuthenticationKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository := &leaseRepositoryStub{
		workload: domain.Workload{ID: "recipient-workload", Grant: testGrant()},
		// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
		parent: domain.Lease{
			ID: "3ff19763-bbda-4d40-ab4a-bb30552a4470", TokenID: "test-token-id",
			WorkloadID: "parent-workload", RootWorkloadID: "parent-workload", RootLeaseID: "3ff19763-bbda-4d40-ab4a-bb30552a4470",
			Audience: "service:orders", Actions: []string{"read"}, Resources: []string{"orders/*"},
			Expiration: now.Add(time.Hour), MaxDepth: 2, IssuedAt: now, ConfirmationThumbprint: testAuthenticatedKeyThumbprint,
		},
	}
	service, privateKey := newTestService(t, repository, now)
	token := signParentToken(t, privateKey, repository.parent, "https://issuer.example")
	digest := sha256.Sum256([]byte(token))
	repository.parent.TokenHash = digest[:]
	_, err := service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID, ParentToken: token, DelegatingWorkloadID: repository.parent.WorkloadID,
		DelegateToWorkloadID: repository.workload.ID, Actions: []string{"read"}, Resources: []string{"orders/1"}, TTL: time.Minute,
		AuthenticatedKeyThumbprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	})
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("mismatched PoP key error = %v", err)
	}
}

func TestConsumeLeaseValidatesTokenAndIdempotencyKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// #nosec G101 -- TokenID values below are public UUID test fixtures, not credentials.
	repository := &leaseRepositoryStub{parent: domain.Lease{
		ID: "3ff19763-bbda-4d40-ab4a-bb30552a4470", TokenID: "test-token-id",
		WorkloadID: "workload-a", RootWorkloadID: "workload-a", RootLeaseID: "3ff19763-bbda-4d40-ab4a-bb30552a4470",
		Audience: "service:orders", Actions: []string{"read"}, Resources: []string{"orders/*"},
		Expiration: now.Add(time.Hour), MaxDepth: 0, MaxUses: 1, IssuedAt: now,
	}}
	service, privateKey := newTestService(t, repository, now)
	token := signParentToken(t, privateKey, repository.parent, "https://issuer.example")
	digest := sha256.Sum256([]byte(token))
	repository.parent.TokenHash = digest[:]
	consumption, err := service.ConsumeLease(context.Background(), domain.ConsumeLeaseRequest{
		LeaseID: repository.parent.ID, Token: token, IdempotencyKey: "request-00000000000000000001",
	})
	if err != nil || consumption.UseNumber != 1 {
		t.Fatalf("ConsumeLease() = %+v, %v", consumption, err)
	}
	if _, err := service.ConsumeLease(context.Background(), domain.ConsumeLeaseRequest{
		LeaseID: repository.parent.ID, Token: token, IdempotencyKey: "short",
	}); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatalf("short idempotency key error = %v", err)
	}
}

func TestMintRootLeaseNormalizesSubsecondTTL(t *testing.T) {
	now := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	repository := &leaseRepositoryStub{workload: domain.Workload{ID: "workload-a", Grant: testGrant()}}
	service, _ := newTestService(t, repository, now)
	authenticatedKey, err := authcrypto.JWKThumbprint(ed25519.PublicKey(repository.workload.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	issued, err := service.MintRootLease(context.Background(), domain.MintRootLeaseRequest{
		WorkloadID: "workload-a", Audience: "service:test", Actions: []string{"read"},
		Resources: []string{"item/1"}, TTL: 1500 * time.Millisecond, MaxDepth: 1,
		AuthenticatedKeyThumbprint: authenticatedKey,
	})
	if err != nil {
		t.Fatalf("MintRootLease() error = %v", err)
	}
	if want := now.Add(time.Second); !issued.Lease.Expiration.Equal(want) {
		t.Fatalf("expiration = %s, want %s", issued.Lease.Expiration, want)
	}
}

func TestMintRootLeaseRejectsAuthorityOutsideGrant(t *testing.T) {
	now := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	repository := &leaseRepositoryStub{workload: domain.Workload{ID: "workload-a", Grant: testGrant()}}
	service, _ := newTestService(t, repository, now)
	authenticatedKey, err := authcrypto.JWKThumbprint(ed25519.PublicKey(repository.workload.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	tests := []domain.MintRootLeaseRequest{
		{WorkloadID: "workload-a", Audience: "service:admin", Actions: []string{"read"}, Resources: []string{"item/1"}, TTL: time.Minute},
		{WorkloadID: "workload-a", Audience: "service:test", Actions: []string{"delete"}, Resources: []string{"item/1"}, TTL: time.Minute},
		{WorkloadID: "workload-a", Audience: "service:test", Actions: []string{"read"}, Resources: []string{"admin/1"}, TTL: time.Minute},
		{WorkloadID: "workload-a", Audience: "service:test", Actions: []string{"read"}, Resources: []string{"item/1"}, TTL: 31 * time.Minute},
		{WorkloadID: "workload-a", Audience: "service:test", Actions: []string{"read"}, Resources: []string{"item/1"}, TTL: time.Minute, MaxDepth: 3},
	}
	for _, request := range tests {
		request.AuthenticatedKeyThumbprint = authenticatedKey
		if _, err := service.MintRootLease(context.Background(), request); !errors.Is(err, domain.ErrAuthorityEscalation) {
			t.Errorf("MintRootLease(%+v) error = %v", request, err)
		}
	}
}

func newTestService(t *testing.T, repository *leaseRepositoryStub, now time.Time) (*LeaseUsecase, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if repository.workload.ID != "" && len(repository.workload.PublicKey) == 0 {
		workloadPublicKey, _, generateErr := authcrypto.GenerateKeyPair()
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		repository.workload.PublicKey = workloadPublicKey
	}
	service, err := NewLeaseUsecase(Config{
		Repository: repository, PrivateKey: privateKey,
		VerificationKeys: authcrypto.VerificationKeys([]ed25519.PublicKey{publicKey}),
		Issuer:           "https://issuer.example", MaxTTL: 2 * time.Hour, ClockSkew: 5 * time.Second, RequestWindow: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return service, privateKey
}

func signParentToken(t *testing.T, privateKey ed25519.PrivateKey, lease domain.Lease, issuer string) string {
	t.Helper()
	capability := map[string]any{
		"version": authcrypto.LeaseTokenVersion, "lease_id": lease.ID, "root_lease_id": lease.RootLeaseID,
		"root_workload_id": lease.RootWorkloadID, "workload_id": lease.WorkloadID,
		"actions": lease.Actions, "resources": lease.Resources, "depth": lease.Depth, "max_depth": lease.MaxDepth, "max_uses": lease.MaxUses,
		"constraints": copyConstraints(lease.Constraints),
	}
	if lease.ParentLeaseID != nil {
		capability["parent_lease_id"] = *lease.ParentLeaseID
		capability["delegated_by_workload_id"] = *lease.DelegatedByWorkloadID
	}
	claims := map[string]any{
		"aud": lease.Audience, "exp": lease.Expiration.Unix(), "iat": lease.IssuedAt.Unix(), "iss": issuer,
		"jti": lease.TokenID, "nbf": lease.IssuedAt.Unix(), "sub": lease.WorkloadID, "ups": capability,
	}
	if lease.ConfirmationThumbprint != "" {
		claims["cnf"] = map[string]string{"jkt": lease.ConfirmationThumbprint}
	}
	token, err := authcrypto.SignClaims(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testGrant() domain.AuthorityGrant {
	return domain.AuthorityGrant{
		Audiences: []string{"service:test", "service:orders"}, Actions: []string{"read", "write"},
		Resources: []string{"item/*", "orders/*", "orders"}, MaxTTL: 30 * time.Minute,
		MaxDelegationDepth: 2, CanDelegate: true, Version: 1,
	}
}
