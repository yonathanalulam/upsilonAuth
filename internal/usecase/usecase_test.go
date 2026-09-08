package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/domain"
)

type leaseRepositoryStub struct {
	parent  domain.Lease
	created domain.Lease
}

func (repository *leaseRepositoryStub) CreateLease(_ context.Context, lease domain.Lease) error {
	repository.created = lease
	return nil
}

func (repository *leaseRepositoryStub) GetLeaseByID(_ context.Context, id string) (domain.Lease, error) {
	if id != repository.parent.ID {
		return domain.Lease{}, domain.ErrLeaseNotFound
	}
	return repository.parent, nil
}

func TestDelegateLease(t *testing.T) {
	now := time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC)
	repository := &leaseRepositoryStub{
		parent: domain.Lease{
			ID:         "3ff19763-bbda-4d40-ab4a-bb30552a4470",
			WorkloadID: "58ffd094-460a-4460-a76b-087660560390",
			Actions:    []string{"read", "write"},
			Resources:  []string{"orders", "invoices"},
			Expiration: now.Add(time.Hour),
			Depth:      1,
			MaxDepth:   3,
		},
	}
	_, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	service, err := NewLeaseUsecase(repository, privateKey)
	if err != nil {
		t.Fatalf("NewLeaseUsecase() error = %v", err)
	}
	service.now = func() time.Time { return now }

	issued, err := service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID,
		Actions:       []string{"read"},
		Resources:     []string{"orders"},
		Expiration:    now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("DelegateLease() error = %v", err)
	}
	if issued.Token == "" || len(strings.Split(issued.Token, ".")) != 3 {
		t.Fatalf("DelegateLease() token = %q", issued.Token)
	}
	if repository.created.ParentLeaseID == nil || *repository.created.ParentLeaseID != repository.parent.ID {
		t.Fatalf("created parent = %v", repository.created.ParentLeaseID)
	}
	if repository.created.Depth != repository.parent.Depth+1 {
		t.Fatalf("created depth = %d", repository.created.Depth)
	}
	if len(repository.created.TokenHash) != 32 {
		t.Fatalf("created token hash length = %d", len(repository.created.TokenHash))
	}
}

func TestDelegateLeaseRejectsExpansion(t *testing.T) {
	now := time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC)
	repository := &leaseRepositoryStub{
		parent: domain.Lease{
			ID:         "3ff19763-bbda-4d40-ab4a-bb30552a4470",
			WorkloadID: "58ffd094-460a-4460-a76b-087660560390",
			Actions:    []string{"read"},
			Resources:  []string{"orders"},
			Expiration: now.Add(time.Hour),
			MaxDepth:   3,
		},
	}
	_, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	service, err := NewLeaseUsecase(repository, privateKey)
	if err != nil {
		t.Fatalf("NewLeaseUsecase() error = %v", err)
	}
	service.now = func() time.Time { return now }

	_, err = service.DelegateLease(context.Background(), domain.DelegateLeaseRequest{
		ParentLeaseID: repository.parent.ID,
		Actions:       []string{"read", "write"},
		Resources:     []string{"orders"},
		Expiration:    now.Add(30 * time.Minute),
	})
	if !errors.Is(err, domain.ErrInvalidAttenuation) {
		t.Fatalf("DelegateLease() error = %v, want %v", err, domain.ErrInvalidAttenuation)
	}
	if repository.created.ID != "" {
		t.Fatal("expanded lease was persisted")
	}
}
