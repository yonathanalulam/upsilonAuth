package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"upsilonAuth/internal/attenuation"
	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/domain"
)

type LeaseUsecase struct {
	repository domain.LeaseRepository
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

func NewLeaseUsecase(repository domain.LeaseRepository, privateKey ed25519.PrivateKey) (*LeaseUsecase, error) {
	if repository == nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, domain.ErrInvalidLease
	}
	return &LeaseUsecase{
		repository: repository,
		privateKey: privateKey,
		now:        time.Now,
	}, nil
}

func (usecase *LeaseUsecase) MintRootLease(ctx context.Context, request domain.MintRootLeaseRequest) (domain.IssuedLease, error) {
	now := usecase.now().UTC()
	audience := request.Audience
	if audience == "" {
		audience = request.WorkloadID
	}
	expiration := request.Expiration
	if expiration.IsZero() && request.TTL > 0 {
		expiration = now.Add(request.TTL)
	}
	if audience == "" || expiration.IsZero() || !expiration.After(now) || request.MaxDepth < 0 {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}
	if err := validateValues(request.Actions, request.Resources); err != nil {
		return domain.IssuedLease{}, err
	}

	id, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	lease := domain.Lease{
		ID:         id,
		WorkloadID: request.WorkloadID,
		Audience:   audience,
		Actions:    append([]string(nil), request.Actions...),
		Resources:  append([]string(nil), request.Resources...),
		Expiration: expiration.UTC(),
		Depth:      0,
		MaxDepth:   request.MaxDepth,
		IssuedAt:   now,
	}
	return usecase.issue(ctx, lease)
}

func (usecase *LeaseUsecase) DelegateLease(ctx context.Context, request domain.DelegateLeaseRequest) (domain.IssuedLease, error) {
	if request.ParentLeaseID == "" {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}

	parent, err := usecase.repository.GetLeaseByID(ctx, request.ParentLeaseID)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	now := usecase.now().UTC()
	expiration := request.Expiration
	if expiration.IsZero() && request.TTL > 0 {
		expiration = now.Add(request.TTL)
	}
	if parent.RevokedAt != nil || !parent.Expiration.After(now) || expiration.IsZero() || !expiration.After(now) {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}
	if parent.Depth >= parent.MaxDepth {
		return domain.IssuedLease{}, domain.ErrInvalidAttenuation
	}

	parentContext := attenuation.AuthorityContext{
		Actions:    parent.Actions,
		Resources:  parent.Resources,
		Expiration: parent.Expiration,
		Depth:      parent.Depth,
	}
	childContext := attenuation.AuthorityContext{
		Actions:    request.Actions,
		Resources:  request.Resources,
		Expiration: expiration,
		Depth:      parent.Depth + 1,
	}
	if err := attenuation.Validate(parentContext, childContext); err != nil {
		return domain.IssuedLease{}, fmt.Errorf("%w: %v", domain.ErrInvalidAttenuation, err)
	}

	id, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	parentID := parent.ID
	lease := domain.Lease{
		ID:            id,
		WorkloadID:    parent.WorkloadID,
		Audience:      parent.Audience,
		ParentLeaseID: &parentID,
		Actions:       append([]string(nil), request.Actions...),
		Resources:     append([]string(nil), request.Resources...),
		Expiration:    expiration.UTC(),
		Depth:         parent.Depth + 1,
		MaxDepth:      parent.MaxDepth,
		IssuedAt:      now,
	}
	return usecase.issue(ctx, lease)
}

func (usecase *LeaseUsecase) issue(ctx context.Context, lease domain.Lease) (domain.IssuedLease, error) {
	capability := map[string]any{
		"actions":   lease.Actions,
		"depth":     lease.Depth,
		"max_depth": lease.MaxDepth,
		"resources": lease.Resources,
	}
	if lease.ParentLeaseID != nil {
		capability["parent"] = *lease.ParentLeaseID
	}
	claims := map[string]any{
		"aud": lease.Audience,
		"exp": lease.Expiration.Unix(),
		"iat": lease.IssuedAt.Unix(),
		"jti": lease.ID,
		"ups": capability,
	}
	if lease.WorkloadID != "" {
		claims["sub"] = lease.WorkloadID
	}

	token, err := authcrypto.SignClaims(claims, usecase.privateKey)
	if err != nil {
		return domain.IssuedLease{}, fmt.Errorf("sign lease: %w", err)
	}
	digest := sha256.Sum256([]byte(token))
	lease.TokenHash = digest[:]

	if err := usecase.repository.CreateLease(ctx, lease); err != nil {
		return domain.IssuedLease{}, err
	}
	return domain.IssuedLease{Lease: lease, Token: token}, nil
}

func validateValues(actions, resources []string) error {
	context := attenuation.AuthorityContext{
		Actions:    actions,
		Resources:  resources,
		Expiration: time.Unix(1, 0),
		Depth:      0,
	}
	child := context
	child.Depth = 1
	child.Expiration = time.Unix(0, 0)
	if err := attenuation.Validate(context, child); err != nil && !errors.Is(err, attenuation.ErrNotStrict) {
		return fmt.Errorf("%w: %v", domain.ErrInvalidLease, err)
	}
	return nil
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate lease id: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
