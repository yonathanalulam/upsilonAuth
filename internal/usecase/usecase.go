package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yonathanalulam/upsilonAuth/internal/attenuation"
	constraintpkg "github.com/yonathanalulam/upsilonAuth/internal/constraints"
	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/domain"
	resourcepkg "github.com/yonathanalulam/upsilonAuth/internal/resource"
)

const maxCapabilityValues = 64
const maxCapabilityValueLength = 256
const maxDelegationDepth = 16

type Config struct {
	Repository       domain.LeaseRepository
	PrivateKey       ed25519.PrivateKey
	VerificationKeys map[string]ed25519.PublicKey
	Issuer           string
	MaxTTL           time.Duration
	ClockSkew        time.Duration
	RequestWindow    time.Duration
}

type LeaseUsecase struct {
	repository       domain.LeaseRepository
	privateKey       ed25519.PrivateKey
	verificationKeys map[string]ed25519.PublicKey
	issuer           string
	maxTTL           time.Duration
	clockSkew        time.Duration
	requestWindow    time.Duration
	now              func() time.Time
}

func NewLeaseUsecase(config Config) (*LeaseUsecase, error) {
	if config.Repository == nil || len(config.PrivateKey) != ed25519.PrivateKeySize || len(config.VerificationKeys) == 0 || strings.TrimSpace(config.Issuer) == "" {
		return nil, domain.ErrInvalidLease
	}
	if config.MaxTTL <= 0 || config.MaxTTL > 24*time.Hour || config.ClockSkew < 0 || config.ClockSkew > time.Minute || config.RequestWindow <= 0 || config.RequestWindow > 5*time.Minute {
		return nil, domain.ErrInvalidLease
	}
	keys := make(map[string]ed25519.PublicKey, len(config.VerificationKeys))
	for id, key := range config.VerificationKeys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, domain.ErrInvalidLease
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &LeaseUsecase{
		repository:       config.Repository,
		privateKey:       append(ed25519.PrivateKey(nil), config.PrivateKey...),
		verificationKeys: keys,
		issuer:           config.Issuer,
		maxTTL:           config.MaxTTL,
		clockSkew:        config.ClockSkew,
		requestWindow:    config.RequestWindow,
		now:              time.Now,
	}, nil
}

func (usecase *LeaseUsecase) RegisterWorkload(ctx context.Context, request domain.RegisterWorkloadRequest) (domain.Workload, error) {
	name := strings.TrimSpace(request.Name)
	if name != request.Name || len(name) < 3 || len(name) > 128 || len(request.PublicKey) != ed25519.PublicKeySize || strings.TrimSpace(request.Actor) == "" {
		return domain.Workload{}, domain.ErrInvalidWorkload
	}
	grant, err := usecase.validateGrant(request.Grant)
	if err != nil {
		return domain.Workload{}, err
	}
	id, err := newID()
	if err != nil {
		return domain.Workload{}, err
	}
	now := usecase.now().UTC().Truncate(time.Second)
	workload := domain.Workload{
		ID:        id,
		Name:      name,
		PublicKey: append([]byte(nil), request.PublicKey...),
		CreatedAt: now,
		UpdatedAt: now,
		Grant:     grant,
	}
	event := domain.AuditEvent{
		WorkloadID: &workload.ID,
		EventType:  "workload.registered",
		Actor:      request.Actor,
		Details: map[string]any{
			"name": workload.Name, "grant_version": grant.Version, "audiences": grant.Audiences,
			"actions": grant.Actions, "resources": grant.Resources, "max_ttl_seconds": int64(grant.MaxTTL / time.Second),
			"max_delegation_depth": grant.MaxDelegationDepth, "can_delegate": grant.CanDelegate,
			"require_proof_of_possession": grant.RequireProofOfPossession, "max_uses": grant.MaxUses, "constraints": grant.Constraints,
		},
		OccurredAt: now,
	}
	if err := usecase.repository.CreateWorkload(ctx, workload, event); err != nil {
		return domain.Workload{}, err
	}
	return workload, nil
}

func (usecase *LeaseUsecase) GetWorkload(ctx context.Context, workloadID string) (domain.Workload, error) {
	if workloadID == "" {
		return domain.Workload{}, domain.ErrInvalidWorkload
	}
	return usecase.repository.GetWorkloadByID(ctx, workloadID)
}

func (usecase *LeaseUsecase) AuthenticateWorkload(ctx context.Context, request domain.AuthenticateWorkloadRequest) (domain.Workload, error) {
	now := usecase.now().UTC().Truncate(time.Second)
	if request.WorkloadID == "" || request.Timestamp.IsZero() || !validNonce(request.Nonce) || len(request.Message) == 0 || len(request.Signature) != ed25519.SignatureSize {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	delta := now.Sub(request.Timestamp)
	if delta < -usecase.requestWindow || delta > usecase.requestWindow {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	workload, err := usecase.repository.GetWorkloadByID(ctx, request.WorkloadID)
	if err != nil {
		if errors.Is(err, domain.ErrWorkloadNotFound) {
			return domain.Workload{}, domain.ErrUnauthenticated
		}
		return domain.Workload{}, err
	}
	if workload.DisabledAt != nil {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	authenticatedKey, ok := authenticatedWorkloadKey(workload, request.Message, request.Signature, now)
	if !ok {
		return domain.Workload{}, domain.ErrUnauthenticated
	}
	nonceHash := sha256.Sum256([]byte(request.Nonce))
	nonceExpiresAt := request.Timestamp.UTC().Add(usecase.requestWindow)
	if err := usecase.repository.ConsumeWorkloadNonce(ctx, workload.ID, nonceHash[:], nonceExpiresAt); err != nil {
		if errors.Is(err, domain.ErrReplayDetected) {
			return domain.Workload{}, err
		}
		return domain.Workload{}, err
	}
	workload.AuthenticatedKeyThumbprint = authenticatedKey
	return workload, nil
}

func (usecase *LeaseUsecase) DisableWorkload(ctx context.Context, workloadID, actor string) (int64, error) {
	if workloadID == "" || strings.TrimSpace(actor) == "" {
		return 0, domain.ErrInvalidWorkload
	}
	return usecase.repository.DisableWorkload(ctx, workloadID, actor, usecase.now().UTC().Truncate(time.Second))
}

func (usecase *LeaseUsecase) RotateWorkloadKey(ctx context.Context, request domain.RotateWorkloadKeyRequest) (domain.Workload, int64, error) {
	if request.WorkloadID == "" || len(request.PublicKey) != ed25519.PublicKeySize || request.Overlap < 0 || request.Overlap > 24*time.Hour || strings.TrimSpace(request.Actor) == "" {
		return domain.Workload{}, 0, domain.ErrInvalidWorkload
	}
	now := usecase.now().UTC().Truncate(time.Second)
	return usecase.repository.RotateWorkloadKey(ctx, request, now)
}

func (usecase *LeaseUsecase) MintRootLease(ctx context.Context, request domain.MintRootLeaseRequest) (domain.IssuedLease, error) {
	now := usecase.now().UTC().Truncate(time.Second)
	if request.WorkloadID == "" || request.Audience == "" || strings.TrimSpace(request.Audience) != request.Audience || len(request.Audience) > 256 || request.MaxDepth < 0 || request.MaxDepth > maxDelegationDepth || request.MaxUses < 0 || request.MaxUses > 1_000_000 || len(request.AuthenticatedKeyThumbprint) != 43 {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}
	workload, err := usecase.repository.GetWorkloadByID(ctx, request.WorkloadID)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	if workload.DisabledAt != nil {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	if !workloadAcceptsThumbprint(workload, request.AuthenticatedKeyThumbprint, now) {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	expiration, err := usecase.expiration(now, request.Expiration, request.TTL)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	if err := validateValues(request.Actions, request.Resources); err != nil {
		return domain.IssuedLease{}, err
	}
	rootContext := attenuation.AuthorityContext{
		Actions: request.Actions, Resources: request.Resources, Expiration: expiration, Depth: 0, MaxDepth: request.MaxDepth, MaxUses: request.MaxUses,
		Constraints: request.Constraints,
	}
	if err := attenuation.ValidateRoot(attenuation.GrantContext{
		Audiences: workload.Grant.Audiences, Actions: workload.Grant.Actions, Resources: workload.Grant.Resources,
		MaxTTL: workload.Grant.MaxTTL, MaxDelegationDepth: workload.Grant.MaxDelegationDepth, CanDelegate: workload.Grant.CanDelegate,
		MaxUses:     workload.Grant.MaxUses,
		Constraints: workload.Grant.Constraints,
	}, request.Audience, rootContext, now); err != nil {
		return domain.IssuedLease{}, fmt.Errorf("%w: %w", domain.ErrAuthorityEscalation, err)
	}
	id, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	tokenID, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	confirmation := ""
	if request.ProofOfPossession || workload.Grant.RequireProofOfPossession {
		confirmation, err = authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PublicKey))
		if err != nil {
			return domain.IssuedLease{}, domain.ErrInvalidWorkload
		}
	}
	lease := domain.Lease{
		ID:                         id,
		TokenID:                    tokenID,
		WorkloadID:                 request.WorkloadID,
		RootWorkloadID:             request.WorkloadID,
		Audience:                   request.Audience,
		RootLeaseID:                id,
		Actions:                    append([]string(nil), request.Actions...),
		Resources:                  append([]string(nil), request.Resources...),
		Expiration:                 expiration,
		Depth:                      0,
		MaxDepth:                   request.MaxDepth,
		IssuedAt:                   now,
		GrantVersion:               workload.Grant.Version,
		ConfirmationThumbprint:     confirmation,
		MaxUses:                    request.MaxUses,
		Constraints:                copyConstraints(request.Constraints),
		AuthenticatedKeyThumbprint: request.AuthenticatedKeyThumbprint,
	}
	return usecase.issue(ctx, lease, "lease.root_minted", request.WorkloadID)
}

func (usecase *LeaseUsecase) DelegateLease(ctx context.Context, request domain.DelegateLeaseRequest) (domain.IssuedLease, error) {
	if request.ParentLeaseID == "" || request.ParentToken == "" || request.DelegatingWorkloadID == "" || request.DelegateToWorkloadID == "" || request.MaxUses < 0 || request.MaxUses > 1_000_000 || len(request.AuthenticatedKeyThumbprint) != 43 {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	parent, err := usecase.repository.GetLeaseByID(ctx, request.ParentLeaseID)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	now := usecase.now().UTC().Truncate(time.Second)
	if parent.RevokedAt != nil {
		return domain.IssuedLease{}, domain.ErrLeaseRevoked
	}
	if request.DelegatingWorkloadID != parent.WorkloadID {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	if !parent.Expiration.After(now) {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}
	claims, err := authcrypto.VerifyLeaseToken(request.ParentToken, usecase.verificationKeys, usecase.issuer, parent.Audience, usecase.clockSkew)
	if err != nil || !usecase.parentTokenMatches(parent, request.ParentToken, claims) {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	if parent.ConfirmationThumbprint != "" && subtle.ConstantTimeCompare([]byte(parent.ConfirmationThumbprint), []byte(request.AuthenticatedKeyThumbprint)) != 1 {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	recipient, err := usecase.repository.GetWorkloadByID(ctx, request.DelegateToWorkloadID)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	if recipient.DisabledAt != nil {
		return domain.IssuedLease{}, domain.ErrUnauthenticated
	}
	expiration, err := usecase.expiration(now, request.Expiration, request.TTL)
	if err != nil {
		return domain.IssuedLease{}, err
	}
	parentContext := attenuation.AuthorityContext{
		Actions: parent.Actions, Resources: parent.Resources, Expiration: parent.Expiration, Depth: parent.Depth, MaxDepth: parent.MaxDepth,
		MaxUses: parent.MaxUses, Constraints: parent.Constraints,
	}
	childMaxDepth := parent.MaxDepth
	if request.MaxUses > 0 {
		childMaxDepth = parent.Depth + 1
	}
	childContext := attenuation.AuthorityContext{
		Actions: request.Actions, Resources: request.Resources, Expiration: expiration, Depth: parent.Depth + 1, MaxDepth: childMaxDepth, MaxUses: request.MaxUses,
		Constraints: request.Constraints,
	}
	if err := attenuation.Validate(parentContext, childContext); err != nil {
		return domain.IssuedLease{}, fmt.Errorf("%w: %w", domain.ErrInvalidAttenuation, err)
	}
	id, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	tokenID, err := newID()
	if err != nil {
		return domain.IssuedLease{}, err
	}
	confirmation := ""
	if request.ProofOfPossession || parent.ConfirmationThumbprint != "" {
		confirmation, err = authcrypto.JWKThumbprint(ed25519.PublicKey(recipient.PublicKey))
		if err != nil {
			return domain.IssuedLease{}, domain.ErrInvalidWorkload
		}
	}
	parentID := parent.ID
	delegatedBy := parent.WorkloadID
	lease := domain.Lease{
		ID: id, TokenID: tokenID, WorkloadID: recipient.ID, RootWorkloadID: parent.RootWorkloadID,
		Audience: parent.Audience, ParentLeaseID: &parentID, RootLeaseID: parent.RootLeaseID,
		DelegatedByWorkloadID: &delegatedBy,
		Actions:               append([]string(nil), request.Actions...), Resources: append([]string(nil), request.Resources...),
		Expiration: expiration, Depth: parent.Depth + 1, MaxDepth: childMaxDepth, IssuedAt: now,
		GrantVersion:               parent.GrantVersion,
		ConfirmationThumbprint:     confirmation,
		MaxUses:                    request.MaxUses,
		Constraints:                copyConstraints(request.Constraints),
		AuthenticatedKeyThumbprint: request.AuthenticatedKeyThumbprint,
	}
	return usecase.issue(ctx, lease, "lease.delegated", parent.WorkloadID)
}

func (usecase *LeaseUsecase) RevokeLease(ctx context.Context, request domain.RevokeLeaseRequest) (int64, error) {
	if request.LeaseID == "" || strings.TrimSpace(request.Actor) == "" {
		return 0, domain.ErrInvalidLease
	}
	return usecase.repository.RevokeLeaseLineage(ctx, request.LeaseID, request.Actor, usecase.now().UTC().Truncate(time.Second))
}

func (usecase *LeaseUsecase) GetLease(ctx context.Context, leaseID string) (domain.Lease, error) {
	if leaseID == "" {
		return domain.Lease{}, domain.ErrInvalidLease
	}
	return usecase.repository.GetLeaseByID(ctx, leaseID)
}

func (usecase *LeaseUsecase) TraceLease(ctx context.Context, leaseID string) ([]domain.Lease, error) {
	if leaseID == "" {
		return nil, domain.ErrInvalidLease
	}
	return usecase.repository.TraceLease(ctx, leaseID)
}

func (usecase *LeaseUsecase) ListAuditEvents(ctx context.Context, workloadID, leaseID string, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		return nil, domain.ErrInvalidLease
	}
	return usecase.repository.ListAuditEvents(ctx, workloadID, leaseID, limit)
}

func (usecase *LeaseUsecase) ConsumeLease(ctx context.Context, request domain.ConsumeLeaseRequest) (domain.LeaseConsumption, error) {
	if request.LeaseID == "" || request.Token == "" || !validIdempotencyKey(request.IdempotencyKey) {
		return domain.LeaseConsumption{}, domain.ErrInvalidLease
	}
	lease, err := usecase.repository.GetLeaseByID(ctx, request.LeaseID)
	if err != nil {
		return domain.LeaseConsumption{}, err
	}
	claims, err := authcrypto.VerifyLeaseToken(request.Token, usecase.verificationKeys, usecase.issuer, lease.Audience, usecase.clockSkew)
	if err != nil || !usecase.parentTokenMatches(lease, request.Token, claims) {
		return domain.LeaseConsumption{}, domain.ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(request.Token))
	return usecase.repository.ConsumeLeaseUse(ctx, lease.ID, digest[:], request.IdempotencyKey, usecase.now().UTC().Truncate(time.Second))
}

func (usecase *LeaseUsecase) ListActiveRevocations(ctx context.Context) ([]string, error) {
	return usecase.repository.ListActiveRevocations(ctx, usecase.now().UTC().Truncate(time.Second))
}

func (usecase *LeaseUsecase) expiration(now, explicit time.Time, ttl time.Duration) (time.Time, error) {
	if !explicit.IsZero() && ttl != 0 {
		return time.Time{}, domain.ErrInvalidLease
	}
	expiration := explicit.UTC().Truncate(time.Second)
	if explicit.IsZero() {
		if ttl <= 0 {
			return time.Time{}, domain.ErrInvalidLease
		}
		expiration = now.Add(ttl)
	}
	// JWT NumericDate values have one-second precision. Keep the persisted
	// lease and its signed representation identical, including for TTLs such
	// as 1500ms.
	expiration = expiration.UTC().Truncate(time.Second)
	if !expiration.After(now) || expiration.After(now.Add(usecase.maxTTL)) {
		return time.Time{}, domain.ErrInvalidLease
	}
	return expiration, nil
}

func (usecase *LeaseUsecase) parentTokenMatches(parent domain.Lease, raw string, claims *authcrypto.LeaseClaims) bool {
	if claims == nil || claims.ID != parent.TokenID || claims.Subject != parent.WorkloadID || claims.UPS.LeaseID != parent.ID || claims.UPS.RootLeaseID != parent.RootLeaseID || claims.UPS.RootWorkloadID != parent.RootWorkloadID || claims.UPS.WorkloadID != parent.WorkloadID || claims.UPS.DelegatedByWorkloadID != delegatedByID(parent) || claims.UPS.Depth != parent.Depth || claims.UPS.MaxDepth != parent.MaxDepth || claims.UPS.MaxUses != parent.MaxUses || claimConfirmation(claims) != parent.ConfirmationThumbprint || !claims.ExpiresAt.Equal(parent.Expiration) {
		return false
	}
	if !sameStrings(claims.UPS.Actions, parent.Actions) || !sameStrings(claims.UPS.Resources, parent.Resources) || !constraintpkg.Equal(claims.UPS.Constraints, parent.Constraints) || claims.UPS.ParentLeaseID != parentID(parent) {
		return false
	}
	digest := sha256.Sum256([]byte(raw))
	return len(parent.TokenHash) == sha256.Size && subtle.ConstantTimeCompare(digest[:], parent.TokenHash) == 1
}

func (usecase *LeaseUsecase) issue(ctx context.Context, lease domain.Lease, eventType, actor string) (domain.IssuedLease, error) {
	if lease.TokenID == "" || lease.RootLeaseID == "" || lease.RootWorkloadID == "" {
		return domain.IssuedLease{}, domain.ErrInvalidLease
	}
	capability := authcrypto.CapabilityClaims{
		Version: authcrypto.LeaseTokenVersion, LeaseID: lease.ID, RootLeaseID: lease.RootLeaseID,
		RootWorkloadID: lease.RootWorkloadID, WorkloadID: lease.WorkloadID,
		DelegatedByWorkloadID: delegatedByID(lease), Actions: lease.Actions, Resources: lease.Resources,
		Depth: lease.Depth, MaxDepth: lease.MaxDepth, ParentLeaseID: parentID(lease), MaxUses: lease.MaxUses,
		Constraints: copyConstraints(lease.Constraints),
	}
	claims := authcrypto.LeaseClaims{
		UPS: capability,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: usecase.issuer, Subject: lease.WorkloadID, Audience: jwt.ClaimStrings{lease.Audience},
			ExpiresAt: jwt.NewNumericDate(lease.Expiration), IssuedAt: jwt.NewNumericDate(lease.IssuedAt),
			NotBefore: jwt.NewNumericDate(lease.IssuedAt), ID: lease.TokenID,
		},
	}
	if lease.ConfirmationThumbprint != "" {
		claims.Confirmation = &authcrypto.ConfirmationClaim{JWKThumbprint: lease.ConfirmationThumbprint}
	}
	token, err := authcrypto.SignLeaseClaims(claims, usecase.privateKey)
	if err != nil {
		return domain.IssuedLease{}, fmt.Errorf("sign lease: %w", err)
	}
	digest := sha256.Sum256([]byte(token))
	lease.TokenHash = digest[:]
	event := domain.AuditEvent{
		WorkloadID: &lease.WorkloadID, LeaseID: &lease.ID, EventType: eventType, Actor: actor,
		Details: map[string]any{
			"audience": lease.Audience, "depth": lease.Depth, "expires_at": lease.Expiration,
			"parent_lease_id": parentID(lease), "root_lease_id": lease.RootLeaseID,
			"root_workload_id": lease.RootWorkloadID, "subject_workload_id": lease.WorkloadID,
			"delegated_by_workload_id": delegatedByID(lease), "actions": lease.Actions, "resources": lease.Resources,
			"max_uses": lease.MaxUses, "constraints": lease.Constraints,
		}, OccurredAt: lease.IssuedAt,
	}
	if err := usecase.repository.CreateLease(ctx, lease, event); err != nil {
		return domain.IssuedLease{}, err
	}
	return domain.IssuedLease{Lease: lease, Token: token}, nil
}

func validateValues(actions, resources []string) error {
	if len(actions) == 0 || len(resources) == 0 || len(actions) > maxCapabilityValues || len(resources) > maxCapabilityValues {
		return domain.ErrInvalidLease
	}
	for _, values := range [][]string{actions, resources} {
		for _, value := range values {
			if len(value) > maxCapabilityValueLength {
				return domain.ErrInvalidLease
			}
		}
	}
	if _, err := resourcepkg.CanonicalizePatterns(resources); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidLease, err)
	}
	context := attenuation.AuthorityContext{Actions: actions, Resources: resources, Expiration: time.Unix(1, 0), Depth: 0, MaxDepth: 1}
	child := context
	child.Depth = 1
	child.Expiration = time.Unix(0, 0)
	if err := attenuation.Validate(context, child); err != nil && !errors.Is(err, attenuation.ErrNotStrict) {
		return fmt.Errorf("%w: %w", domain.ErrInvalidLease, err)
	}
	return nil
}

func (usecase *LeaseUsecase) validateGrant(grant domain.AuthorityGrant) (domain.AuthorityGrant, error) {
	if len(grant.Audiences) == 0 || len(grant.Audiences) > 16 || grant.MaxTTL <= 0 || grant.MaxTTL > usecase.maxTTL || grant.MaxDelegationDepth < 0 || grant.MaxDelegationDepth > maxDelegationDepth || grant.MaxUses < 0 || grant.MaxUses > 1_000_000 {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	if !grant.CanDelegate && grant.MaxDelegationDepth != 0 {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	if grant.MaxUses > 0 && (grant.CanDelegate || grant.MaxDelegationDepth != 0) {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	if err := validateUniqueValues(grant.Audiences, 16); err != nil {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	if err := validateValues(grant.Actions, grant.Resources); err != nil {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	canonicalResources, err := resourcepkg.CanonicalizePatterns(grant.Resources)
	if err != nil {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	validationTime := time.Unix(1, 0).UTC()
	if err := attenuation.ValidateRoot(attenuation.GrantContext{
		Audiences: grant.Audiences, Actions: grant.Actions, Resources: canonicalResources, MaxTTL: grant.MaxTTL,
		MaxDelegationDepth: grant.MaxDelegationDepth, CanDelegate: grant.CanDelegate, MaxUses: grant.MaxUses,
		Constraints: grant.Constraints,
	}, grant.Audiences[0], attenuation.AuthorityContext{
		Actions: grant.Actions, Resources: canonicalResources, Expiration: validationTime.Add(grant.MaxTTL),
		MaxDepth: grant.MaxDelegationDepth, MaxUses: grant.MaxUses, Constraints: grant.Constraints,
	}, validationTime); err != nil {
		return domain.AuthorityGrant{}, domain.ErrInvalidWorkload
	}
	grant.Audiences = append([]string(nil), grant.Audiences...)
	grant.Actions = append([]string(nil), grant.Actions...)
	grant.Resources = canonicalResources
	grant.Constraints = copyConstraints(grant.Constraints)
	grant.Version = 1
	return grant, nil
}

func validateUniqueValues(values []string, maximum int) error {
	if len(values) == 0 || len(values) > maximum {
		return domain.ErrInvalidWorkload
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maxCapabilityValueLength || strings.TrimSpace(value) != value {
			return domain.ErrInvalidWorkload
		}
		if _, exists := seen[value]; exists {
			return domain.ErrInvalidWorkload
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validNonce(value string) bool {
	if len(value) < 32 || len(value) > 128 {
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

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func authenticatedWorkloadKey(workload domain.Workload, message, signature []byte, now time.Time) (string, bool) {
	if len(workload.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(workload.PublicKey), message, signature) {
		thumbprint, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PublicKey))
		return thumbprint, err == nil
	}
	if workload.PreviousKeyExpiresAt != nil && now.Before(*workload.PreviousKeyExpiresAt) && len(workload.PreviousPublicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(workload.PreviousPublicKey), message, signature) {
		thumbprint, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PreviousPublicKey))
		return thumbprint, err == nil
	}
	return "", false
}

func workloadAcceptsThumbprint(workload domain.Workload, thumbprint string, now time.Time) bool {
	current, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PublicKey))
	if err == nil && subtle.ConstantTimeCompare([]byte(current), []byte(thumbprint)) == 1 {
		return true
	}
	if workload.PreviousKeyExpiresAt == nil || !now.Before(*workload.PreviousKeyExpiresAt) {
		return false
	}
	previous, err := authcrypto.JWKThumbprint(ed25519.PublicKey(workload.PreviousPublicKey))
	return err == nil && subtle.ConstantTimeCompare([]byte(previous), []byte(thumbprint)) == 1
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[value]; !exists {
			return false
		}
	}
	return true
}

func copyConstraints(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func parentID(lease domain.Lease) string {
	if lease.ParentLeaseID == nil {
		return ""
	}
	return *lease.ParentLeaseID
}

func delegatedByID(lease domain.Lease) string {
	if lease.DelegatedByWorkloadID == nil {
		return ""
	}
	return *lease.DelegatedByWorkloadID
}

func claimConfirmation(claims *authcrypto.LeaseClaims) string {
	if claims == nil || claims.Confirmation == nil {
		return ""
	}
	return claims.Confirmation.JWKThumbprint
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
