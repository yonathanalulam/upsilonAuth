package attenuation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	constraintpkg "github.com/yonathanalulam/upsilonAuth/internal/constraints"
	resourcepkg "github.com/yonathanalulam/upsilonAuth/internal/resource"
)

var (
	ErrInvalidDepth        = errors.New("child depth must be exactly one greater than parent depth")
	ErrMaxDepthExceeded    = errors.New("child depth exceeds parent maximum depth")
	ErrMaxDepthExpanded    = errors.New("child maximum depth exceeds parent maximum depth")
	ErrExpirationExtended  = errors.New("child expiration exceeds parent expiration")
	ErrActionsExpanded     = errors.New("child actions are not a subset of parent actions")
	ErrResourcesExpanded   = errors.New("child resources are not a subset of parent resources")
	ErrNotStrict           = errors.New("child authority does not strictly attenuate parent authority")
	ErrInvalidContext      = errors.New("authority context is invalid")
	ErrAudienceExpanded    = errors.New("audience is outside the workload grant")
	ErrTTLExpanded         = errors.New("lease lifetime exceeds the workload grant")
	ErrDelegationForbidden = errors.New("workload grant forbids delegation")
	ErrUsesExpanded        = errors.New("maximum uses exceeds the authority ceiling")
	ErrStatefulDelegation  = errors.New("limited-use capabilities cannot be delegated")
	ErrConstraintsWeakened = errors.New("child constraints weaken parent constraints")
)

type GrantContext struct {
	Audiences          []string
	Actions            []string
	Resources          []string
	MaxTTL             time.Duration
	MaxDelegationDepth int
	CanDelegate        bool
	MaxUses            int
	Constraints        map[string]string
}

type AuthorityContext struct {
	Actions     []string
	Resources   []string
	Expiration  time.Time
	Depth       int
	MaxDepth    int
	MaxUses     int
	Constraints map[string]string
}

func ValidateRoot(grant GrantContext, audience string, requested AuthorityContext, issuedAt time.Time) error {
	if grant.MaxTTL <= 0 || grant.MaxDelegationDepth < 0 || grant.MaxDelegationDepth > 16 || grant.MaxUses < 0 || issuedAt.IsZero() {
		return ErrInvalidContext
	}
	if hasEmptyOrDuplicate(grant.Audiences) || hasEmptyOrDuplicate(grant.Actions) || hasEmptyOrDuplicate(grant.Resources) {
		return ErrInvalidContext
	}
	if !constraintpkg.Valid(grant.Constraints) || !constraintpkg.AtLeastAsStrong(grant.Constraints, requested.Constraints) {
		return ErrConstraintsWeakened
	}
	for _, value := range grant.Resources {
		if _, err := resourcepkg.CanonicalizePattern(value); err != nil {
			return ErrInvalidContext
		}
	}
	if !contains(grant.Audiences, audience) {
		return ErrAudienceExpanded
	}
	if requested.Depth != 0 || requested.MaxDepth > grant.MaxDelegationDepth {
		return ErrMaxDepthExpanded
	}
	if requested.MaxDepth > 0 && !grant.CanDelegate {
		return ErrDelegationForbidden
	}
	if requested.MaxUses > 0 && requested.MaxDepth > 0 {
		return ErrStatefulDelegation
	}
	if grant.MaxUses > 0 && (requested.MaxUses == 0 || requested.MaxUses > grant.MaxUses) {
		return ErrUsesExpanded
	}
	if requested.Expiration.After(issuedAt.Add(grant.MaxTTL)) {
		return ErrTTLExpanded
	}
	if err := validateContext(requested); err != nil {
		return err
	}
	if !isSubset(toSet(requested.Actions), toSet(grant.Actions)) {
		return ErrActionsExpanded
	}
	if !resourcepkg.Subset(requested.Resources, grant.Resources) {
		return ErrResourcesExpanded
	}
	return nil
}

func Validate(parent, child AuthorityContext) error {
	if err := validateContext(parent); err != nil {
		return fmt.Errorf("parent: %w", err)
	}
	if err := validateContext(child); err != nil {
		return fmt.Errorf("child: %w", err)
	}
	if parent.MaxUses > 0 {
		return ErrStatefulDelegation
	}
	if parent.Depth == int(^uint(0)>>1) || child.Depth != parent.Depth+1 {
		return ErrInvalidDepth
	}
	if child.Depth > parent.MaxDepth {
		return ErrMaxDepthExceeded
	}
	if child.MaxDepth > parent.MaxDepth {
		return ErrMaxDepthExpanded
	}
	if child.MaxDepth < child.Depth {
		return ErrInvalidContext
	}
	if child.Expiration.After(parent.Expiration) {
		return ErrExpirationExtended
	}
	if child.MaxUses > 0 && child.MaxDepth != child.Depth {
		return ErrStatefulDelegation
	}
	if !constraintpkg.AtLeastAsStrong(parent.Constraints, child.Constraints) {
		return ErrConstraintsWeakened
	}

	parentActions := toSet(parent.Actions)
	childActions := toSet(child.Actions)
	if !isSubset(childActions, parentActions) {
		return ErrActionsExpanded
	}

	if !resourcesSubset(child.Resources, parent.Resources) {
		return ErrResourcesExpanded
	}

	if setsEqual(childActions, parentActions) && setsEqual(toSet(child.Resources), toSet(parent.Resources)) && child.Expiration.Equal(parent.Expiration) && child.MaxDepth == parent.MaxDepth && child.MaxUses == parent.MaxUses && constraintpkg.Equal(parent.Constraints, child.Constraints) {
		return ErrNotStrict
	}

	return nil
}

func validateContext(context AuthorityContext) error {
	if context.Depth < 0 || context.MaxDepth < context.Depth || context.MaxUses < 0 || context.Expiration.IsZero() || !constraintpkg.Valid(context.Constraints) {
		return ErrInvalidContext
	}
	if hasEmptyOrDuplicate(context.Actions) || hasEmptyOrDuplicate(context.Resources) {
		return ErrInvalidContext
	}
	for _, resource := range context.Resources {
		if _, err := resourcepkg.CanonicalizePattern(resource); err != nil {
			return ErrInvalidContext
		}
	}
	return nil
}

func hasEmptyOrDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func resourcesSubset(candidate, parent []string) bool {
	return resourcepkg.Subset(candidate, parent)
}

func contains(values []string, required string) bool {
	for _, value := range values {
		if value == required {
			return true
		}
	}
	return false
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func isSubset(candidate, parent map[string]struct{}) bool {
	for value := range candidate {
		if _, exists := parent[value]; !exists {
			return false
		}
	}
	return true
}

func setsEqual(left, right map[string]struct{}) bool {
	return len(left) == len(right) && isSubset(left, right)
}
