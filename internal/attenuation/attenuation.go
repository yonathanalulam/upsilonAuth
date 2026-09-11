package attenuation

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidDepth       = errors.New("child depth must be exactly one greater than parent depth")
	ErrMaxDepthExceeded   = errors.New("child depth exceeds parent maximum depth")
	ErrMaxDepthExpanded   = errors.New("child maximum depth exceeds parent maximum depth")
	ErrExpirationExtended = errors.New("child expiration exceeds parent expiration")
	ErrActionsExpanded    = errors.New("child actions are not a subset of parent actions")
	ErrResourcesExpanded  = errors.New("child resources are not a subset of parent resources")
	ErrNotStrict          = errors.New("child authority does not strictly attenuate parent authority")
	ErrInvalidContext     = errors.New("authority context is invalid")
)

type AuthorityContext struct {
	Actions    []string
	Resources  []string
	Expiration time.Time
	Depth      int
	MaxDepth   int
}

func Validate(parent, child AuthorityContext) error {
	if err := validateContext(parent); err != nil {
		return fmt.Errorf("parent: %w", err)
	}
	if err := validateContext(child); err != nil {
		return fmt.Errorf("child: %w", err)
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

	parentActions := toSet(parent.Actions)
	childActions := toSet(child.Actions)
	if !isSubset(childActions, parentActions) {
		return ErrActionsExpanded
	}

	parentResources := toSet(parent.Resources)
	childResources := toSet(child.Resources)
	if !isSubset(childResources, parentResources) {
		return ErrResourcesExpanded
	}

	if len(childActions) == len(parentActions) && len(childResources) == len(parentResources) && child.Expiration.Equal(parent.Expiration) && child.MaxDepth == parent.MaxDepth {
		return ErrNotStrict
	}

	return nil
}

func validateContext(context AuthorityContext) error {
	if context.Depth < 0 || context.MaxDepth < context.Depth || context.Expiration.IsZero() {
		return ErrInvalidContext
	}
	if hasEmptyOrDuplicate(context.Actions) || hasEmptyOrDuplicate(context.Resources) {
		return ErrInvalidContext
	}
	return nil
}

func hasEmptyOrDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
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
