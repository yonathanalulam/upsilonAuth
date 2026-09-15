package attenuation

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	constraintpkg "github.com/yonathanalulam/upsilonAuth/internal/constraints"
)

func TestValidateMonotonicAttenuation(t *testing.T) {
	expiration := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	parent := AuthorityContext{
		Actions:    []string{"payments:refund", "payments:read"},
		Resources:  []string{"customer/123", "invoice/456"},
		Expiration: expiration,
		Depth:      1,
		MaxDepth:   3,
	}

	tests := []struct {
		name  string
		child AuthorityContext
		want  error
	}{
		{
			name: "strict action reduction",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/123", "invoice/456"},
				Expiration: expiration,
				Depth:      2,
				MaxDepth:   3,
			},
		},
		{
			name: "strict resource and ttl reduction",
			child: AuthorityContext{
				Actions:    []string{"payments:refund", "payments:read"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      2,
				MaxDepth:   3,
			},
		},
		{
			name: "strict max depth reduction",
			child: AuthorityContext{
				Actions:    []string{"payments:refund", "payments:read"},
				Resources:  []string{"customer/123", "invoice/456"},
				Expiration: expiration,
				Depth:      2,
				MaxDepth:   2,
			},
		},
		{
			name: "action privilege escalation",
			child: AuthorityContext{
				Actions:    []string{"payments:read", "payments:delete"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      2,
				MaxDepth:   3,
			},
			want: ErrActionsExpanded,
		},
		{
			name: "resource scope broadening",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/*"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      2,
				MaxDepth:   3,
			},
			want: ErrResourcesExpanded,
		},
		{
			name: "child ttl exceeds parent ttl",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(time.Second),
				Depth:      2,
				MaxDepth:   3,
			},
			want: ErrExpirationExtended,
		},
		{
			name: "delegation exceeds max depth",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      4,
				MaxDepth:   4,
			},
			want: ErrInvalidDepth,
		},
		{
			name: "next delegation exceeds max depth",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      2,
				MaxDepth:   1,
			},
			want: ErrInvalidContext,
		},
		{
			name: "maximum depth expansion",
			child: AuthorityContext{
				Actions:    []string{"payments:read"},
				Resources:  []string{"customer/123"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      2,
				MaxDepth:   4,
			},
			want: ErrMaxDepthExpanded,
		},
		{
			name: "authority unchanged",
			child: AuthorityContext{
				Actions:    []string{"payments:read", "payments:refund"},
				Resources:  []string{"invoice/456", "customer/123"},
				Expiration: expiration,
				Depth:      2,
				MaxDepth:   3,
			},
			want: ErrNotStrict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(parent, test.child)
			if !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRejectsDelegationAtMaximumDepth(t *testing.T) {
	expiration := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	parent := AuthorityContext{
		Actions:    []string{"payments:read"},
		Resources:  []string{"customer/123"},
		Expiration: expiration,
		Depth:      3,
		MaxDepth:   3,
	}
	child := AuthorityContext{
		Actions:    []string{"payments:read"},
		Resources:  []string{"customer/123"},
		Expiration: expiration.Add(-time.Minute),
		Depth:      4,
		MaxDepth:   4,
	}

	err := Validate(parent, child)
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMaxDepthExceeded)
	}
}

func TestValidateAllowsWildcardNarrowing(t *testing.T) {
	expiration := time.Now().UTC().Add(time.Minute)
	parent := AuthorityContext{
		Actions: []string{"read", "write"}, Resources: []string{"customer/*"},
		Expiration: expiration, Depth: 0, MaxDepth: 2,
	}
	child := AuthorityContext{
		Actions: []string{"read"}, Resources: []string{"customer/cus_123"},
		Expiration: expiration.Add(-time.Second), Depth: 1, MaxDepth: 2,
	}
	if err := Validate(parent, child); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMalformedResourcePattern(t *testing.T) {
	expiration := time.Now().UTC().Add(time.Minute)
	parent := AuthorityContext{
		Actions: []string{"read"}, Resources: []string{"customer/**"},
		Expiration: expiration, Depth: 0, MaxDepth: 2,
	}
	child := AuthorityContext{
		Actions: []string{"read"}, Resources: []string{"customer/123"},
		Expiration: expiration.Add(-time.Second), Depth: 1, MaxDepth: 2,
	}
	if err := Validate(parent, child); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLimitedUseAuthorityRules(t *testing.T) {
	expiration := time.Now().UTC().Add(time.Minute)
	grant := GrantContext{
		Audiences: []string{"service:test"}, Actions: []string{"read"}, Resources: []string{"item/*"},
		MaxTTL: time.Minute, MaxDelegationDepth: 2, CanDelegate: true, MaxUses: 5,
	}
	validRoot := AuthorityContext{Actions: []string{"read"}, Resources: []string{"item/1"}, Expiration: expiration, MaxUses: 5}
	if err := ValidateRoot(grant, "service:test", validRoot, expiration.Add(-time.Minute)); err != nil {
		t.Fatalf("valid limited root rejected: %v", err)
	}
	unlimitedRoot := validRoot
	unlimitedRoot.MaxUses = 0
	if err := ValidateRoot(grant, "service:test", unlimitedRoot, expiration.Add(-time.Minute)); !errors.Is(err, ErrUsesExpanded) {
		t.Fatalf("unlimited root error = %v, want %v", err, ErrUsesExpanded)
	}
	delegatingRoot := validRoot
	delegatingRoot.MaxDepth = 1
	if err := ValidateRoot(grant, "service:test", delegatingRoot, expiration.Add(-time.Minute)); !errors.Is(err, ErrStatefulDelegation) {
		t.Fatalf("delegating limited root error = %v, want %v", err, ErrStatefulDelegation)
	}
	child := AuthorityContext{Actions: validRoot.Actions, Resources: validRoot.Resources, Expiration: expiration.Add(-time.Second), Depth: 1, MaxDepth: 1, MaxUses: 1}
	if err := Validate(validRoot, child); !errors.Is(err, ErrStatefulDelegation) {
		t.Fatalf("limited parent delegation error = %v, want %v", err, ErrStatefulDelegation)
	}
}

func TestRandomDelegationTreesNeverExpandAuthority(t *testing.T) {
	// #nosec G404 -- deterministic pseudo-randomness is required for reproducible property tests.
	random := rand.New(rand.NewSource(0x555053494c4f4e))
	actionUniverse := []string{"read", "write", "refund", "settle", "export"}
	resourceUniverse := []string{"customer/*", "invoice/*", "repo/acme", "repo/widgets", "pipeline/release"}
	baseExpiration := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)

	for tree := 0; tree < 1000; tree++ {
		maxDepth := 1 + random.Intn(8)
		parent := AuthorityContext{
			Actions: randomNonEmptySubset(random, actionUniverse), Resources: randomNonEmptySubset(random, resourceUniverse),
			Expiration: baseExpiration.Add(time.Duration(1+random.Intn(3600)) * time.Second), Depth: 0, MaxDepth: maxDepth,
			Constraints: randomConstraints(random),
		}
		for depth := 1; depth <= maxDepth; depth++ {
			child := AuthorityContext{
				Actions: randomNonEmptySubset(random, parent.Actions), Resources: narrowResources(random, parent.Resources),
				Expiration: parent.Expiration.Add(-time.Duration(random.Intn(30)) * time.Second), Depth: depth, MaxDepth: parent.MaxDepth,
				Constraints: attenuateConstraints(random, parent.Constraints),
			}
			if setsEqual(toSet(child.Actions), toSet(parent.Actions)) && setsEqual(toSet(child.Resources), toSet(parent.Resources)) && child.Expiration.Equal(parent.Expiration) && constraintpkg.Equal(parent.Constraints, child.Constraints) {
				child.Expiration = child.Expiration.Add(-time.Second)
			}
			if err := Validate(parent, child); err != nil {
				t.Fatalf("tree %d depth %d rejected valid attenuation: %v\nparent=%+v\nchild=%+v", tree, depth, err, parent, child)
			}
			if !isSubset(toSet(child.Actions), toSet(parent.Actions)) || !resourcesSubset(child.Resources, parent.Resources) || child.Expiration.After(parent.Expiration) || child.MaxDepth > parent.MaxDepth || !constraintpkg.AtLeastAsStrong(parent.Constraints, child.Constraints) {
				t.Fatalf("tree %d depth %d expanded authority", tree, depth)
			}
			parent = child
		}
	}
}

func TestRandomEscalationsAreRejected(t *testing.T) {
	// #nosec G404 -- deterministic pseudo-randomness is required for reproducible property tests.
	random := rand.New(rand.NewSource(0x415554484f524954))
	expiration := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	for iteration := 0; iteration < 1000; iteration++ {
		parent := AuthorityContext{Actions: []string{"read"}, Resources: []string{"customer/*"}, Expiration: expiration, Depth: 0, MaxDepth: 2}
		child := AuthorityContext{Actions: []string{"read"}, Resources: []string{"customer/123"}, Expiration: expiration.Add(-time.Second), Depth: 1, MaxDepth: 2}
		parent.Constraints = map[string]string{"environment": "prod", "max_transaction_minor_units": "1000"}
		child.Constraints = map[string]string{"environment": "prod", "max_transaction_minor_units": "500"}
		switch random.Intn(5) {
		case 0:
			child.Actions = append(child.Actions, "admin")
		case 1:
			child.Resources = []string{"*"}
		case 2:
			child.Expiration = expiration.Add(time.Second)
		case 3:
			child.MaxDepth = 3
		case 4:
			child.Constraints["max_transaction_minor_units"] = "1001"
		}
		if err := Validate(parent, child); err == nil {
			t.Fatalf("iteration %d accepted authority escalation: %+v", iteration, child)
		}
	}
}

func randomNonEmptySubset(random *rand.Rand, values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if random.Intn(2) == 0 {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		result = append(result, values[random.Intn(len(values))])
	}
	return result
}

func narrowResources(random *rand.Rand, parent []string) []string {
	result := randomNonEmptySubset(random, parent)
	for index, value := range result {
		if len(value) > 2 && value[len(value)-2:] == "/*" && random.Intn(2) == 0 {
			// #nosec G115 -- Intn(26) proves this conversion remains in the ASCII letter range.
			result[index] = value[:len(value)-1] + "item-" + string(rune('a'+random.Intn(26)))
		}
	}
	return result
}

func randomConstraints(random *rand.Rand) map[string]string {
	constraints := map[string]string{"environment": "prod"}
	if random.Intn(2) == 0 {
		constraints["max_transaction_minor_units"] = "100000"
	}
	return constraints
}

func attenuateConstraints(random *rand.Rand, parent map[string]string) map[string]string {
	result := make(map[string]string, len(parent)+1)
	for key, value := range parent {
		result[key] = value
	}
	if value, exists := result["max_transaction_minor_units"]; exists && random.Intn(2) == 0 {
		if value == "100000" {
			result["max_transaction_minor_units"] = "50000"
		}
	}
	if _, exists := result["branch"]; !exists && random.Intn(4) == 0 {
		result["branch"] = "main"
	}
	return result
}
