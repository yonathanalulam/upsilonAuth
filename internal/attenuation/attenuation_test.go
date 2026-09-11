package attenuation

import (
	"errors"
	"testing"
	"time"
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
