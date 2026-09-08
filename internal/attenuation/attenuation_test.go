package attenuation

import (
	"errors"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	expiration := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	parent := AuthorityContext{
		Actions:    []string{"read", "write"},
		Resources:  []string{"orders", "invoices"},
		Expiration: expiration,
		Depth:      2,
	}

	tests := []struct {
		name  string
		child AuthorityContext
		want  error
	}{
		{
			name: "action subset",
			child: AuthorityContext{
				Actions:    []string{"read"},
				Resources:  []string{"orders", "invoices"},
				Expiration: expiration,
				Depth:      3,
			},
		},
		{
			name: "resource subset and earlier expiration",
			child: AuthorityContext{
				Actions:    []string{"read", "write"},
				Resources:  []string{"orders"},
				Expiration: expiration.Add(-time.Minute),
				Depth:      3,
			},
		},
		{
			name: "equal authority",
			child: AuthorityContext{
				Actions:    []string{"write", "read"},
				Resources:  []string{"invoices", "orders"},
				Expiration: expiration,
				Depth:      3,
			},
			want: ErrNotStrict,
		},
		{
			name: "expanded action",
			child: AuthorityContext{
				Actions:    []string{"read", "delete"},
				Resources:  []string{"orders"},
				Expiration: expiration,
				Depth:      3,
			},
			want: ErrActionsExpanded,
		},
		{
			name: "expanded resource",
			child: AuthorityContext{
				Actions:    []string{"read"},
				Resources:  []string{"payments"},
				Expiration: expiration,
				Depth:      3,
			},
			want: ErrResourcesExpanded,
		},
		{
			name: "extended expiration",
			child: AuthorityContext{
				Actions:    []string{"read"},
				Resources:  []string{"orders"},
				Expiration: expiration.Add(time.Second),
				Depth:      3,
			},
			want: ErrExpirationExtended,
		},
		{
			name: "skipped depth",
			child: AuthorityContext{
				Actions:    []string{"read"},
				Resources:  []string{"orders"},
				Expiration: expiration,
				Depth:      4,
			},
			want: ErrInvalidDepth,
		},
		{
			name: "duplicate action",
			child: AuthorityContext{
				Actions:    []string{"read", "read"},
				Resources:  []string{"orders"},
				Expiration: expiration,
				Depth:      3,
			},
			want: ErrInvalidContext,
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
