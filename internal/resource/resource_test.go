package resource

import "testing"

func TestCanonicalizeRejectsAmbiguousResources(t *testing.T) {
	tests := []string{
		"", "/customer/1", "customer/1/", "customer//1", "customer/../admin",
		"customer/./1", `customer\admin`, "customer/%2e%2e/admin", "customer/%252e%252e/admin",
		"customer/**", "customer/*/secret", "customer/\u0000", " customer/1", "customer/1 ",
		"cafe\u0301/1",
	}
	for _, value := range tests {
		if _, err := CanonicalizePattern(value); err == nil {
			t.Errorf("CanonicalizePattern(%q) unexpectedly succeeded", value)
		}
	}
}

func TestResourceCoverageIsSegmentBoundedAndCaseSensitive(t *testing.T) {
	if !Covers("customer/*", "customer/cus_123") {
		t.Fatal("expected descendant to be covered")
	}
	for _, value := range []string{"customer", "customers/1", "Customer/1", "customer/../admin", "customer/%2e%2e/admin"} {
		if Allows("customer/*", value) {
			t.Errorf("customer/* unexpectedly allowed %q", value)
		}
	}
}

func FuzzResourceCoverageNeverAcceptsInvalidValue(f *testing.F) {
	for _, seed := range []string{"customer/1", "customer/../admin", "customer/%2e%2e/admin", "customer//1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, err := CanonicalizeValue(value)
		if err != nil && Allows("customer/*", value) {
			t.Fatalf("invalid value %q was allowed", value)
		}
	})
}
