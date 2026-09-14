package main

import (
	"math"
	"testing"
)

func TestEnvFloatRejectsNonFiniteValues(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-Inf"} {
		t.Setenv("TEST_RATE", value)
		if _, err := envFloat("TEST_RATE", 120); err == nil {
			t.Fatalf("envFloat accepted %q", value)
		}
	}

	t.Setenv("TEST_RATE", "120.5")
	value, err := envFloat("TEST_RATE", 120)
	if err != nil || value != 120.5 || math.IsNaN(value) || math.IsInf(value, 0) {
		t.Fatalf("envFloat() = %v, %v", value, err)
	}
}
