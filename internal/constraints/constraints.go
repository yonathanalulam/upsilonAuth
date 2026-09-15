package constraints

import (
	"strconv"
	"strings"
)

const MaxConstraints = 16

// Valid reports whether constraints use the intentionally small, typed V1
// vocabulary. Unknown keys fail closed so different verifiers cannot silently
// interpret the same lease differently.
func Valid(values map[string]string) bool {
	if len(values) > MaxConstraints {
		return false
	}
	for key, value := range values {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return false
		}
		switch key {
		case "environment", "repository", "branch":
		case "http_method":
			if value != strings.ToUpper(value) || len(value) > 16 {
				return false
			}
		case "max_transaction_minor_units":
			parsed, err := strconv.ParseUint(value, 10, 63)
			if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// AtLeastAsStrong enforces monotonic constraint attenuation. A child must
// preserve every parent constraint and may lower numeric ceilings or add new
// constraints.
func AtLeastAsStrong(parent, child map[string]string) bool {
	if !Valid(parent) || !Valid(child) {
		return false
	}
	for key, parentValue := range parent {
		childValue, exists := child[key]
		if !exists {
			return false
		}
		if key == "max_transaction_minor_units" {
			parentAmount, _ := strconv.ParseUint(parentValue, 10, 63)
			childAmount, _ := strconv.ParseUint(childValue, 10, 63)
			if childAmount > parentAmount {
				return false
			}
			continue
		}
		if childValue != parentValue {
			return false
		}
	}
	return true
}

func Equal(left, right map[string]string) bool {
	return len(left) == len(right) && AtLeastAsStrong(left, right) && AtLeastAsStrong(right, left)
}

// Satisfied compares locally-derived request values with signed stateless
// constraints. Callers remain responsible for deriving those values from
// trusted request/application state.
func Satisfied(required, actual map[string]string) bool {
	if !Valid(required) {
		return false
	}
	for key, expected := range required {
		value, exists := actual[key]
		if !exists {
			return false
		}
		if key == "max_transaction_minor_units" {
			limit, limitErr := strconv.ParseUint(expected, 10, 63)
			amount, amountErr := strconv.ParseUint(value, 10, 63)
			if limitErr != nil || amountErr != nil || amount > limit {
				return false
			}
			continue
		}
		if value != expected {
			return false
		}
	}
	return true
}
