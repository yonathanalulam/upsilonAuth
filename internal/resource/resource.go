package resource

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrInvalidResource      = errors.New("invalid resource")
	ErrDuplicateResource    = errors.New("duplicate resource")
	ErrResourceNotCanonical = errors.New("resource is not canonical")
)

// CanonicalizePattern validates a resource scope and returns its NFC form.
// Resource identifiers are case-sensitive. Percent encoding is deliberately
// forbidden so the control plane and protected service cannot decode a value
// differently. The only wildcard is a complete final "*" segment.
func CanonicalizePattern(value string) (string, error) {
	return canonicalize(value, true)
}

// CanonicalizeValue validates a concrete resource value. Wildcards are not
// valid in a value presented by a protected service.
func CanonicalizeValue(value string) (string, error) {
	return canonicalize(value, false)
}

func CanonicalizePatterns(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, ErrInvalidResource
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := CanonicalizePattern(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical]; exists {
			return nil, ErrDuplicateResource
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func Covers(parentPattern, childPattern string) bool {
	parent, err := CanonicalizePattern(parentPattern)
	if err != nil {
		return false
	}
	child, err := CanonicalizePattern(childPattern)
	if err != nil {
		return false
	}
	if parent == child {
		return true
	}
	if !strings.HasSuffix(parent, "/*") {
		return false
	}
	prefix := strings.TrimSuffix(parent, "*")
	return strings.HasPrefix(child, prefix) && len(child) > len(prefix)
}

func Allows(pattern, value string) bool {
	canonicalPattern, err := CanonicalizePattern(pattern)
	if err != nil {
		return false
	}
	canonicalValue, err := CanonicalizeValue(value)
	if err != nil {
		return false
	}
	if canonicalPattern == canonicalValue {
		return true
	}
	if !strings.HasSuffix(canonicalPattern, "/*") {
		return false
	}
	prefix := strings.TrimSuffix(canonicalPattern, "*")
	return strings.HasPrefix(canonicalValue, prefix) && len(canonicalValue) > len(prefix)
}

func Subset(candidate, parent []string) bool {
	for _, child := range candidate {
		covered := false
		for _, ancestor := range parent {
			if Covers(ancestor, child) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func canonicalize(value string, wildcardAllowed bool) (string, error) {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", ErrInvalidResource
	}
	if strings.ContainsAny(value, "%\\?#") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return "", ErrInvalidResource
	}
	canonical := norm.NFC.String(value)
	if canonical != value {
		return "", ErrResourceNotCanonical
	}
	segments := strings.Split(canonical, "/")
	for index, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrInvalidResource
		}
		if segment == "*" {
			if !wildcardAllowed || index != len(segments)-1 || index == 0 {
				return "", ErrInvalidResource
			}
			continue
		}
		if strings.Contains(segment, "*") {
			return "", ErrInvalidResource
		}
		for _, character := range segment {
			if unicode.IsControl(character) || unicode.IsSpace(character) || unicode.Is(unicode.Pattern_Syntax, character) && !strings.ContainsRune("-_.:@", character) {
				return "", ErrInvalidResource
			}
		}
	}
	return canonical, nil
}
