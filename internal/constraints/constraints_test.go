package constraints

import "testing"

func TestConstraintVocabularyAndAttenuation(t *testing.T) {
	parent := map[string]string{"environment": "prod", "max_transaction_minor_units": "1000"}
	child := map[string]string{"environment": "prod", "max_transaction_minor_units": "500", "branch": "main"}
	if !Valid(parent) || !Valid(child) || !AtLeastAsStrong(parent, child) {
		t.Fatal("valid narrowed constraints were rejected")
	}
	if AtLeastAsStrong(child, parent) {
		t.Fatal("constraint removal or numeric ceiling expansion was accepted")
	}
	for _, invalid := range []map[string]string{
		{"unknown": "value"},
		{"http_method": "get"},
		{"max_transaction_minor_units": "010"},
		{"max_transaction_minor_units": "0"},
	} {
		if Valid(invalid) {
			t.Fatalf("invalid constraints accepted: %#v", invalid)
		}
	}
}

func TestSatisfiedFailsClosed(t *testing.T) {
	required := map[string]string{
		"environment": "prod", "http_method": "POST", "max_transaction_minor_units": "500",
	}
	if !Satisfied(required, map[string]string{
		"environment": "prod", "http_method": "POST", "max_transaction_minor_units": "500",
	}) {
		t.Fatal("matching stateless context was rejected")
	}
	for _, actual := range []map[string]string{
		{"environment": "prod", "http_method": "POST"},
		{"environment": "dev", "http_method": "POST", "max_transaction_minor_units": "10"},
		{"environment": "prod", "http_method": "POST", "max_transaction_minor_units": "501"},
	} {
		if Satisfied(required, actual) {
			t.Fatalf("insufficient context accepted: %#v", actual)
		}
	}
}
