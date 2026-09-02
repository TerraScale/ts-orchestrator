package contracts

import (
	"strings"
	"testing"
)

func TestCellTokenBoundariesAndInvalidForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "minimum", value: "a", valid: true},
		{name: "maximum", value: strings.Repeat("a", 63), valid: true},
		{name: "empty", value: "", valid: false},
		{name: "too-long", value: strings.Repeat("a", 64), valid: false},
		{name: "leading-dash", value: "-a", valid: false},
		{name: "trailing-dash", value: "a-", valid: false},
		{name: "uppercase", value: "A", valid: false},
		{name: "underscore", value: "a_b", valid: false},
		{name: "unicode", value: "grü", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CellTokenIsValid(test.value); got != test.valid {
				t.Fatalf("CellTokenIsValid(%q) = %v, want %v", test.value, got, test.valid)
			}
		})
	}
}
