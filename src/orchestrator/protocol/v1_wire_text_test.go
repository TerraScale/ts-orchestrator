package protocol

import "testing"

func TestV1UTF16CodeUnitCount(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{value: "ascii", want: 5},
		{value: "caf\u00e9", want: 4},
		{value: "\U0001F680", want: 2},
		{value: "a\U0001F680z", want: 4},
	}

	for _, test := range tests {
		if got := v1UTF16CodeUnitCount(test.value); got != test.want {
			t.Fatalf("v1UTF16CodeUnitCount(%q) = %d, want %d", test.value, got, test.want)
		}
	}
}
