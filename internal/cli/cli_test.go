package cli

import (
	"bytes"
	"testing"
)

func TestLocalCommandDispatchWithoutRuntimeConfig(t *testing.T) {
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"--help"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("command produced no output")
	}
}
