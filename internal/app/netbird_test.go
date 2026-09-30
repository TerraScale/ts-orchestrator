package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestNetBirdEnrollCommandDispatchRejectsPositionalArguments(t *testing.T) {
	var output bytes.Buffer
	err := Run(t.Context(), []string{"netbird-enroll", "unexpected"}, &output)
	if err == nil || !strings.Contains(err.Error(), "no positional arguments") || output.Len() != 0 {
		t.Fatalf("enrollment command dispatch failed: output=%q error=%v", output.String(), err)
	}
}
