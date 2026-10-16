package app

import (
	"bytes"
	"context"
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

func TestAutomaticNetBirdRetriesUnavailableFoundation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	loop := netbirdManagementLoop(nil)
	if loop.Token == nil {
		t.Fatal("automatic NetBird credential discovery is missing")
	}
	value, err := loop.Token(ctx)
	if err == nil || len(value) != 0 {
		t.Fatalf("canceled OCI discovery returned a credential: bytes=%d error=%v", len(value), err)
	}
	loop.Run(ctx)
}
