package app

import (
	"context"
	"testing"
)

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
