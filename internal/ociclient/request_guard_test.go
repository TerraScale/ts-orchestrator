package ociclient

import (
	"context"
	"errors"
	"testing"
)

func TestCheckRequestGuardRetainsAndSuppressesOriginalGuard(t *testing.T) {
	type valueKey struct{}
	sentinel := errors.New("original guard rejected")
	calls := 0
	ctx := WithRequestGuard(context.WithValue(t.Context(), valueKey{}, "original"), func(ctx context.Context) error {
		calls++
		if ctx.Value(valueKey{}) != "original" {
			t.Fatal("original call values lost")
		}
		if err := CheckRequestGuard(ctx); err != nil {
			t.Fatalf("suppressed nested guard failed: %v", err)
		}
		return sentinel
	})
	if err := CheckRequestGuard(ctx); !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("original guard cause or recursion suppression lost: calls=%d error=%v", calls, err)
	}
}

func TestCheckRequestGuardRetainsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	guarded := WithRequestGuard(ctx, func(context.Context) error { calls++; return nil })
	cancel()
	if err := CheckRequestGuard(guarded); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled call reached original guard: calls=%d error=%v", calls, err)
	}
	during, stop := context.WithCancel(t.Context())
	defer stop()
	sentinel := errors.New("guard cause")
	during = WithRequestGuard(during, func(context.Context) error { stop(); return sentinel })
	if err := CheckRequestGuard(during); !errors.Is(err, sentinel) || !errors.Is(err, context.Canceled) {
		t.Fatalf("guard or cancellation cause lost after guard returned: %v", err)
	}
	if err := CheckRequestGuard(t.Context()); err != nil {
		t.Fatalf("absent guard changed SDK semantics: %v", err)
	}
	if err := CheckRequestGuard(WithRequestGuard(t.Context(), nil)); err == nil {
		t.Fatal("typed nil guard accepted")
	}
}
