package rootfoundation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNodeScopeCannotRenewOriginalLifetimeWithFreshContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name  string
		scope NodeOperationScope
	}{
		{name: "missing original source", scope: NodeOperationScope{ExpiresAt: time.Now().Add(time.Hour), deadline: time.Now().Add(time.Minute)}},
		{name: "cancelled original source", scope: NodeOperationScope{source: cancelled, ExpiresAt: time.Now().Add(time.Hour), deadline: time.Now().Add(time.Minute)}},
		{name: "extended public expiry", scope: NodeOperationScope{source: context.Background(), ExpiresAt: time.Now().Add(time.Hour), deadline: time.Now().Add(-time.Second)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.scope.Revalidate(context.Background()); !errors.Is(err, ErrScope) {
				t.Fatalf("original lifetime bypass reached later admission: %v", err)
			}
		})
	}
}
