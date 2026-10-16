package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

func TestNodePoolBindsAfterAFailedAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	binding := &nodePoolBinding{}
	if _, err := binding.Observe(ctx); err == nil {
		t.Fatal("unbound pool observed nodes")
	}
	if binding.scaleStatus() != nil {
		t.Fatal("unbound pool published a status")
	}
	attempts := 0
	bind := func(context.Context) (boundNodePool, error) {
		attempts++
		if attempts == 1 {
			return boundNodePool{}, errors.New("IMDS is not answering")
		}
		return boundNodePool{status: func() *nodescale.Status {
			return &nodescale.Status{Schema: nodescale.StatusSchema, Cell: "gru"}
		}}, nil
	}
	bindNodePool(ctx, binding, time.Millisecond, bind)
	if attempts != 2 || binding.bound.Load() == nil {
		t.Fatalf("attempts = %d, bound = %v; want the second attempt to bind", attempts, binding.bound.Load() != nil)
	}
	if status := binding.scaleStatus(); status == nil || status.Cell != "gru" {
		t.Fatalf("bound pool status = %+v, want the running scaler's", status)
	}
}
