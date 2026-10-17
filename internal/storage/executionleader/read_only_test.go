package executionleader

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
)

func TestReadOnlyVerifierRequiresActualSources(t *testing.T) {
	if _, err := NewReadOnlyVerifier(ReadOnlyVerifierConfig{}); err == nil {
		t.Fatal("missing root sources accepted")
	}
	for _, verifier := range []*ReadOnlyVerifier{nil, {}} {
		if _, err := verifier.Resolve(t.Context(), nil, host.RuntimeEffectCaller{}); err == nil {
			t.Fatal("unconstructed readonly verifier resolved material")
		}
		if err := verifier.VerifyCurrent(t.Context(), nil, host.RuntimeEffectCaller{}, executionwire.WorkerGrantMaterial{}); err == nil {
			t.Fatal("unconstructed readonly verifier accepted material")
		}
	}
	if _, ok := any(&ReadOnlyVerifier{}).(interface {
		Apply(context.Context, delivery.Intent) error
	}); ok {
		t.Fatal("root readonly verifier exposes service writes")
	}
}
