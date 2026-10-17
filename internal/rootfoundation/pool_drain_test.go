package rootfoundation

import (
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// A final immutable append can call this guard while holding the authority
// mutex. Busy capture must refuse promptly so its renewal barrier can proceed.
func TestPoolExecutionGuardRefusesBusyCapture(t *testing.T) {
	backend := new(Backend)
	backend.poolMu.Lock()
	defer backend.poolMu.Unlock()
	result := make(chan error, 1)
	go func() {
		result <- backend.GuardPoolExecution(t.Context(), rootoci.Call{}, drainwire.ExecutionHold{})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, rootoci.ErrPending) {
			t.Fatal("busy protected capture did not refuse execution", err)
		}
	case <-time.After(time.Second):
		t.Fatal("execution guard waited behind capture's renewal barrier")
	}
}
