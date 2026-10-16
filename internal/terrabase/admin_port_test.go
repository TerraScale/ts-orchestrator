package terrabase

import (
	"strconv"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// The host agent's default observability listener must leave the member's
// loopback admin port free on a host that runs both.
func TestDefaultObservabilityListenerAvoidsTheAdminPort(t *testing.T) {
	if got := (observability.Config{}).Address(); got == "127.0.0.1:"+strconv.Itoa(DefaultAdminPort) {
		t.Fatalf("default observability listener %s collides with the TerraBase admin port", got)
	}
}
