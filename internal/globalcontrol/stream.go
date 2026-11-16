package globalcontrol

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// StreamName is the global stream in the home region and its mirror name.
	StreamName = protocol.GlobalControlStream
	contract   = "global-control-v1"
	apiTimeout = 5 * time.Second
)
