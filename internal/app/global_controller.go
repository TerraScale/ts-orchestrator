package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
)

// GlobalControlConfig optionally pins the home derived from the signed topology.
type GlobalControlConfig struct {
	Home string `json:"home"`
}

// globalControl is this controller's view of global state: the fenced writer
// and global-scope authority in the home region, or a read-only mirror reader
// everywhere else. The budget allocator and region suggestions read it.
type globalControl struct {
	authority *authority.Runtime
	stop      context.CancelFunc
	writer    *globalcontrol.Writer
	reader    *globalcontrol.Reader
}
