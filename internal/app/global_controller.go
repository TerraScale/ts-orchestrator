package app

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
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

func globalControlHome(global *GlobalControlConfig, nats natscell.Config) (string, error) {
	home := natscell.LinkHome
	if nats.Embedded == nil || nats.Embedded.Link == nil {
		var err error
		if home, err = interRegionLink(nats).GlobalControlHome(nats.Cell); err != nil {
			return "", err
		}
	}
	if global != nil && global.Home != "" && global.Home != home {
		return "", errors.New("global control home must agree with the interregion topology")
	}
	return home, nil
}

// interRegionLink returns the region's leaf topology material, or nil.
func interRegionLink(nats natscell.Config) *natscell.InterRegion {
	if nats.Embedded == nil {
		return nil
	}
	return nats.Embedded.InterRegion
}
