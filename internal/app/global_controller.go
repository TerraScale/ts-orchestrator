package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// GlobalControlConfig optionally pins the home derived from the signed topology.
type GlobalControlConfig struct {
	Home string `json:"home"`
}

// globalControl is this controller's view of global state: the fenced writer
// and global-scope authority in the home region, or a read-only mirror reader
// everywhere else. Consumers (directory admission, the region planner) are
// wired in follow-up changes.
type globalControl struct {
	authority *authority.Runtime
	stop      context.CancelFunc
	writer    *globalcontrol.Writer
	reader    *globalcontrol.Reader
}

func (g *globalControl) close() {
	if g.authority == nil {
		return
	}
	_ = g.authority.Close()
	g.stop()
}

func globalControlHome(global *GlobalControlConfig, nats natscell.Config) (string, error) {
	home, err := interRegionLink(nats).GlobalControlHome(nats.Cell)
	if err != nil {
		return "", err
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

// globalMirrorPeers are the regions whose durable mirror consumers the home
// region creates: every interregion peer, or none for a standalone home.
func globalMirrorPeers(nats natscell.Config) []string {
	if link := interRegionLink(nats); link != nil {
		return link.Peers
	}
	return nil
}

// startGlobalControl starts the global-scope lease and writable stream in the
// home region, or the read-only mirror elsewhere.
func startGlobalControl(ctx context.Context, cfg Config, js jetstream.JetStream, deploymentID, candidateID string,
	clockCheck func() error, fullClusterReady func() bool,
) (*globalControl, error) {
	home, err := globalControlHome(cfg.Controller.Global, cfg.NATS)
	if err != nil {
		return nil, err
	}
	if home != cfg.NATS.Cell {
		reader, _, err := retryControllerOpen(ctx, "open global control mirror", fullClusterReady, false,
			func(attempt context.Context) (*globalcontrol.Reader, error) {
				return globalcontrol.OpenMirror(attempt, js, home, cfg.NATS.Cell, cfg.NATS.Replicas)
			}, nil)
		if err != nil {
			return nil, err
		}
		return &globalControl{reader: reader}, nil
	}
	// Fail fast on credentials issued before the global home grants: a
	// denied publish would otherwise look like a timeout and retry forever.
	if err := natscell.ValidateGlobalControllerPermissions(cfg.NATS); err != nil {
		return nil, fmt.Errorf("global home controller: %w", err)
	}
	control, stop, err := retryControllerOpen(ctx, "start global authority", fullClusterReady, true,
		func(attempt context.Context) (*authority.Runtime, error) {
			return authority.Start(attempt, js, authority.Config{
				Scope: protocol.GlobalScope, DeploymentID: deploymentID, CandidateID: candidateID,
				LeaseDuration: time.Duration(cfg.Controller.LeaseSeconds) * time.Second,
				RenewInterval: time.Duration(cfg.Controller.RenewSeconds) * time.Second,
				Replicas:      cfg.NATS.Replicas,
				ClockCheck:    clockCheck,
			})
		}, func(control *authority.Runtime) { _ = control.Close() })
	if err != nil {
		return nil, err
	}
	writer, _, err := retryControllerOpen(ctx, "open global control stream", fullClusterReady, false,
		func(attempt context.Context) (*globalcontrol.Writer, error) {
			return globalcontrol.OpenHome(attempt, js, cfg.NATS.Cell, globalMirrorPeers(cfg.NATS), cfg.NATS.Replicas, control)
		}, nil)
	if err != nil {
		_ = control.Close()
		stop()
		return nil, err
	}
	return &globalControl{authority: control, stop: stop, writer: writer, reader: &writer.Reader}, nil
}
