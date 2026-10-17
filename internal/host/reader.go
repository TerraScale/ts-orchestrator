package host

import (
	"context"
	"errors"
	"fmt"
)

// Reader gives operator and placement callers a read-only host view without
// requiring the controller's private response signing key.
type Reader struct{ controller *Controller }

func NewReader(ctx context.Context, cfg ReaderConfig) (*Reader, error) {
	if err := validateToken(cfg.Cell, "cell"); err != nil {
		return nil, err
	}
	if cfg.HostMutations == nil || cfg.Conn == nil {
		return nil, errors.New("reader requires NATS connection and ordered host mutation store")
	}
	state := cfg.State
	if state == nil {
		if cfg.JS == nil {
			return nil, errors.New("reader requires JetStream or host state")
		}
		var err error
		state, err = cfg.JS.KeyValue(ctx, stateBucket)
		if err != nil {
			return nil, err
		}
	}
	replicas := cfg.StateReplicas
	if replicas == 0 {
		replicas = 3
	}
	status, err := state.Status(ctx)
	if err != nil {
		return nil, err
	}
	if status.Config().Replicas != replicas {
		return nil, fmt.Errorf("host state has %d replicas, requires %d", status.Config().Replicas, replicas)
	}
	controlLog := cfg.ControlLog
	if controlLog == nil {
		if cfg.JS == nil {
			return nil, errors.New("reader requires JetStream or control log")
		}
		controlLog, err = cfg.JS.Stream(ctx, "TS_CONTROL_LOG")
		if err != nil {
			return nil, err
		}
	}
	return &Reader{controller: &Controller{cell: cfg.Cell, conn: cfg.Conn, state: state, controlLog: controlLog, mutations: cfg.HostMutations, credentialFloor: cfg.ManagedCredentialFloor, readOnly: true}}, nil
}

func (r *Reader) ListHosts(ctx context.Context) ([]HostStatus, error) {
	return r.controller.ListHosts(ctx)
}
