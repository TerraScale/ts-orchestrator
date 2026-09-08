package bootstrap

import (
	"context"
	"maps"
	"path/filepath"
	"slices"

	"github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/brokeradmission"
)

type EnrollmentBrokerConfig struct {
	ReaderGrants []brokeradmission.ReaderGrant
	BrokerIDs    []string
	Source       interface {
		Read(context.Context) ([]byte, error)
		Ack(context.Context, []byte) error
	}
	MinimumRevision       uint64
	AllowInitialBootstrap bool
	Verifier              *brokeradmission.Verifier
	Policy                brokeradmission.Policy
	CheckpointPath        string
	// CheckAuthority checks the exact live desired epoch/lease before applying a
	// newly read signed journal record. Restart recovery uses only the retained
	// signed checkpoint and keeps serving when control authority is unavailable.
	CheckAuthority func(context.Context, brokeradmission.Desired) error
}
type enrollmentBrokerState struct {
	config            EnrollmentBrokerConfig
	baseline, options *server.Options
	desired           brokeradmission.Desired
	applied           bool
}

func prepareEnrollmentBroker(ctx context.Context, baseline *server.Options, config *EnrollmentBrokerConfig) (*enrollmentBrokerState, error) {
	if config == nil {
		return nil, nil
	}
	if baseline == nil || config.Verifier == nil || config.CheckAuthority == nil || !filepath.IsAbs(config.CheckpointPath) || config.Policy.Environment == "" || config.Policy.Cluster == "" || len(config.Policy.Regions) == 0 || config.Policy.RegionalPermissions == nil {
		return nil, brokeradmission.ErrInvalid
	}
	frozen := *config
	frozen.ReaderGrants = slices.Clone(config.ReaderGrants)
	frozen.BrokerIDs = slices.Clone(config.BrokerIDs)
	frozen.Policy.Regions = maps.Clone(config.Policy.Regions)
	frozen.Policy.ProtectedNKeys = slices.Clone(config.Policy.ProtectedNKeys)
	var err error
	baseline, err = brokeradmission.ApplyReaderGrants(baseline, frozen.ReaderGrants, frozen.BrokerIDs, frozen.Policy)
	if err != nil {
		return nil, err
	}
	for _, grant := range frozen.ReaderGrants {
		frozen.Policy.ProtectedNKeys = append(frozen.Policy.ProtectedNKeys, grant.PublicNKey)
	}
	config = &frozen
	_, desired, err := brokeradmission.ReadCheckpoint(config.CheckpointPath, config.Verifier)
	if err != nil {
		return nil, err
	}
	if desired.Revision == 0 && config.MinimumRevision == 0 {
		if !config.AllowInitialBootstrap {
			return nil, brokeradmission.ErrInvalid
		}
		if err := brokeradmission.ClaimInitialBootstrap(config.CheckpointPath); err != nil {
			return nil, err
		}
	}
	if desired.Revision < config.MinimumRevision {
		if config.Source == nil {
			return nil, brokeradmission.ErrInvalid
		}
		wire, err := config.Source.Read(ctx)
		if err != nil {
			return nil, err
		}
		fresh, err := config.Verifier.Verify(wire)
		if err != nil {
			return nil, err
		}
		if fresh.Revision < config.MinimumRevision {
			return nil, brokeradmission.ErrRollback
		}
		if err := brokeradmission.CheckAdvance(desired, fresh); err != nil {
			return nil, err
		}
		if err := config.CheckAuthority(ctx, fresh); err != nil {
			return nil, err
		}
		if _, err := brokeradmission.ApplyOptions(baseline, fresh, config.Policy); err != nil {
			return nil, err
		}
		if err := brokeradmission.PersistCheckpoint(config.CheckpointPath, wire); err != nil {
			return nil, err
		}
		desired = fresh
	}
	state := &enrollmentBrokerState{config: frozen, baseline: baseline.Clone(), options: baseline, desired: desired, applied: true}
	if desired.Revision > 0 {
		state.options, err = brokeradmission.ApplyOptions(state.baseline, desired, config.Policy)
		if err != nil {
			return nil, err
		}
	}
	return state, nil
}

// ApplyEnrollmentGrants updates the linked broker's native auth map. NATS
// disconnects existing clients whose keys were removed; it rejects reconnects.
// A failed reload is not acknowledged, and its persisted desired state remains
// authoritative for a retry or process restart.
func (s *NatsServer) ApplyEnrollmentGrants(ctx context.Context, wire []byte) error {
	if s == nil || ctx == nil {
		return brokeradmission.ErrInvalid
	}
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	state := s.enrollment
	if state == nil || s.instance == nil {
		return brokeradmission.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	desired, err := state.config.Verifier.Verify(wire)
	if err != nil {
		return err
	}
	if err := brokeradmission.CheckAdvance(state.desired, desired); err != nil {
		return err
	}
	options, err := brokeradmission.ApplyOptions(state.baseline, desired, state.config.Policy)
	if err != nil {
		return err
	}
	if err := state.config.CheckAuthority(ctx, desired); err != nil {
		return err
	}
	if desired.Revision == state.desired.Revision && state.applied {
		return nil
	}
	if err := brokeradmission.PersistCheckpoint(state.config.CheckpointPath, wire); err != nil {
		return err
	}
	state.desired = desired
	state.applied = false
	if err := s.instance.ReloadOptions(options); err != nil {
		return err
	}
	state.options = options
	state.applied = true
	return nil
}
