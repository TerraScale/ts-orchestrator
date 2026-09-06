package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// Targets come from admitted host identity, not request-controlled endpoints.
// ValidateProposal must evaluate current control-plane placement/residency
// policy before a desired proposal is accepted into the fenced durable journal.
type productionPlacementConfig struct {
	Targets          []productionPlacementTarget
	ValidateProposal func(context.Context, string, *pb.PlacementControlServiceStageRequest) error
}
type productionPlacementTarget struct{ ServerIdentity, Principal string }
type productionPlacement struct {
	config     productionPlacementConfig
	publishers map[string]*placementpublisher.Publisher
	mu         sync.Mutex
	failures   map[string]error
}

func newProductionPlacement(config productionPlacementConfig, session globalWorkerSession) (*productionPlacement, error) {
	if len(config.Targets) == 0 || len(config.Targets) > 128 || config.ValidateProposal == nil {
		return nil, errors.New("runtime placement: admitted host targets and placement policy are required")
	}
	journal, err := placementpublisher.NewNATSJournal(placementpublisher.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return nil, err
	}
	result := &productionPlacement{config: config, publishers: map[string]*placementpublisher.Publisher{}, failures: map[string]error{}}
	for _, identity := range config.Targets {
		if _, exists := result.publishers[identity.ServerIdentity]; exists {
			return nil, errors.New("runtime placement: duplicate host identity")
		}
		target, err := placementpublisher.NewRemoteTarget(session.Connection, identity.ServerIdentity, identity.Principal, 10*time.Second)
		if err != nil {
			return nil, err
		}
		publisher, err := placementpublisher.New(journal, target, session.CheckEffectAuthority)
		if err != nil {
			return nil, err
		}
		result.publishers[identity.ServerIdentity] = publisher
	}
	return result, nil
}
func (placement *productionPlacement) Accept(ctx context.Context, serverIdentity, operationID string, request *pb.PlacementControlServiceStageRequest) error {
	publisher, ok := placement.publishers[serverIdentity]
	if !ok {
		return errors.New("runtime placement: host is not admitted")
	}
	if err := placement.config.ValidateProposal(ctx, serverIdentity, request); err != nil {
		return err
	}
	return publisher.Accept(ctx, operationID, request)
}

func (placement *productionPlacement) AcceptReceipt(ctx context.Context, serverIdentity, operationID string, request *pb.PlacementControlServiceStageRequest) (*pb.PlacementControlServiceStageResponse, error) {
	publisher, ok := placement.publishers[serverIdentity]
	if !ok {
		return nil, errors.New("runtime placement: host is not admitted")
	}
	if err := placement.config.ValidateProposal(ctx, serverIdentity, request); err != nil {
		return nil, err
	}
	if err := publisher.Accept(ctx, operationID, request); err != nil {
		return nil, err
	}
	return publisher.Reconcile(ctx)
}
func (placement *productionPlacement) Reconcile(ctx context.Context) error {
	for _, identity := range placement.config.Targets {
		_, err := placement.publishers[identity.ServerIdentity].Reconcile(ctx)
		if errors.Is(err, placementpublisher.ErrIntentMissing) {
			err = nil
		}
		if errors.Is(err, placementpublisher.ErrPlacementEpochFenced) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		placement.mu.Lock()
		previous := placement.failures[identity.ServerIdentity]
		placement.failures[identity.ServerIdentity] = err
		placement.mu.Unlock()
		// Report transitions, not every retry. Durable intent remains unchanged on
		// uncertainty; one unreachable host must not stop retries to surviving hosts.
		if err != nil && (previous == nil || previous.Error() != err.Error()) {
			slog.ErrorContext(ctx, "placement proposal remains unresolved", "host", identity.ServerIdentity, "error", err)
		}
	}
	return nil
}

// AcceptPlacement is the production control ingress after domain validation.
// Its response acknowledges persisted intent only; the engine separately stages
// PENDING and never converts it into membership or readiness evidence here.
func (runtime *productionRuntime) AcceptPlacement(ctx context.Context, serverIdentity, operationID string, request *pb.PlacementControlServiceStageRequest) error {
	if runtime == nil {
		return errors.New("runtime placement: global runtime missing")
	}
	runtime.mu.Lock()
	active := runtime.active
	runtime.mu.Unlock()
	if active == nil || active.placement == nil {
		return errors.New("runtime placement: current GRU authority required")
	}
	if err := active.placement.Accept(ctx, serverIdentity, operationID, request); err != nil {
		return fmt.Errorf("runtime placement acceptance: %w", err)
	}
	return nil
}
