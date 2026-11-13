package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// channelSource opens the region's head bucket once, from the controller's
// instance principal; a failure (the metadata service, the namespace call)
// is retried on the next use.
type channelSource struct {
	mu       sync.Mutex
	client   *rootoci.Client
	location *releasechannel.Location
	open     func(context.Context) (releasechannel.Location, error)
}

func (s *channelSource) get(ctx context.Context) (releasechannel.Location, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.location != nil {
		return *s.location, nil
	}
	location, err := s.open(ctx)
	if err != nil {
		return releasechannel.Location{}, err
	}
	s.location = &location
	return location, nil
}

func instancePrincipalChannel(region, cell string) *channelSource {
	return &channelSource{client: rootoci.NewClient(rootoci.Expectations{Cell: cell}), open: func(ctx context.Context) (releasechannel.Location, error) {
		bucket, err := releasechannel.BucketName(cell)
		if err != nil {
			return releasechannel.Location{}, err
		}
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return releasechannel.Location{}, err
		}
		client, err := factory.ObjectStorage()
		if err != nil {
			return releasechannel.Location{}, err
		}
		namespace, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
		if err != nil || namespace.Value == nil {
			return releasechannel.Location{}, fmt.Errorf("read the Object Storage namespace: %w", err)
		}
		return releasechannel.Location{Client: client, Namespace: *namespace.Value, Bucket: bucket}, nil
	}}
}

// generationState is the progress of one generation's rollouts: the
// controllers', then the hosts'. Completion requires every current unit to
// freshly prove the target, even after its recorded rollout completed.
type rolloutStatusReader interface {
	Load(context.Context, string) (rollout.Record, uint64, error)
	Desired(context.Context) (rollout.Desired, uint64, error)
	IsKnownBad(context.Context, string) (bool, error)
}

func (c *rolloutControl) generationState(ctx context.Context, store rolloutStatusReader, generation rollout.Release,
) (releasechannel.State, string, error) {
	parts := []struct {
		domain string
		units  func(context.Context) ([]rollout.Unit, error)
	}{
		{rollout.ControllerReleaseDomain, func(context.Context) ([]rollout.Unit, error) { return c.program.Controllers, nil }},
		{rollout.HostReleaseDomain, c.program.Hosts},
	}
	for _, part := range parts {
		if part.units == nil {
			continue
		}
		record, _, err := store.Load(ctx, entityid.Derive(part.domain, rollout.ReleaseRolloutID(generation.Generation)))
		if errors.Is(err, rollout.ErrAbandonedRollout) {
			return releasechannel.StateFailed, "the rollout was abandoned before any update; run release again", nil
		}
		if err == nil {
			switch record.Phase {
			case rollout.PhaseComplete:
			case rollout.PhaseRolledBack, rollout.PhaseAborted, rollout.PhaseFrozen:
				return releasechannel.StateFailed, fmt.Sprintf("%s %s: %s", record.RolloutID, record.Phase, record.Reason), nil
			default:
				return releasechannel.StateRolling, fmt.Sprintf("%s %s", record.RolloutID, record.Phase), nil
			}
		}
		if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			return "", "", err
		}
		// No rollout of this part started (yet) for this generation.
		desired, _, err := store.Desired(ctx)
		if err != nil {
			return "", "", err
		}
		// A follower read can lag the generation just published by CAS.
		// Only a newer generation proves this release was superseded.
		if desired.Generation() < generation.Generation {
			return releasechannel.StateRolling, fmt.Sprintf("waiting for generation %d to become visible", generation.Generation), nil
		}
		if desired.Generation() != generation.Generation {
			return releasechannel.StateFailed, fmt.Sprintf("generation %d was replaced by generation %d before it rolled out",
				generation.Generation, desired.Generation()), nil
		}
		if bad, err := store.IsKnownBad(ctx, generation.Digest); err != nil || bad {
			return releasechannel.StateFailed, "the release is known bad in this cell", err
		}
		if desired.Paused {
			return releasechannel.StateRolling, "the cell's rollouts are paused", nil
		}
		units, err := part.units(ctx)
		if err != nil {
			return releasechannel.StateRolling, "the cell's hosts are unreadable: " + err.Error(), nil
		}
		behind, _, err := c.program.Behind(units, generation.Digest)
		if err == nil && len(behind) == 0 {
			continue
		}
		if err != nil {
			return releasechannel.StateRolling, "waiting for health proofs: " + err.Error(), nil
		}
		reason := "waiting for the rollout to start"
		if status := c.status.Load(); status != nil && status.Waiting != "" {
			reason = status.Waiting
		}
		return releasechannel.StateRolling, reason, nil
	}
	return releasechannel.StateComplete, "", nil
}
