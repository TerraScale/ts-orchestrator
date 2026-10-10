package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// managedTerminalRuntime resumes every admitted terminal marker on the current
// leader. A marker is durable before any destructive OCI reconciliation starts.
type managedTerminalRuntime struct {
	control           *authority.Runtime
	placements        placement.Store
	hosts             *host.Controller
	executor          oci.TerminalExecutor
	enrollment        *managedHostEnrollment
	requireEnrollment bool
}

func (runtime *managedTerminalRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.control == nil || runtime.placements == nil || runtime.executor == nil {
		return errors.New("managed terminal runtime is incomplete")
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		if err := runtime.reconcile(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "managed terminal reconciliation failed", observability.ComponentKey, "terminal", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (runtime *managedTerminalRuntime) reconcile(ctx context.Context) error {
	if !runtime.control.Current().CanMutate() {
		return nil
	}
	intents, err := runtime.placements.ListIntents(ctx)
	if err != nil {
		return fmt.Errorf("list admitted placement intents for terminal replay: %w", err)
	}
	var failures []error
	for _, placementIntent := range intents {
		entry, err := runtime.control.ReadTerminalIntent(ctx, placementIntent.DatabaseID, placementIntent.PartitionID)
		if errors.Is(err, authority.ErrNotFound) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		intent, err := decodeCurrentTerminal(entry, placementIntent.DatabaseID, placementIntent.PartitionID)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := runtime.reconcileIntent(ctx, intent, entry.Sequence); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func decodeCurrentTerminal(entry authority.LogEntry, databaseID, partitionID string) (authority.TerminalIntent, error) {
	var intent authority.TerminalIntent
	if entry.Kind != authority.MutationTerminalIntent || entry.SubjectKey != databaseID+"."+partitionID ||
		entry.Sequence == 0 || entry.Epoch == 0 || len(entry.Payload) == 0 ||
		json.Unmarshal(entry.Payload, &intent, json.RejectUnknownMembers(true)) != nil ||
		intent.Validate() != nil || intent.DatabaseID != databaseID || intent.PartitionID != partitionID ||
		intent.OperationID != entry.OperationID {
		return authority.TerminalIntent{}, errors.New("current terminal marker has an invalid workload binding")
	}
	return intent, nil
}

func (runtime *managedTerminalRuntime) reconcileIntent(ctx context.Context, intent authority.TerminalIntent,
	markerSequence uint64,
) error {
	if runtime.hosts != nil {
		if err := runtime.withdrawActiveDesired(ctx, intent); err != nil {
			slog.WarnContext(ctx, "managed terminal optional desired withdrawal failed", observability.ComponentKey, "terminal",
				"database", intent.DatabaseID, "partition", intent.PartitionID, "error", err)
		}
	}
	status, err := runtime.executor.ReconcileTerminal(ctx, intent, markerSequence)
	if err != nil {
		return fmt.Errorf("reconcile exact terminal OCI inventory %s/%s: %w", intent.DatabaseID, intent.PartitionID, err)
	}
	if status.Phase != "complete" {
		return nil
	}
	if runtime.enrollment == nil {
		return errors.New("terminal teardown cannot confirm enrollment grants without the enrollment store")
	}
	snapshot := runtime.control.Current()
	if !snapshot.CanMutate() || snapshot.Epoch == 0 {
		return authority.ErrNotLeader
	}
	return runtime.enrollment.verifyTerminalGrants(ctx, intent)
}

func (runtime *managedTerminalRuntime) withdrawActiveDesired(ctx context.Context, intent authority.TerminalIntent) error {
	desired, err := runtime.hosts.ListDesired(ctx, "terrabase")
	if err != nil {
		return err
	}
	statuses, err := runtime.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	byNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		if _, exists := byNode[status.Registration.Node]; exists {
			return errors.New("duplicate host registration during terminal withdrawal")
		}
		byNode[status.Registration.Node] = status
	}
	var failures []error
	for _, target := range intent.Targets {
		if target.InstanceID == "" {
			continue
		}
		member, err := runtime.placements.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, target.SeatID)
		if err != nil || member.Revision == 0 || member.State.Validate() != nil ||
			member.State.InstanceID != target.InstanceID || member.State.CreateKey != target.HostCreateKey ||
			member.State.VolumeID != target.DataVolumeID || member.State.MemberID != target.MemberID {
			failures = append(failures, fmt.Errorf("seat %s has no exact durable withdrawal pin", target.SeatID))
			continue
		}
		var current *host.Desired
		for index := range desired {
			if desired[index].Node == member.State.HostNode && desired[index].Role == "terrabase" {
				if current != nil {
					failures = append(failures, fmt.Errorf("seat %s has duplicate desired targets", target.SeatID))
					current = nil
					break
				}
				current = &desired[index]
			}
		}
		if current == nil || current.Withdrawn {
			continue
		}
		registration := byNode[current.Node].Registration
		if registration.ManagedPlacement == nil || registration.ManagedMember == nil ||
			registration.ManagedPlacement.DatabaseID != intent.DatabaseID ||
			registration.ManagedPlacement.PartitionID != intent.PartitionID ||
			registration.ManagedPlacement.SeatID != target.SeatID ||
			registration.ManagedMember.Scope.MemberID != target.MemberID ||
			current.ManagedMember == nil || current.ManagedMember.Member.Scope.MemberID != target.MemberID ||
			current.ManagedMember.OCI.InstanceID != target.InstanceID ||
			current.ManagedMember.OCI.CreateKey != target.HostCreateKey ||
			current.ManagedMember.VolumeID != target.DataVolumeID ||
			current.ManagedMember.AttachmentID != member.State.AttachmentID || current.Generation == math.MaxUint64 {
			failures = append(failures, fmt.Errorf("seat %s active desired differs from terminal pins", target.SeatID))
			continue
		}
		withdrawn := *current
		launch := *current.ManagedMember
		launch.ProcessMemoryBytes = 0
		launch.MemoryHeadroomBytes = 0
		launch.CgroupMemoryMaxBytes = 0
		launch.SystemReserveBytes = 0
		launch.Runtime = nil
		withdrawn.ManagedMember = &launch
		withdrawn.Generation++
		withdrawn.AuthorityEpoch = runtime.control.Current().Epoch
		withdrawn.Digest = ""
		withdrawn.Args = nil
		withdrawn.Env = nil
		withdrawn.Withdrawn = true
		if _, err := runtime.hosts.ApplyDesired(ctx, withdrawn); err != nil {
			failures = append(failures, fmt.Errorf("withdraw seat %s: %w", target.SeatID, err))
		}
	}
	return errors.Join(failures...)
}
