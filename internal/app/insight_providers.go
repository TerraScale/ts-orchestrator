package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// The adapters below expose state the parallel slices already keep (the
// workload autoscaler, placement's retained volumes) through the optional
// insights providers, so the insight rules and the dashboard read them
// without those slices importing the insights package. Each is read-only.

// workloadAutoscalers lists every autoscaled stateless service with its
// current goal and configured maximum. The insight engine tracks how long a
// target has been at its maximum itself, so AtMaxSince stays zero.
type workloadAutoscalers struct{ reconciler *workload.Reconciler }

func (source workloadAutoscalers) Autoscalers(context.Context) ([]insights.Autoscaler, error) {
	if source.reconciler == nil {
		return nil, nil
	}
	last := source.reconciler.Last()
	roles := make([]string, 0, len(last))
	for role := range last {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	out := make([]insights.Autoscaler, 0, len(roles))
	for _, role := range roles {
		spec, owned := source.reconciler.Owns(role)
		if !owned || spec.Scaling == nil {
			continue
		}
		result := last[role]
		current := result.Target
		if current == 0 {
			current = result.Replicas
		}
		out = append(out, insights.Autoscaler{Name: role, Current: current, Max: spec.Replicas.Max})
	}
	return out, nil
}

// placementVolumes reports every placed member's retained volume with its
// attachment state, derived from the member stage, and when it entered it.
type placementVolumes struct{ store placement.Store }

func (source placementVolumes) Volumes(ctx context.Context) ([]insights.Volume, error) {
	if source.store == nil {
		return nil, nil
	}
	members, _, err := placedVolumeMembers(ctx, source.store, false)
	if err != nil {
		return nil, err
	}
	out := make([]insights.Volume, 0, len(members))
	for _, member := range members {
		out = append(out, insights.Volume{ID: member.VolumeID, Host: member.HostNode,
			State: volumeAttachmentState(member.Stage), StateSince: member.UpdatedAt})
	}
	return out, nil
}

// volumeAttachmentState maps a member stage onto the attachment vocabulary
// the volume insight rule keys on ("attaching").
func volumeAttachmentState(stage placement.MemberStage) string {
	switch stage {
	case placement.StagePreparedAttach, placement.StageAwaitingAttach:
		return "ATTACHING"
	case placement.StagePreparedVolume:
		return "AVAILABLE"
	}
	return "ATTACHED (" + strings.ToLower(string(stage)) + ")"
}

// placedVolumeMembers lists the member state of every placed member that
// holds a retained volume, once per volume. The volume insight provider and
// the volume backup policy share it. A partition whose members cannot be read
// aborts the listing, unless skipUnreadable is set: then the partition is
// skipped and its error is returned in skipped instead.
func placedVolumeMembers(ctx context.Context, store placement.Store, skipUnreadable bool) (out []placement.MemberState, skipped []error, err error) {
	intents, err := store.ListIntents(ctx)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool)
	for _, intent := range intents {
		members, err := store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			if !skipUnreadable {
				return nil, nil, err
			}
			skipped = append(skipped, fmt.Errorf("partition %s/%s: %w", intent.DatabaseID, intent.PartitionID, err))
			continue
		}
		for _, member := range members {
			if id := member.State.VolumeID; id != "" && member.State.Stage != placement.StageRemoved && !seen[id] {
				seen[id] = true
				out = append(out, member.State)
			}
		}
	}
	return out, skipped, nil
}

var (
	_ insights.AutoscalerProvider = workloadAutoscalers{}
	_ insights.VolumeProvider     = placementVolumes{}
)
