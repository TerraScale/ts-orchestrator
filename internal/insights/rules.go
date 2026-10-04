package insights

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// Thresholds tune the default rules. Zero fields take the defaults below.
type Thresholds struct {
	// MemberNotReady is how long a member may fail readiness.
	MemberNotReady time.Duration
	// NoLeader is how long a cell may lack an authority leader.
	NoLeader time.Duration
	// RolloutStalled is how long a managed rollout may make no progress.
	RolloutStalled time.Duration
	// MixedVersions is how long members may run different builds.
	MixedVersions time.Duration
	// DiskTimeToFullWarning and DiskTimeToFullCritical bound projected
	// time to full; DiskUsedWarning and DiskUsedCritical bound used ratio.
	DiskTimeToFullWarning  time.Duration
	DiskTimeToFullCritical time.Duration
	DiskUsedWarning        float64
	DiskUsedCritical       float64
	// MemoryUsedWarning bounds a member's used memory ratio.
	MemoryUsedWarning float64
	// VolumeAttachStuck is how long a seat may wait on its volume.
	VolumeAttachStuck time.Duration
	// OCIErrorsPerMinute and OCIThrottledPerMinute bound OCI API error and
	// 429 rates over OCIWindow.
	OCIErrorsPerMinute    float64
	OCIThrottledPerMinute float64
	OCIWindow             time.Duration
	// ConsumerPending bounds a JetStream consumer's backlog held for
	// ConsumerPendingFor.
	ConsumerPending    float64
	ConsumerPendingFor time.Duration
	// CertificateWarning and CertificateCritical bound time to expiry.
	CertificateWarning  time.Duration
	CertificateCritical time.Duration
	// PeerOffline is how long a NetBird peer may be disconnected.
	PeerOffline time.Duration
	// AutoscalerAtMax is how long a target may sit at its maximum.
	AutoscalerAtMax time.Duration
	// BudgetWarning is the used fraction of a budget that raises a warning.
	BudgetWarning float64
	// RegionUnreachable is how long a linked region may stop answering.
	RegionUnreachable time.Duration
	// RepeatedHolds is how many holds of one subject within an hour raise
	// an insight from the decision journal.
	RepeatedHolds int
	// OCIDrift is how long an OCI resource may stay out of sync with its
	// desired spec before it raises an insight.
	OCIDrift time.Duration
}

func (thresholds Thresholds) withDefaults() Thresholds {
	defaults := Thresholds{
		MemberNotReady: time.Minute, NoLeader: 30 * time.Second, RolloutStalled: 30 * time.Minute,
		MixedVersions: 30 * time.Minute, DiskTimeToFullWarning: 72 * time.Hour,
		DiskTimeToFullCritical: 24 * time.Hour, DiskUsedWarning: 0.85, DiskUsedCritical: 0.95,
		MemoryUsedWarning: 0.9, VolumeAttachStuck: 15 * time.Minute, OCIErrorsPerMinute: 1,
		OCIThrottledPerMinute: 0.2, OCIWindow: 10 * time.Minute, ConsumerPending: 1000,
		ConsumerPendingFor: 10 * time.Minute, CertificateWarning: 14 * 24 * time.Hour,
		CertificateCritical: 3 * 24 * time.Hour, PeerOffline: 5 * time.Minute,
		AutoscalerAtMax: 15 * time.Minute, BudgetWarning: 0.9, RegionUnreachable: time.Minute,
		RepeatedHolds: 3, OCIDrift: 10 * time.Minute,
	}
	merged := thresholds
	if merged.MemberNotReady <= 0 {
		merged.MemberNotReady = defaults.MemberNotReady
	}
	if merged.NoLeader <= 0 {
		merged.NoLeader = defaults.NoLeader
	}
	if merged.RolloutStalled <= 0 {
		merged.RolloutStalled = defaults.RolloutStalled
	}
	if merged.MixedVersions <= 0 {
		merged.MixedVersions = defaults.MixedVersions
	}
	if merged.DiskTimeToFullWarning <= 0 {
		merged.DiskTimeToFullWarning = defaults.DiskTimeToFullWarning
	}
	if merged.DiskTimeToFullCritical <= 0 {
		merged.DiskTimeToFullCritical = defaults.DiskTimeToFullCritical
	}
	if merged.DiskUsedWarning <= 0 {
		merged.DiskUsedWarning = defaults.DiskUsedWarning
	}
	if merged.DiskUsedCritical <= 0 {
		merged.DiskUsedCritical = defaults.DiskUsedCritical
	}
	if merged.MemoryUsedWarning <= 0 {
		merged.MemoryUsedWarning = defaults.MemoryUsedWarning
	}
	if merged.VolumeAttachStuck <= 0 {
		merged.VolumeAttachStuck = defaults.VolumeAttachStuck
	}
	if merged.OCIErrorsPerMinute <= 0 {
		merged.OCIErrorsPerMinute = defaults.OCIErrorsPerMinute
	}
	if merged.OCIThrottledPerMinute <= 0 {
		merged.OCIThrottledPerMinute = defaults.OCIThrottledPerMinute
	}
	if merged.OCIWindow <= 0 {
		merged.OCIWindow = defaults.OCIWindow
	}
	if merged.ConsumerPending <= 0 {
		merged.ConsumerPending = defaults.ConsumerPending
	}
	if merged.ConsumerPendingFor <= 0 {
		merged.ConsumerPendingFor = defaults.ConsumerPendingFor
	}
	if merged.CertificateWarning <= 0 {
		merged.CertificateWarning = defaults.CertificateWarning
	}
	if merged.CertificateCritical <= 0 {
		merged.CertificateCritical = defaults.CertificateCritical
	}
	if merged.PeerOffline <= 0 {
		merged.PeerOffline = defaults.PeerOffline
	}
	if merged.AutoscalerAtMax <= 0 {
		merged.AutoscalerAtMax = defaults.AutoscalerAtMax
	}
	if merged.BudgetWarning <= 0 {
		merged.BudgetWarning = defaults.BudgetWarning
	}
	if merged.RegionUnreachable <= 0 {
		merged.RegionUnreachable = defaults.RegionUnreachable
	}
	if merged.RepeatedHolds <= 0 {
		merged.RepeatedHolds = defaults.RepeatedHolds
	}
	if merged.OCIDrift <= 0 {
		merged.OCIDrift = defaults.OCIDrift
	}
	return merged
}

// DefaultRules returns every built-in rule, in a stable order.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "quorum_at_risk", Description: "Fewer controllers answer than the cell expects.", Evaluate: quorumAtRisk},
		{Name: "no_leader", Description: "No member holds the regional authority lease.", Evaluate: noLeader},
		{Name: "member_not_ready", Description: "A member fails its readiness checks.", Evaluate: memberNotReady},
		{Name: "jetstream_replicas", Description: "A JetStream stream has offline replicas.", Evaluate: streamReplicas},
		{Name: "consumer_backlog", Description: "A JetStream consumer's backlog stays high.", Evaluate: consumerBacklog},
		{Name: "mixed_versions", Description: "Members run different builds for too long.", Evaluate: mixedVersions},
		{Name: "rollout_stalled", Description: "A managed rollout made no progress.", Evaluate: rolloutStalled},
		{Name: "rollout_deadline", Description: "A rollout phase ran past its deadline.", Evaluate: rolloutDeadline},
		{Name: "member_held", Description: "A TerraBase seat or managed update is held.", Evaluate: memberHeld},
		{Name: "volume_stuck", Description: "A volume is stuck attaching.", Evaluate: volumeStuck},
		{Name: "disk_time_to_full", Description: "A filesystem fills soon or is nearly full.", Evaluate: diskTimeToFull},
		{Name: "memory_pressure", Description: "A member is short of memory.", Evaluate: memoryPressure},
		{Name: "oci_errors", Description: "OCI API errors or 429s spike.", Evaluate: ociErrors},
		{Name: "region_unreachable", Description: "A linked region stopped answering.", Evaluate: regionUnreachable},
		{Name: "certificate_expiring", Description: "A certificate or delegation expires soon.", Evaluate: certificateExpiring},
		{Name: "netbird_peer", Description: "A NetBird peer is offline or relayed.", Evaluate: netbirdPeers},
		{Name: "autoscaler_at_max", Description: "An autoscaler is pinned at its maximum.", Evaluate: autoscalerAtMax},
		{Name: "budget_ceiling", Description: "A budget is near its ceiling.", Evaluate: budgetCeiling},
		{Name: "oci_drift", Description: "An OCI resource drifts from its desired spec, is foreign, or fails to reconcile.",
			Evaluate: ociDrift},
	}
}

func threshold(value float64) *float64 { return &value }

func members(inputs *Inputs) []observability.MemberSnapshot {
	if inputs.Cluster == nil {
		return nil
	}
	return inputs.Cluster.Members
}

func memberHref(member string) string { return "/members#member-" + member }

func quorumAtRisk(inputs *Inputs) []Insight {
	cluster := inputs.Cluster
	if cluster == nil || len(cluster.Expected) == 0 {
		return nil
	}
	expected := len(cluster.Expected)
	answering := 0
	for _, member := range cluster.Members {
		if member.Role == "controller" || member.Role == "" {
			answering++
		}
	}
	missing := expected - answering
	if missing <= 0 {
		return nil
	}
	quorum := expected/2 + 1
	severity := SeverityWarning
	why := fmt.Sprintf("%d of %d controllers answer. The cell keeps quorum with %d, so one more loss would stop "+
		"authority and JetStream writes.", answering, expected, quorum)
	if answering < quorum {
		severity = SeverityCritical
		why = fmt.Sprintf("Only %d of %d controllers answer, below the quorum of %d: authority and JetStream "+
			"writes are stopped.", answering, expected, quorum)
	} else if answering-1 >= quorum {
		why = fmt.Sprintf("%d of %d controllers answer; quorum (%d) still holds with room to spare.", answering,
			expected, quorum)
	}
	return []Insight{{Severity: severity, Score: float64(missing), Title: "Controller quorum at risk",
		Why: why, Entity: Entity{Kind: "region", ID: inputs.Region, Href: "/members"},
		Evidence: []Evidence{{Label: "Controllers answering", Metric: observability.HistMembersAnswering,
			Value: float64(answering), Comparison: ">=", Threshold: threshold(float64(quorum))},
			{Label: "Missing", Text: strings.Join(cluster.Missing, ", "), Value: float64(missing)}},
		Actions: []Action{{Label: "Check the missing controllers' service logs",
			Command: "journalctl -u terrascale-orchestrator --since -15min"},
			{Label: "Open members", Href: "/members"}}}}
}

func noLeader(inputs *Inputs) []Insight {
	reporting := false
	for _, member := range members(inputs) {
		if member.Authority == nil {
			continue
		}
		reporting = true
		if member.Authority.Leader || member.Authority.OwnerID != "" && member.Authority.Ready {
			return nil
		}
	}
	if !reporting {
		return nil
	}
	held := inputs.Since("no_leader")
	if held < inputs.Thresholds.NoLeader {
		return nil
	}
	return []Insight{{Severity: SeverityCritical, Score: held.Seconds(), Title: "No regional authority leader",
		Why: fmt.Sprintf("No controller has held the authority lease for %s, so the region cannot make "+
			"control-plane changes.", roundDuration(held)),
		Entity:   Entity{Kind: "region", ID: inputs.Region, Href: "/members"},
		Evidence: []Evidence{{Label: "Leaderless for", Value: held.Seconds(), Unit: "s", Comparison: "<", Threshold: threshold(inputs.Thresholds.NoLeader.Seconds())}},
		Actions:  []Action{{Label: "Check controller and JetStream health", Href: "/nats"}}}}
}

func memberNotReady(inputs *Inputs) []Insight {
	var out []Insight
	for _, member := range members(inputs) {
		if member.Ready {
			continue
		}
		held := inputs.Since("not_ready:" + member.Member)
		if held < inputs.Thresholds.MemberNotReady {
			continue
		}
		var failing []string
		evidence := []Evidence{}
		for _, check := range member.Checks {
			if !check.OK {
				failing = append(failing, check.Name)
				evidence = append(evidence, Evidence{Label: "Check " + check.Name, Text: check.Detail})
			}
		}
		why := fmt.Sprintf("%s has not been ready for %s.", member.Member, roundDuration(held))
		if len(failing) > 0 {
			why = fmt.Sprintf("%s has failed %s for %s.", member.Member, strings.Join(failing, ", "), roundDuration(held))
		}
		out = append(out, Insight{Severity: SeverityWarning, Score: held.Seconds(), Title: "Member not ready",
			Why: why, Evidence: evidence, Entity: Entity{Kind: "member", ID: member.Member, Href: memberHref(member.Member)},
			Actions: []Action{{Label: "Read the member's readiness", Command: "curl -s http://127.0.0.1:9464/readyz"}}})
	}
	return out
}

func streamReplicas(inputs *Inputs) []Insight {
	seen := map[string]observability.StreamView{}
	for _, member := range members(inputs) {
		if member.NATS == nil {
			continue
		}
		for _, stream := range member.NATS.Streams {
			if stream.OfflinePeers > seen[stream.Name].OfflinePeers {
				seen[stream.Name] = stream
			}
		}
	}
	var out []Insight
	for _, name := range slices.Sorted(maps.Keys(seen)) {
		stream := seen[name]
		severity := SeverityWarning
		if stream.Replicas > 0 && stream.OfflinePeers*2 >= stream.Replicas {
			severity = SeverityCritical
		}
		out = append(out, Insight{Severity: severity, Score: float64(stream.OfflinePeers),
			Title: "Stream " + name + " has offline replicas",
			Why: fmt.Sprintf("%d of %d replicas of %s are offline; its data has less redundancy until they return.",
				stream.OfflinePeers, stream.Replicas, name),
			Entity: Entity{Kind: "stream", ID: name, Href: "/nats"},
			Evidence: []Evidence{{Label: "Offline replicas", Value: float64(stream.OfflinePeers), Comparison: "==",
				Threshold: threshold(0)}},
			Actions: []Action{{Label: "Open NATS", Href: "/nats"}}})
	}
	return out
}

func consumerBacklog(inputs *Inputs) []Insight {
	type key struct{ stream, name string }
	worst := map[key]uint64{}
	for _, member := range members(inputs) {
		if member.NATS == nil {
			continue
		}
		for _, consumer := range member.NATS.Consumers {
			k := key{consumer.Stream, consumer.Name}
			worst[k] = max(worst[k], consumer.NumPending)
		}
	}
	var out []Insight
	keys := slices.SortedFunc(maps.Keys(worst), func(left, right key) int {
		return strings.Compare(left.stream+"/"+left.name, right.stream+"/"+right.name)
	})
	for _, k := range keys {
		pending := float64(worst[k])
		if pending < inputs.Thresholds.ConsumerPending {
			continue
		}
		held := inputs.Since("backlog:" + k.stream + "/" + k.name)
		if held < inputs.Thresholds.ConsumerPendingFor {
			continue
		}
		out = append(out, Insight{Severity: SeverityWarning, Score: pending, Title: "Consumer backlog on " + k.name,
			Why: fmt.Sprintf("%s on %s has had %s pending messages for %s; its worker is not keeping up.",
				k.name, k.stream, observability.FormatFloat(pending), roundDuration(held)),
			Entity: Entity{Kind: "consumer", ID: k.stream + "/" + k.name, Href: "/nats"},
			Evidence: []Evidence{{Label: "Pending", Metric: observability.HistConsumerPending,
				Labels: map[string]string{"stream": k.stream, "consumer": k.name}, Value: pending, Comparison: "<",
				Threshold: threshold(inputs.Thresholds.ConsumerPending)}},
			Actions: []Action{{Label: "Open NATS", Href: "/nats"}}})
	}
	return out
}

func mixedVersions(inputs *Inputs) []Insight {
	versions := map[string][]string{}
	for _, member := range members(inputs) {
		if member.BuildVersion != "" {
			versions[member.BuildVersion] = append(versions[member.BuildVersion], member.Member)
		}
	}
	if len(versions) < 2 {
		return nil
	}
	held := inputs.Since("mixed_versions")
	if held < inputs.Thresholds.MixedVersions {
		return nil
	}
	var parts []string
	for _, version := range slices.Sorted(maps.Keys(versions)) {
		parts = append(parts, fmt.Sprintf("%s on %s", version, strings.Join(versions[version], ", ")))
	}
	return []Insight{{Severity: SeverityWarning, Score: held.Seconds(), Title: "Mixed orchestrator versions",
		Why: fmt.Sprintf("Members have run %d different builds for %s. A rollout may be stuck or a member "+
			"missed an update.", len(versions), roundDuration(held)),
		Entity: Entity{Kind: "region", ID: inputs.Region, Href: "/members"},
		Evidence: []Evidence{{Label: "Builds", Value: float64(len(versions)), Text: strings.Join(parts, "; "),
			Comparison: "<=", Threshold: threshold(1)},
			{Label: "Mixed for", Value: held.Seconds(), Unit: "s", Comparison: "<", Threshold: threshold(inputs.Thresholds.MixedVersions.Seconds())}},
		Actions: []Action{{Label: "Open rollouts", Href: "/rollouts"}}}}
}

func placement(inputs *Inputs) *observability.PlacementView {
	var best *observability.PlacementView
	for _, member := range members(inputs) {
		if member.Placement != nil && (best == nil || len(member.Placement.Databases) > len(best.Databases)) {
			best = member.Placement
		}
	}
	return best
}

func rolloutStalled(inputs *Inputs) []Insight {
	view := placement(inputs)
	if view == nil {
		return nil
	}
	var out []Insight
	for _, database := range view.Databases {
		rollout := database.Rollout
		if rollout == nil || rollout.Seats == 0 || rollout.Completed >= rollout.Seats {
			continue
		}
		held := inputs.Since(fmt.Sprintf("rollout:%s:%d", rollout.OperationID, rollout.Completed))
		if held < inputs.Thresholds.RolloutStalled {
			continue
		}
		out = append(out, Insight{Severity: SeverityWarning, Score: held.Seconds(),
			Title: "Rollout " + shortID(rollout.OperationID) + " is not progressing",
			Why: fmt.Sprintf("The managed update of %s/%s has stayed at %d of %d seats for %s.",
				database.DatabaseID, database.PartitionID, rollout.Completed, rollout.Seats, roundDuration(held)),
			Entity: Entity{Kind: "rollout", ID: rollout.OperationID, Href: "/rollouts"},
			Evidence: []Evidence{{Label: "Progress", Metric: observability.HistRolloutProgress,
				Labels: map[string]string{"operation": rollout.OperationID}, Value: rollout.Progress(), Unit: "ratio"},
				{Label: "Unchanged for", Value: held.Seconds(), Unit: "s", Comparison: "<",
					Threshold: threshold(inputs.Thresholds.RolloutStalled.Seconds())}},
			Actions: []Action{{Label: "Inspect the update", Command: "ts-orch operator terrabase-status --state DIR"},
				{Label: "Open rollouts", Href: "/rollouts"}}})
	}
	return out
}

func rolloutDeadline(inputs *Inputs) []Insight {
	var out []Insight
	for _, rollout := range inputs.Rollouts {
		if rollout.Done || rollout.PhaseDeadline.IsZero() || inputs.Now.Before(rollout.PhaseDeadline) {
			continue
		}
		over := inputs.Now.Sub(rollout.PhaseDeadline)
		severity := SeverityWarning
		if over > time.Hour {
			severity = SeverityCritical
		}
		out = append(out, Insight{Severity: severity, Score: over.Seconds(),
			Title: fmt.Sprintf("Rollout %s is past its %s deadline", shortID(rollout.ID), rollout.Phase),
			Why: fmt.Sprintf("Release %s has been in %s since %s, %s past its deadline.", shortID(rollout.Release),
				rollout.Phase, rollout.PhaseStarted.Format(time.RFC3339), roundDuration(over)),
			Entity: Entity{Kind: "rollout", ID: rollout.ID, Href: "/rollouts"},
			Evidence: []Evidence{{Label: "Past deadline by", Value: over.Seconds(), Unit: "s", Comparison: "<=",
				Threshold: threshold(0)}},
			Actions: []Action{{Label: "Open rollouts", Href: "/rollouts"}}})
	}
	return out
}

func memberHeld(inputs *Inputs) []Insight {
	var out []Insight
	if view := placement(inputs); view != nil {
		for _, database := range view.Databases {
			for _, member := range database.Members {
				if member.UpdatePhase != "held" {
					continue
				}
				// Seat IDs repeat across databases and partitions.
				seat := database.DatabaseID + "/" + database.PartitionID + "/" + member.SeatID
				out = append(out, Insight{inputs: placementInputs, Severity: SeverityWarning, Score: 2,
					Key:   "member_held:seat:" + seat,
					Title: "Managed update held on seat " + member.SeatID,
					Why: fmt.Sprintf("The managed runtime update of %s/%s is durably held on seat %s; it will not "+
						"advance or roll forward without an operator.", database.DatabaseID, database.PartitionID, member.SeatID),
					Entity:   Entity{Kind: "seat", ID: seat, Href: "/terrabase"},
					Evidence: []Evidence{{Label: "Update phase", Text: member.UpdatePhase}},
					Actions: []Action{{Label: "Inspect the hold", Command: "ts-orch operator terrabase-status --state DIR"},
						{Label: "Open TerraBase", Href: "/terrabase"}}})
			}
		}
	}
	for _, hold := range inputs.Holds {
		subject := holdSubject(hold.Reason)
		// Holds are read in process and never fail.
		out = append(out, Insight{inputs: []string{}, Severity: SeverityWarning, Score: 1,
			Key:      "member_held:hold:" + subject,
			Title:    "Placement held: " + subject,
			Why:      "The placement reconciler is holding: " + hold.Reason + ".",
			Entity:   Entity{Kind: "member", ID: subject, Href: "/terrabase"},
			Evidence: []Evidence{{Label: "Last asserted", Text: hold.LastSeen.Format(time.RFC3339)}},
			Actions:  []Action{{Label: "Inspect placement", Command: "ts-orch operator terrabase-status --state DIR"}}})
	}
	// Repeated holds of one subject in the journal point at a flapping seat.
	counts := map[string]int{}
	ids := map[string]string{}
	cutoff := inputs.Now.Add(-time.Hour)
	for _, decision := range inputs.Decisions {
		if decision.Kind == decisionlog.KindHeld && decision.Time.After(cutoff) && decision.Subject.ID != "" {
			counts[decision.Subject.String()]++
			ids[decision.Subject.String()] = decision.Subject.ID
		}
	}
	for _, subject := range slices.Sorted(maps.Keys(counts)) {
		if counts[subject] < inputs.Thresholds.RepeatedHolds {
			continue
		}
		// The decision search (q) matches subject IDs, names and
		// summaries, not the kind-qualified form.
		out = append(out, Insight{inputs: []string{"decisions"}, Severity: SeverityInfo,
			Score: float64(counts[subject]),
			Key:   "member_held:repeated:" + subject, Title: "Repeated holds on " + subject,
			Why:    fmt.Sprintf("%s was held %d times in the last hour.", subject, counts[subject]),
			Entity: Entity{Kind: "subject", ID: subject, Href: "/decisions?q=" + url.QueryEscape(ids[subject])},
			Evidence: []Evidence{{Label: "Holds in 1h", Value: float64(counts[subject]), Comparison: "<",
				Threshold: threshold(float64(inputs.Thresholds.RepeatedHolds))}}})
	}
	return out
}

// holdSubject extracts the member or database a placement hold names.
func holdSubject(reason string) string {
	fields := strings.Fields(reason)
	for index := 0; index+1 < len(fields); index++ {
		switch fields[index] {
		case "member", "database":
			return fields[index+1]
		}
	}
	if len(reason) > 48 {
		return reason[:48]
	}
	return reason
}

// placementInputs are the inputs of an insight read from the placement
// section of the cluster snapshot.
var placementInputs = []string{"cluster", "snapshot", "section placement"}

func volumeStuck(inputs *Inputs) []Insight {
	var out []Insight
	limit := inputs.Thresholds.VolumeAttachStuck
	// Hosts whose seat already reports the stuck attachment: the volume
	// provider describes the same placement state, so it must not open a
	// second problem for it.
	reported := map[string]bool{}
	if view := placement(inputs); view != nil {
		for _, database := range view.Databases {
			for _, member := range database.Members {
				if member.Stage != "prepared-attach" && member.Stage != "awaiting-attach" || member.UpdatedAt.IsZero() {
					continue
				}
				stuck := inputs.Now.Sub(member.UpdatedAt)
				if stuck < limit {
					continue
				}
				seat := database.DatabaseID + "/" + database.PartitionID + "/" + member.SeatID
				if member.HostNode != "" {
					reported[member.HostNode] = true
				}
				out = append(out, Insight{inputs: placementInputs, Severity: SeverityWarning, Score: stuck.Seconds(),
					Key:   "volume_stuck:seat:" + seat,
					Title: "Volume stuck attaching for seat " + member.SeatID,
					Why: fmt.Sprintf("Seat %s has waited in %s for %s; its retained volume is not attached.",
						member.SeatID, member.Stage, roundDuration(stuck)),
					Entity: Entity{Kind: "seat", ID: seat, Href: "/storage"},
					Evidence: []Evidence{{Label: "Waiting", Value: stuck.Seconds(), Unit: "s", Comparison: "<",
						Threshold: threshold(limit.Seconds())}},
					Actions: []Action{{Label: "Inspect the attachment",
						Command: "oci compute volume-attachment list --instance-id <host OCID>"},
						{Label: "Open storage", Href: "/storage"}}})
			}
		}
	}
	for _, volume := range inputs.Volumes {
		if !strings.Contains(strings.ToLower(volume.State), "attaching") || volume.StateSince.IsZero() ||
			volume.Host != "" && reported[volume.Host] {
			continue
		}
		stuck := inputs.Now.Sub(volume.StateSince)
		if stuck < limit {
			continue
		}
		out = append(out, Insight{inputs: []string{"volumes"}, Severity: SeverityWarning, Score: stuck.Seconds(),
			Title:  "Volume " + shortID(volume.ID) + " stuck attaching",
			Why:    fmt.Sprintf("Volume %s has been %s for %s.", volume.ID, volume.State, roundDuration(stuck)),
			Entity: Entity{Kind: "volume", ID: volume.ID, Href: "/storage"},
			Evidence: []Evidence{{Label: "Attaching for", Value: stuck.Seconds(), Unit: "s", Comparison: "<",
				Threshold: threshold(limit.Seconds())}},
			Actions: []Action{{Label: "Open storage", Href: "/storage"}}})
	}
	return out
}

func diskTimeToFull(inputs *Inputs) []Insight {
	var out []Insight
	thresholds := inputs.Thresholds
	for _, member := range members(inputs) {
		if member.System == nil {
			continue
		}
		for _, filesystem := range member.System.Filesystems {
			if filesystem.SizeBytes == 0 {
				continue
			}
			size := float64(filesystem.SizeBytes)
			used := size - float64(min(filesystem.AvailBytes, filesystem.SizeBytes))
			ratio := used / size
			entity := Entity{Kind: "host", ID: member.Member + ":" + filesystem.Role, Href: memberHref(member.Member)}
			labels := map[string]string{"member": member.Member, "role": filesystem.Role}
			usedEvidence := Evidence{Label: "Used", Metric: observability.HistFSRatio, Labels: labels, Value: ratio,
				Unit: "ratio", Comparison: "<", Threshold: threshold(thresholds.DiskUsedWarning)}
			action := Action{Label: "Find what is growing", Command: "du -xh --max-depth=2 " + filesystem.Path + " | sort -h | tail"}
			// Both criteria are evaluated and the worse one wins, under one
			// key per filesystem: crossing the usage warning must not
			// downgrade a disk that fills within hours, nor resolve and
			// reopen the same problem under a new key.
			var candidates []Insight
			if ratio >= thresholds.DiskUsedWarning {
				severity := SeverityWarning
				evidence := usedEvidence
				if ratio >= thresholds.DiskUsedCritical {
					severity = SeverityCritical
					evidence.Threshold = threshold(thresholds.DiskUsedCritical)
				}
				candidates = append(candidates, Insight{Severity: severity, Score: ratio * 100,
					Title: fmt.Sprintf("%s %s filesystem is %.0f%% full", member.Member, filesystem.Role, ratio*100),
					Why: fmt.Sprintf("The %s filesystem (%s) on %s has %s free.", filesystem.Role, filesystem.Path,
						member.Member, bytesText(float64(filesystem.AvailBytes))),
					Evidence: []Evidence{evidence}})
			}
			if ttf, rate, ok := timeToFull(inputs, labels, size, used); ok && ttf < thresholds.DiskTimeToFullWarning {
				severity := SeverityWarning
				limit := thresholds.DiskTimeToFullWarning
				if ttf < thresholds.DiskTimeToFullCritical {
					severity, limit = SeverityCritical, thresholds.DiskTimeToFullCritical
				}
				candidates = append(candidates, Insight{Severity: severity, Score: 1e6 / max(ttf.Hours(), 0.01),
					Title: fmt.Sprintf("%s %s filesystem full in about %s", member.Member, filesystem.Role, roundDuration(ttf)),
					Why: fmt.Sprintf("The %s filesystem on %s grows %s per hour and has %s free, so it fills in about %s.",
						filesystem.Role, member.Member, bytesText(rate*3600), bytesText(size-used), roundDuration(ttf)),
					Evidence: []Evidence{{Label: "Time to full", Value: ttf.Hours(), Unit: "h", Comparison: ">=",
						Threshold: threshold(limit.Hours())},
						{Label: "Growth", Metric: observability.HistFSUsed, Labels: labels, Value: rate * 3600, Unit: "bytes/h"},
						usedEvidence}})
			}
			if len(candidates) == 0 {
				continue
			}
			worst := candidates[0]
			for _, candidate := range candidates[1:] {
				if candidate.Severity.Rank() > worst.Severity.Rank() {
					worst = candidate
				}
			}
			worst.Key, worst.Entity, worst.Actions = "disk:"+entity.ID, entity, []Action{action}
			out = append(out, worst)
		}
	}
	return out
}

// timeToFull fits a least-squares line through the filesystem's used bytes
// over the last six hours of history. It needs at least 30 minutes of data
// and a growing trend.
func timeToFull(inputs *Inputs, labels map[string]string, size, used float64) (time.Duration, float64, bool) {
	if inputs.History == nil {
		return 0, 0, false
	}
	result := inputs.History.Range(observability.HistoryQuery{Metric: observability.HistFSUsed, Labels: labels,
		Start: inputs.Now.Add(-6 * time.Hour), End: inputs.Now, Tier: observability.Tier1m, MaxSeries: 1})
	if len(result.Series) == 0 {
		return 0, 0, false
	}
	points := result.Series[0].Points
	if len(points) < 5 || points[len(points)-1].Time.Sub(points[0].Time) < 30*time.Minute {
		return 0, 0, false
	}
	origin := points[0].Time
	var sumX, sumY, sumXY, sumXX float64
	for _, point := range points {
		x := point.Time.Sub(origin).Seconds()
		sumX += x
		sumY += point.Value
		sumXY += x * point.Value
		sumXX += x * x
	}
	count := float64(len(points))
	denominator := count*sumXX - sumX*sumX
	if denominator == 0 {
		return 0, 0, false
	}
	slope := (count*sumXY - sumX*sumY) / denominator // bytes per second
	if slope <= 0 {
		return 0, 0, false
	}
	seconds := (size - used) / slope
	if seconds > (365 * 24 * time.Hour).Seconds() {
		return 0, 0, false
	}
	return time.Duration(seconds * float64(time.Second)), slope, true
}

func memoryPressure(inputs *Inputs) []Insight {
	var out []Insight
	for _, member := range members(inputs) {
		system := member.System
		if system == nil || system.MemTotalBytes == 0 {
			continue
		}
		ratio := 1 - float64(min(system.MemAvailBytes, system.MemTotalBytes))/float64(system.MemTotalBytes)
		if ratio < inputs.Thresholds.MemoryUsedWarning {
			continue
		}
		out = append(out, Insight{Severity: SeverityWarning, Score: ratio * 100,
			Title: fmt.Sprintf("%s memory is %.0f%% used", member.Member, ratio*100),
			Why: fmt.Sprintf("%s has %s of memory available; the kernel may start reclaiming or killing processes.",
				member.Member, bytesText(float64(system.MemAvailBytes))),
			Entity: Entity{Kind: "member", ID: member.Member, Href: memberHref(member.Member)},
			Evidence: []Evidence{{Label: "Memory used", Metric: observability.HistMemoryRatio,
				Labels: map[string]string{"member": member.Member}, Value: ratio, Unit: "ratio", Comparison: "<",
				Threshold: threshold(inputs.Thresholds.MemoryUsedWarning)}},
			Actions: []Action{{Label: "List the largest processes", Command: "ps aux --sort=-rss | head"}}})
	}
	return out
}

func ociErrors(inputs *Inputs) []Insight {
	if inputs.History == nil {
		return nil
	}
	window := inputs.Thresholds.OCIWindow
	perMinute := func(metric string) map[string]float64 {
		result := inputs.History.Range(observability.HistoryQuery{Metric: metric, Start: inputs.Now.Add(-window),
			End: inputs.Now, Tier: observability.TierRaw, Rate: true, MaxSeries: 256})
		rates := map[string]float64{}
		for _, series := range result.Series {
			if len(series.Points) == 0 {
				continue
			}
			var sum float64
			for _, point := range series.Points {
				sum += point.Value
			}
			rates[series.Labels["operation"]] = sum / float64(len(series.Points)) * 60
		}
		return rates
	}
	var out []Insight
	add := func(kind, metric string, limit float64, title, why string) {
		rates := perMinute(metric)
		total := 0.0
		var worst []string
		for _, operation := range slices.Sorted(maps.Keys(rates)) {
			total += rates[operation]
			if rates[operation] > 0 {
				worst = append(worst, fmt.Sprintf("%s %.1f/min", operation, rates[operation]))
			}
		}
		if total < limit {
			return
		}
		severity := SeverityWarning
		if total >= limit*10 {
			severity = SeverityCritical
		}
		out = append(out, Insight{Severity: severity, Score: total, Key: "oci_errors:" + kind, Title: title,
			Why:    fmt.Sprintf(why, total, roundDuration(window)),
			Entity: Entity{Kind: "operation", ID: kind, Href: "/oci"},
			Evidence: []Evidence{{Label: "Rate", Metric: metric, Value: total, Unit: "per min", Comparison: "<",
				Threshold: threshold(limit)}, {Label: "By operation", Text: strings.Join(worst, ", ")}},
			Actions: []Action{{Label: "Open OCI", Href: "/oci"}}})
	}
	add("errors", observability.HistOCIErrors, inputs.Thresholds.OCIErrorsPerMinute, "OCI API errors are elevated",
		"OCI calls failed %.1f times per minute over the last %s.")
	add("throttled", observability.HistOCIThrottled, inputs.Thresholds.OCIThrottledPerMinute,
		"OCI is throttling the orchestrator (429)",
		"OCI returned 429 Too Many Requests %.1f times per minute over the last %s; calls are backing off.")
	return out
}

func regionUnreachable(inputs *Inputs) []Insight {
	var out []Insight
	for _, reach := range inputs.Reachability {
		if reach.State != decisionlog.RegionUnreachable && reach.State != decisionlog.RegionError {
			continue
		}
		held := inputs.Since("region:" + reach.Region)
		if held < inputs.Thresholds.RegionUnreachable {
			continue
		}
		out = append(out, Insight{Severity: SeverityCritical, Score: held.Seconds(), Region: reach.Region,
			Title:  "Region " + strings.ToUpper(reach.Region) + " is unreachable",
			Why:    fmt.Sprintf("%s has not answered cross-region queries for %s.", strings.ToUpper(reach.Region), roundDuration(held)),
			Entity: Entity{Kind: "region", ID: reach.Region, Region: reach.Region, Href: "/regions/" + reach.Region},
			Evidence: []Evidence{{Label: "Unreachable for", Value: held.Seconds(), Unit: "s", Comparison: "<",
				Threshold: threshold(inputs.Thresholds.RegionUnreachable.Seconds())}},
			Actions: []Action{{Label: "Open the global view", Href: "/regions"}}})
	}
	return out
}

func certificateExpiring(inputs *Inputs) []Insight {
	var out []Insight
	for _, certificate := range inputs.Certificates {
		left := certificate.NotAfter.Sub(inputs.Now)
		if left >= inputs.Thresholds.CertificateWarning {
			continue
		}
		severity, limit := SeverityWarning, inputs.Thresholds.CertificateWarning
		if left < inputs.Thresholds.CertificateCritical {
			severity, limit = SeverityCritical, inputs.Thresholds.CertificateCritical
		}
		why := fmt.Sprintf("The %s %s expires in %s (%s).", certificate.Kind, certificate.Name, roundDuration(left),
			certificate.NotAfter.Format(time.RFC3339))
		if left <= 0 {
			why = fmt.Sprintf("The %s %s expired on %s.", certificate.Kind, certificate.Name,
				certificate.NotAfter.Format(time.RFC3339))
		}
		out = append(out, Insight{Severity: severity, Score: -left.Hours(), Title: "Expiring " + certificate.Kind + ": " + certificate.Name,
			Why: why, Entity: Entity{Kind: "certificate", ID: certificate.Name},
			Evidence: []Evidence{{Label: "Days left", Value: left.Hours() / 24, Unit: "days", Comparison: ">=",
				Threshold: threshold(limit.Hours() / 24)}},
			Actions: []Action{{Label: "Rotate it", Command: "ts-orch bootstrap --help"}}})
	}
	return out
}

func netbirdPeers(inputs *Inputs) []Insight {
	var out []Insight
	for _, peer := range inputs.Peers {
		switch {
		case !peer.Connected:
			held := inputs.Since("peer_offline:" + peer.Name)
			if held < inputs.Thresholds.PeerOffline {
				continue
			}
			out = append(out, Insight{Severity: SeverityWarning, Score: held.Seconds(), Key: "netbird_peer:offline:" + peer.Name,
				Title:  "NetBird peer " + peer.Name + " is offline",
				Why:    fmt.Sprintf("%s has been disconnected from the overlay for %s.", peer.Name, roundDuration(held)),
				Entity: Entity{Kind: "peer", ID: peer.Name},
				Evidence: []Evidence{{Label: "Offline for", Value: held.Seconds(), Unit: "s", Comparison: "<",
					Threshold: threshold(inputs.Thresholds.PeerOffline.Seconds())}},
				Actions: []Action{{Label: "Check the peer", Command: "netbird status --detail"}}})
		case peer.Relayed:
			out = append(out, Insight{Severity: SeverityInfo, Score: 1, Key: "netbird_peer:relayed:" + peer.Name,
				Title:  "NetBird peer " + peer.Name + " is relayed",
				Why:    peer.Name + " reaches its peers through a relay instead of a direct path, adding latency.",
				Entity: Entity{Kind: "peer", ID: peer.Name}, Evidence: []Evidence{{Label: "Path", Text: "relayed"}},
				Actions: []Action{{Label: "Check NAT traversal", Command: "netbird status --detail"}}})
		}
	}
	return out
}

func autoscalerAtMax(inputs *Inputs) []Insight {
	var out []Insight
	for _, scaler := range inputs.Autoscalers {
		if scaler.Max <= 0 || scaler.Current < scaler.Max {
			continue
		}
		since := scaler.AtMaxSince
		held := inputs.Since("autoscaler:" + scaler.Name)
		if !since.IsZero() {
			held = inputs.Now.Sub(since)
		}
		if held < inputs.Thresholds.AutoscalerAtMax {
			continue
		}
		out = append(out, Insight{Severity: SeverityWarning, Score: held.Seconds(),
			Title: "Autoscaler " + scaler.Name + " is at its maximum",
			Why: fmt.Sprintf("%s has run at its maximum of %d replicas for %s; demand above it is not served.",
				scaler.Name, scaler.Max, roundDuration(held)),
			Entity: Entity{Kind: "autoscaler", ID: scaler.Name, Href: "/terrabase"},
			Evidence: []Evidence{{Label: "Replicas", Value: float64(scaler.Current), Comparison: "<",
				Threshold: threshold(float64(scaler.Max))}},
			Actions: []Action{{Label: "Raise the maximum or add capacity", Href: "/terrabase"}}})
	}
	return out
}

func budgetCeiling(inputs *Inputs) []Insight {
	var out []Insight
	for _, budget := range inputs.Budgets {
		if budget.Ceiling <= 0 {
			continue
		}
		ratio := budget.Used / budget.Ceiling
		if ratio < inputs.Thresholds.BudgetWarning {
			continue
		}
		severity := SeverityWarning
		if ratio >= 1 {
			severity = SeverityCritical
		}
		out = append(out, Insight{Severity: severity, Score: ratio * 100,
			Title: fmt.Sprintf("Budget %s is %.0f%% used", budget.Name, ratio*100),
			Why: fmt.Sprintf("%s has used %s of its %s %s ceiling; new capacity may be refused.", budget.Name,
				observability.FormatFloat(budget.Used), observability.FormatFloat(budget.Ceiling), budget.Unit),
			Entity: Entity{Kind: "budget", ID: budget.Name},
			Evidence: []Evidence{{Label: "Used", Value: ratio, Unit: "ratio", Comparison: "<",
				Threshold: threshold(inputs.Thresholds.BudgetWarning)}}})
	}
	return out
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func roundDuration(duration time.Duration) string {
	switch {
	case duration < 0:
		return "0s"
	case duration < time.Minute:
		return duration.Round(time.Second).String()
	case duration < time.Hour:
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	case duration < 48*time.Hour:
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		if minutes == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh%02dm", hours, minutes)
	default:
		return fmt.Sprintf("%dd", int(duration.Hours()/24))
	}
}

func bytesText(value float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	index := 0
	for value >= 1024 && index < len(units)-1 {
		value /= 1024
		index++
	}
	return fmt.Sprintf("%.1f %s", value, units[index])
}
