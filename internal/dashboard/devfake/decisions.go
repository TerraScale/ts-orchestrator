package devfake

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// store is an in-memory, multi-region decision journal. It implements
// decisionlog.Source and decisionlog.LiveSource with the real query
// matching and chain building.
type store struct {
	mu          sync.Mutex
	decisions   []decisionlog.Decision
	subscribers []chan decisionlog.Decision
}

func (store *store) record(decision decisionlog.Decision) decisionlog.Decision {
	decision = decision.Normalize(time.Now())
	store.mu.Lock()
	defer store.mu.Unlock()
	store.decisions = append(store.decisions, decision)
	for _, subscriber := range store.subscribers {
		select {
		case subscriber <- decision:
		default:
		}
	}
	return decision
}

func (store *store) Query(_ context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	query = query.Normalized()
	store.mu.Lock()
	defer store.mu.Unlock()
	result := decisionlog.Result{}
	regions := map[string]int{}
	for _, decision := range store.decisions {
		if query.Matches(decision) {
			result.Decisions = append(result.Decisions, decision)
			regions[decision.Region]++
		}
	}
	decisionlog.SortNewestFirst(result.Decisions)
	if len(result.Decisions) > query.Limit {
		result.Decisions, result.Truncated = result.Decisions[:query.Limit], true
	}
	for _, region := range regionNames {
		if len(query.Regions) == 0 || slices.Contains(query.Regions, region) {
			result.Regions = append(result.Regions, decisionlog.RegionStatus{Region: region, State: decisionlog.RegionOK,
				Count: regions[region]})
		}
	}
	return result, nil
}

func (store *store) Chain(_ context.Context, id string) (decisionlog.Chain, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	chain, ok := decisionlog.BuildChain(store.decisions, id)
	if !ok {
		return decisionlog.Chain{}, decisionlog.ErrNotFound
	}
	return chain, nil
}

func (store *store) Subscribe(ctx context.Context, buffer int) <-chan decisionlog.Decision {
	channel := make(chan decisionlog.Decision, buffer)
	store.mu.Lock()
	store.subscribers = append(store.subscribers, channel)
	store.mu.Unlock()
	context.AfterFunc(ctx, func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.subscribers = slices.DeleteFunc(store.subscribers, func(other chan decisionlog.Decision) bool {
			return other == channel
		})
		close(channel)
	})
	return channel
}

// regional restricts a store to one region, like that region's own journal.
type regional struct {
	store  *store
	region string
}

func (source regional) Query(ctx context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	query.Regions = []string{source.region}
	return source.store.Query(ctx, query)
}

func (source regional) Chain(ctx context.Context, id string) (decisionlog.Chain, error) {
	return source.store.Chain(ctx, id)
}

// releaseChain records one release's path through a region, each step a
// child of the previous one.
type releaseChain struct {
	store   *store
	region  string
	member  string
	release decisionlog.Subject
	epoch   uint64
	parent  string
}

func (chain *releaseChain) step(at time.Time, kind decisionlog.Kind, status decisionlog.Status, summary, reason, rule string,
	signals []decisionlog.Signal, attrs map[string]string,
) {
	merged := map[string]string{"version": chain.release.Name}
	for key, value := range attrs {
		merged[key] = value
	}
	decision := chain.store.record(decisionlog.Decision{Time: at, Region: chain.region,
		Actor: decisionlog.Actor{Slice: "rollout", Member: chain.member}, Kind: kind, Subject: chain.release,
		Summary: summary, Reason: reason, Rule: rule, Signals: signals, Status: status, ParentID: chain.parent,
		Epoch: chain.epoch, Attrs: merged})
	chain.parent = decision.ID
}

// seedLeadership writes a day of authority and JetStream leadership and
// quorum changes for a region, shaped like what watchControlPlane records:
// a rolling restart hands the lease to another controller and back, and
// the JetStream meta leader follows.
func (world *World) seedLeadership(region *region, now time.Time) {
	offset := time.Duration(len(region.name)*7%5) * 40 * time.Minute
	other := region.controllers[len(region.controllers)-1]
	if other == region.leader {
		other = region.controllers[0]
	}
	leadership := func(at time.Time, member string, epoch uint64, reason string) {
		world.store.record(decisionlog.Decision{Time: at, Region: region.name,
			Actor: decisionlog.Actor{Slice: "authority", Member: member}, Kind: decisionlog.KindLeaderChanged,
			Subject: decisionlog.Subject{Kind: "member", ID: member},
			Summary: fmt.Sprintf("%s became the regional authority leader (epoch %d)", member, epoch),
			Reason:  reason, Rule: "fenced JetStream authority lease", Status: decisionlog.StatusSucceeded, Epoch: epoch,
			Signals: []decisionlog.Signal{{Name: "epoch", Value: float64(epoch)},
				{Name: "lease_expires_at", Text: at.Add(8 * time.Second).UTC().Format(time.RFC3339)}}})
	}
	meta := func(at time.Time, member, previous string, epoch uint64) {
		world.store.record(decisionlog.Decision{Time: at, Region: region.name,
			Actor: decisionlog.Actor{Slice: "cluster", Member: member}, Kind: decisionlog.KindLeaderChanged,
			Subject: decisionlog.Subject{Kind: "nats-meta", ID: member},
			Summary: member + " became the JetStream meta leader",
			Reason:  "The JetStream metadata group elected this server after " + previous + " stepped down.",
			Rule:    "JetStream meta leader election", Status: decisionlog.StatusSucceeded, Epoch: epoch,
			Signals: []decisionlog.Signal{{Name: "meta_leader", Text: member}, {Name: "previous", Text: previous}}})
	}
	quorum := func(at time.Time, healthy bool, epoch uint64) {
		peers := len(region.controllers) + len(region.missing)
		decision := decisionlog.Decision{Time: at, Region: region.name,
			Actor: decisionlog.Actor{Slice: "cluster", Member: region.leader}, Subject: decisionlog.Subject{Kind: "cluster", ID: region.name},
			Rule: "full regional cluster readiness", Epoch: epoch,
			Signals: []decisionlog.Signal{{Name: "required_replicas", Value: float64(peers)}}}
		if healthy {
			decision.Kind, decision.Status = decisionlog.KindQuorumRestored, decisionlog.StatusSucceeded
			decision.Summary = "Regional cluster is back at full strength"
			decision.Reason = fmt.Sprintf("All %d replicas route and the JetStream metadata quorum is current.", peers)
			decision.Signals = append(decision.Signals, gate("cluster_peers", float64(peers), "", ">=", float64(peers)))
		} else {
			decision.Kind, decision.Status = decisionlog.KindQuorumDegraded, decisionlog.StatusFailed
			decision.Summary = "Regional cluster dropped below full strength"
			decision.Reason = fmt.Sprintf("%s restarted for an upgrade; %d of %d replicas routed meanwhile.", region.leader, peers-1, peers)
			decision.Signals = append(decision.Signals, gate("cluster_peers", float64(peers-1), "", ">=", float64(peers)))
		}
		world.store.record(decision)
	}
	// Two days ago this region's current leader first took the lease.
	leadership(now.Add(-31*time.Hour), region.leader, region.epoch-2,
		"This controller acquired the regional authority lease after the previous holder restarted for an upgrade.")
	// A rolling restart about 20h ago: the leader restarts, the lease and
	// the meta group move to another controller, the cluster recovers.
	restart := now.Add(-20*time.Hour + offset)
	quorum(restart, false, region.epoch-2)
	leadership(restart.Add(40*time.Second), other, region.epoch-1,
		fmt.Sprintf("This controller acquired the regional authority lease, ending epoch %d.", region.epoch-2))
	meta(restart.Add(55*time.Second), other, region.leader, region.epoch-1)
	quorum(restart.Add(4*time.Minute), true, region.epoch-1)
	// About 5h ago the lease and the meta group moved back after a drain.
	back := now.Add(-5*time.Hour - offset)
	leadership(back, region.leader, region.epoch,
		fmt.Sprintf("This controller acquired the regional authority lease, ending epoch %d.", region.epoch-1))
	meta(back.Add(30*time.Second), region.leader, other, region.epoch)
}

func gate(name string, value float64, unit, comparison string, threshold float64) decisionlog.Signal {
	passed := false
	switch comparison {
	case "<=":
		passed = value <= threshold
	case ">=":
		passed = value >= threshold
	case "<":
		passed = value < threshold
	case ">":
		passed = value > threshold
	}
	return decisionlog.Signal{Name: name, Value: value, Unit: unit, Comparison: comparison,
		Threshold: decisionlog.Threshold(threshold), Passed: decisionlog.Passed(passed)}
}

// seedDecisions writes two days of decisions for every region.
func (world *World) seedDecisions(now time.Time) {
	ago := func(duration time.Duration) time.Time { return now.Add(-duration) }
	healthGates := func(errorRate, p99 float64) []decisionlog.Signal {
		return []decisionlog.Signal{gate("error_rate", errorRate, "%", "<=", 2), gate("p99_latency_ms", p99, "", "<=", 250),
			gate("crash_loops", 0, "", "<=", 0), gate("ready_members", 3, "", ">=", 3)}
	}
	for _, region := range world.regions {
		store := world.store
		leader := region.leader
		member := func(slice string) decisionlog.Actor { return decisionlog.Actor{Slice: slice, Member: leader} }
		world.seedLeadership(region, now)
		// The last release every region completed.
		old := releaseChain{store: store, region: region.name, member: leader, epoch: region.epoch,
			release: decisionlog.Subject{Kind: "release", ID: "sha256:4be1c0de77a1", Name: "v0.42.1"}}
		world.fullRollout(&old, ago(40*time.Hour), healthGates)
		// Autoscaling, backups, launches and seat moves.
		for hour := 46; hour > 0; hour -= 3 + len(region.name)%2 {
			at := ago(time.Duration(hour)*time.Hour + time.Duration(len(region.hosts))*time.Minute)
			cpu := 0.55 + 0.25*wave(at, 9*time.Hour, region.name)
			kind, summary, comparison, threshold, scaled := scaleDecision(cpu)
			status := decisionlog.StatusSucceeded
			// Inside the target band the autoscaler holds: no decision.
			if scaled {
				scale := store.record(decisionlog.Decision{Time: at, Region: region.name, Actor: member("autoscale"), Kind: kind,
					Subject: decisionlog.Subject{Kind: "service", ID: "terrabase-pool"}, Summary: summary, Status: status,
					Reason: fmt.Sprintf("Mean pool CPU was %.0f%% for 10 minutes.", cpu*100),
					Rule:   "pool CPU target band 35-70%",
					Signals: []decisionlog.Signal{gate("pool_cpu", cpu, "ratio", comparison, threshold),
						{Name: "hosts", Value: float64(len(region.hosts))}},
					Alternatives: []decisionlog.Alternative{{Option: "wait one more window",
						Reason: "the band was breached for two consecutive windows"}}})
				if kind == decisionlog.KindScaleUp {
					host := fmt.Sprintf("%s-host-%c", region.name, 'f'+rune(hour%5))
					store.record(decisionlog.Decision{Time: at.Add(3 * time.Minute), Region: region.name, Actor: member("placement"),
						Kind: decisionlog.KindHostLaunched, Subject: decisionlog.Subject{Kind: "host", ID: host},
						Summary: "Launched host " + host + " in FAULT-DOMAIN-" + fmt.Sprint(hour%3+1), ParentID: scale.ID,
						Reason: "The pool needed one more host and this fault domain had the fewest seats.",
						Rule:   "spread seats across fault domains", Status: decisionlog.StatusSucceeded,
						Alternatives: []decisionlog.Alternative{{Option: "FAULT-DOMAIN-1", Reason: "already carries the most seats"}}})
				}
			}
			if hour%6 == 0 || hour%6 == 1 {
				store.record(decisionlog.Decision{Time: at.Add(20 * time.Minute), Region: region.name, Actor: member("storage"),
					Kind: decisionlog.KindBackupTaken, Subject: decisionlog.Subject{Kind: "database", ID: region.databases[hour%len(region.databases)].id},
					Summary: "Backed up " + region.databases[hour%len(region.databases)].id + " to object storage",
					Reason:  "The six-hour backup schedule came due.", Rule: "backup every 6h, keep 14 days",
					Signals: []decisionlog.Signal{{Name: "size", Value: float64(2+hour%5) * 1.1e9, Unit: "bytes"}},
					Status:  decisionlog.StatusSucceeded})
			}
			if hour%4 == 0 {
				db := region.databases[(hour/4)%len(region.databases)]
				seat := fmt.Sprintf("%s-%d", db.id, hour%db.seats+1)
				store.record(decisionlog.Decision{Time: at.Add(35 * time.Minute), Region: region.name, Actor: member("placement"),
					Kind: decisionlog.KindStageChanged, Subject: decisionlog.Subject{Kind: "seat", ID: seat},
					Summary: "Seat " + seat + " moved from awaiting-healthy to serving",
					Reason:  "The seat passed three consecutive health checks.", Rule: "seat readiness gate",
					Signals: []decisionlog.Signal{gate("health_checks_passed", 3, "", ">=", 3)}, Status: decisionlog.StatusSucceeded})
			}
		}
		store.record(decisionlog.Decision{Time: ago(9 * time.Hour), Region: region.name, Actor: member("storage"),
			Kind: decisionlog.KindVolumeResized, Subject: decisionlog.Subject{Kind: "volume", ID: region.name + "-vol-data-3"},
			Summary: "Grew volume " + region.name + "-vol-data-3 from 200 GiB to 300 GiB",
			Reason:  "Projected time to full dropped under 7 days.", Rule: "resize at 7 days to full",
			Signals: []decisionlog.Signal{gate("days_to_full", 5.2, "days", "<", 7)}, Status: decisionlog.StatusSucceeded})
		store.record(decisionlog.Decision{Time: ago(14 * time.Hour), Region: region.name, Actor: member("netbird"),
			Kind: decisionlog.KindPeerEnrolled, Subject: decisionlog.Subject{Kind: "peer", ID: region.hosts[0]},
			Summary: "Enrolled " + region.hosts[0] + " in the NetBird overlay", Status: decisionlog.StatusSucceeded,
			Rule: "host enrollment with a one-time setup key"})
	}
	world.seedCurrentRelease(now, healthGates)
	// Placement holds on one GRU partition, as the hold journal records
	// them: once per reason every 15 minutes while re-asserted, then
	// cleared.
	gru := world.regions[0]
	held := gru.databases[0]
	partition := held.id + "/p0"
	seat := held.id + "-2"
	for _, minutes := range []int{140, 125, 110} {
		world.store.record(decisionlog.Decision{Time: ago(time.Duration(minutes) * time.Minute), Region: gru.name,
			Actor: decisionlog.Actor{Slice: "placement", Member: gru.leader}, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "seat", ID: seat}, Summary: "Placement held seat/" + seat,
			Reason: "member " + seat + " retained volume attachment is ATTACHING; desired state remains withheld",
			Rule:   "placement reconciliation safety gate", Status: decisionlog.StatusPending})
	}
	world.store.record(decisionlog.Decision{Time: ago(95 * time.Minute), Region: gru.name, Actor: decisionlog.Actor{Slice: "placement", Member: gru.leader},
		Kind: decisionlog.KindHeld, Subject: decisionlog.Subject{Kind: "database", ID: partition},
		Summary: "Placement held database/" + partition,
		Reason:  "database " + partition + " has no admitted managed placement profile; host reconciliation is held",
		Rule:    "placement reconciliation safety gate", Status: decisionlog.StatusPending})
	world.store.record(decisionlog.Decision{Time: ago(70 * time.Minute), Region: gru.name, Actor: decisionlog.Actor{Slice: "placement", Member: gru.leader},
		Kind: decisionlog.KindHoldCleared, Subject: decisionlog.Subject{Kind: "database", ID: partition},
		Summary: "Placement hold on " + partition + " cleared",
		Reason:  "The signed placement profile was admitted and the seat's volume attached.",
		Rule:    "placement reconciliation safety gate", Status: decisionlog.StatusSucceeded})
	fra := world.regions[2]
	world.store.record(decisionlog.Decision{Time: ago(3 * time.Hour), Region: fra.name,
		Actor: decisionlog.Actor{Slice: "cluster", Member: fra.leader}, Kind: decisionlog.KindQuorumDegraded,
		Subject: decisionlog.Subject{Kind: "cluster", ID: fra.name}, Summary: "Regional cluster dropped below full strength",
		Reason: fra.leader + " observed 2 of 3 routed replicas: " + fra.missing[0] + " stopped answering.",
		Rule:   "full regional cluster readiness", Status: decisionlog.StatusFailed, Epoch: fra.epoch,
		Signals: []decisionlog.Signal{gate("cluster_peers", 2, "", ">=", 3), {Name: "meta_offline_peers", Value: 1}}})
	world.store.record(decisionlog.Decision{Time: ago(2*time.Hour + 50*time.Minute), Region: fra.name,
		Actor: decisionlog.Actor{Slice: "membership", Member: fra.leader}, Kind: decisionlog.KindHeld,
		Subject: decisionlog.Subject{Kind: "member", ID: fra.missing[0]}, Summary: "Held replacing " + fra.missing[0],
		Reason: "The controller may be rebooting; replacement waits 30 minutes of absence and a healthy OCI instance check.",
		Rule:   "replace a controller after 30m absent and instance terminated", Status: decisionlog.StatusPending,
		Signals:      []decisionlog.Signal{gate("absent_minutes", 10, "", ">=", 30), {Name: "instance_state", Text: "STOPPED"}},
		Alternatives: []decisionlog.Alternative{{Option: "replace now", Reason: "an unnecessary replacement costs a full JetStream resync"}}})
}

// scaleDecision is the autoscaler's rule for the pool CPU target band
// 35-70%: scale up at or above 70%, down at or below 35%, otherwise hold.
func scaleDecision(cpu float64) (kind decisionlog.Kind, summary, comparison string, threshold float64, scaled bool) {
	switch {
	case cpu >= 0.7:
		return decisionlog.KindScaleUp, "Scaled the TerraBase pool up by one host", ">=", 0.7, true
	case cpu <= 0.35:
		return decisionlog.KindScaleDown, "Scaled the TerraBase pool down by one host", "<=", 0.35, true
	default:
		return "", "", "", 0, false
	}
}

func (world *World) fullRollout(chain *releaseChain, start time.Time, gates func(float64, float64) []decisionlog.Signal) {
	chain.step(start, decisionlog.KindReleaseAdmitted, decisionlog.StatusSucceeded, "Admitted release "+chain.release.Name,
		"The release passed CI qualification and carries a valid signature from the release delegation.",
		"signed release with qualification evidence", []decisionlog.Signal{{Name: "qualification", Text: "passed 14/14 suites"},
			{Name: "signature", Text: "valid"}}, map[string]string{"qualification": "passed", "delegation": "release-signer-2026q4"})
	chain.step(start.Add(10*time.Minute), decisionlog.KindUpgradeStarted, decisionlog.StatusSucceeded, "Staged "+chain.release.Name+" on every unit",
		"The artifact is cached on every host and controller.", "stage before canary", nil, nil)
	chain.step(start.Add(25*time.Minute), decisionlog.KindCanaryPromoted, decisionlog.StatusSucceeded, "Promoted the canary of "+chain.release.Name,
		"Every health gate held for the canary window.", "canary health gates", gates(0.3, 41), nil)
	chain.step(start.Add(55*time.Minute), decisionlog.KindHoldCleared, decisionlog.StatusSucceeded, "Soak of "+chain.release.Name+" passed",
		"30 minutes of soak with no gate regression.", "soak 30m", gates(0.2, 38), map[string]string{"stage": "soak"})
	for batch := 1; batch <= 3; batch++ {
		chain.step(start.Add(time.Duration(55+batch*15)*time.Minute), decisionlog.KindBatchPromoted, decisionlog.StatusSucceeded,
			fmt.Sprintf("Promoted batch %d of 3 of %s", batch, chain.release.Name), "The previous batch held its gates for 10 minutes.",
			"batch gates", gates(0.2+0.05*float64(batch), 40+float64(batch)), map[string]string{"batch": fmt.Sprint(batch), "batches": "3"})
	}
	chain.step(start.Add(115*time.Minute), decisionlog.KindRolloutCompleted, decisionlog.StatusSucceeded, "Completed rollout of "+chain.release.Name,
		"Every unit runs the release and the gates held.", "rollout complete", nil, nil)
}

// seedCurrentRelease: v0.43.0 completed in GRU, is in batch 1 in SFO and is
// held in FRA; v0.42.9 was rolled back at canary in FRA.
func (world *World) seedCurrentRelease(now time.Time, gates func(float64, float64) []decisionlog.Signal) {
	gru, sfo, fra := world.regions[0], world.regions[1], world.regions[2]
	current := decisionlog.Subject{Kind: "release", ID: "sha256:9f2c7ab3e410", Name: "v0.43.0"}
	world.fullRollout(&releaseChain{store: world.store, region: gru.name, member: gru.leader, release: current, epoch: gru.epoch},
		now.Add(-6*time.Hour), gates)
	chain := &releaseChain{store: world.store, region: sfo.name, member: sfo.leader, release: current, epoch: sfo.epoch}
	start := now.Add(-110 * time.Minute)
	chain.step(start, decisionlog.KindReleaseAdmitted, decisionlog.StatusSucceeded, "Admitted release v0.43.0",
		"GRU completed v0.43.0 with every gate passing.", "region waves: GRU, then SFO, then FRA",
		[]decisionlog.Signal{{Name: "qualification", Text: "passed 14/14 suites"}, {Name: "previous_wave", Text: "gru complete"}},
		map[string]string{"qualification": "passed", "delegation": "release-signer-2026q4"})
	chain.step(start.Add(8*time.Minute), decisionlog.KindUpgradeStarted, decisionlog.StatusSucceeded, "Staged v0.43.0 on every unit",
		"The artifact is cached on every host and controller.", "stage before canary", nil, nil)
	chain.step(start.Add(20*time.Minute), decisionlog.KindCanaryPromoted, decisionlog.StatusSucceeded, "Promoted the canary of v0.43.0",
		"Every health gate held for the canary window.", "canary health gates", gates(0.4, 52), nil)
	chain.step(start.Add(52*time.Minute), decisionlog.KindHoldCleared, decisionlog.StatusSucceeded, "Soak of v0.43.0 passed",
		"30 minutes of soak with no gate regression.", "soak 30m", gates(0.3, 47), map[string]string{"stage": "soak"})
	chain.step(start.Add(80*time.Minute), decisionlog.KindBatchPromoted, decisionlog.StatusInProgress, "Rolling batch 1 of 3 of v0.43.0",
		"The soak passed; batch 1 (one controller, two hosts) is updating.", "batch gates", gates(0.5, 58),
		map[string]string{"batch": "1", "batches": "3"})
	fraChain := &releaseChain{store: world.store, region: fra.name, member: fra.leader, release: current, epoch: fra.epoch}
	fraChain.step(now.Add(-150*time.Minute), decisionlog.KindReleaseAdmitted, decisionlog.StatusSucceeded, "Admitted release v0.43.0",
		"GRU completed v0.43.0.", "region waves: GRU, then SFO, then FRA", nil,
		map[string]string{"qualification": "passed", "delegation": "release-signer-2026q4"})
	fraChain.step(now.Add(-140*time.Minute), decisionlog.KindHeld, decisionlog.StatusPending, "Held v0.43.0 before staging",
		"FRA is below full controller strength; a rollout waits for full quorum.", "rollouts need full quorum",
		[]decisionlog.Signal{gate("controllers_answering", 2, "", ">=", 3)}, map[string]string{"stage": "staged"})
	bad := &releaseChain{store: world.store, region: fra.name, member: fra.leader, epoch: fra.epoch,
		release: decisionlog.Subject{Kind: "release", ID: "sha256:77d0be55aa09", Name: "v0.42.9"}}
	at := now.Add(-20 * time.Hour)
	bad.step(at, decisionlog.KindReleaseAdmitted, decisionlog.StatusSucceeded, "Admitted release v0.42.9",
		"The release passed CI qualification.", "signed release with qualification evidence", nil,
		map[string]string{"qualification": "passed", "delegation": "release-signer-2026q4"})
	bad.step(at.Add(9*time.Minute), decisionlog.KindUpgradeStarted, decisionlog.StatusSucceeded, "Staged v0.42.9 on every unit",
		"The artifact is cached on every host and controller.", "stage before canary", nil, nil)
	bad.step(at.Add(31*time.Minute), decisionlog.KindRollback, decisionlog.StatusRolledBack, "Rolled back the canary of v0.42.9",
		"The canary's error rate rose to 4.1% (gate 2%) and p99 latency to 410 ms (gate 250 ms); the release is marked known-bad.",
		"canary health gates", gates(4.1, 410), nil)
}
