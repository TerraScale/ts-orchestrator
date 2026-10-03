package hostpool

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// actor is the decision journal slice name of the host pool scaler.
const actor = "hostpool"

func poolSubject(pool NodePool) decisionlog.Subject {
	return decisionlog.Subject{Kind: "host_pool", ID: pool.Name, Name: pool.Environment + "/" + pool.Name}
}

// launchReason explains a launch plan from its reason token.
func launchReason(plan Plan) string {
	switch plan.Reason {
	case "below-min":
		return "The pool was below its minimum host count (" + plan.Reason + ")."
	case "pool-max-insufficient":
		return "Placement could not fit pending workloads even with the pool at its maximum; launching up to the maximum (" +
			plan.Reason + ")."
	default:
		return "Placement could not fit pending workloads on the pool's hosts (" + plan.Reason + ")."
	}
}

// recordLaunch journals one pool host launch after its provisioner call
// succeeded and returns the decision ID its outcome links to.
func recordLaunch(ctx context.Context, cell string, epoch uint64, pool NodePool, plan Plan, launch Launch) string {
	return decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: actor},
		Kind:    decisionlog.KindHostLaunched,
		Subject: decisionlog.Subject{Kind: "host", ID: launch.Node, Name: pool.Name + "/" + launch.Node},
		Summary: fmt.Sprintf("Launched pool host %s for %s in %s", launch.Node, pool.Name, launch.FailureDomain),
		Reason:  launchReason(plan),
		Rule:    "hostpool." + plan.Reason,
		Signals: []decisionlog.Signal{{Name: "launch", Value: float64(len(plan.Launch))}},
		Status:  decisionlog.StatusInProgress,
		Epoch:   epoch,
		Attrs: map[string]string{"pool": pool.Name, "failure_domain": launch.FailureDomain,
			"min": strconv.Itoa(pool.Min), "max": strconv.Itoa(pool.Max)},
	})
}

// launchOutcome is how one in-flight launch ended: the host registered, or
// its launch grace expired without registration.
type launchOutcome struct {
	node       string
	state      launchState
	registered bool
}

// recordLaunchOutcome resolves a journaled in-progress launch with a
// follow-up decision chained to it.
func recordLaunchOutcome(ctx context.Context, cell string, epoch uint64, pool NodePool, outcome launchOutcome,
	grace time.Duration,
) {
	decision := decisionlog.Decision{
		Region:   cell,
		Actor:    decisionlog.Actor{Slice: actor},
		Kind:     decisionlog.KindHostLaunched,
		Subject:  decisionlog.Subject{Kind: "host", ID: outcome.node, Name: pool.Name + "/" + outcome.node},
		ParentID: outcome.state.decision,
		Rule:     "hostpool.launch-outcome",
		Epoch:    epoch,
		Attrs:    map[string]string{"pool": pool.Name, "failure_domain": outcome.state.domain},
	}
	if outcome.registered {
		decision.Summary = fmt.Sprintf("Pool host %s registered in %s", outcome.node, pool.Name)
		decision.Reason = "The launched host registered with the controller."
		decision.Status = decisionlog.StatusSucceeded
	} else {
		decision.Summary = fmt.Sprintf("Pool host %s did not register in %s", outcome.node, pool.Name)
		decision.Reason = fmt.Sprintf("The launched host did not register within the %s launch grace.", grace)
		decision.Status = decisionlog.StatusFailed
	}
	decisionlog.Record(ctx, decision)
}

// recordReclaim journals one idle pool host reclaimed after its cooldown.
func recordReclaim(ctx context.Context, cell string, epoch uint64, pool NodePool, plan Plan, node string) {
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: actor},
		Kind:    decisionlog.KindHostReclaimed,
		Subject: decisionlog.Subject{Kind: "host", ID: node, Name: pool.Name + "/" + node},
		Summary: fmt.Sprintf("Reclaimed idle pool host %s from %s", node, pool.Name),
		Reason: fmt.Sprintf("The host held no allocations for the pool's %ds idle cooldown (%s).",
			pool.IdleCooldownSeconds, plan.Reason),
		Rule:   "hostpool." + plan.Reason,
		Status: decisionlog.StatusSucceeded,
		Epoch:  epoch,
		Attrs:  map[string]string{"pool": pool.Name},
	})
}

// recordRecommendation journals a plan the scaler could not act on because
// no provisioner is configured. The caller records it only when the plan
// changes, so a steady recommendation is journaled once.
func recordRecommendation(ctx context.Context, cell string, epoch uint64, pool NodePool, plan Plan) {
	nodes := make([]string, 0, len(plan.Launch))
	for _, launch := range plan.Launch {
		nodes = append(nodes, launch.Node)
	}
	kind := decisionlog.KindScaleUp
	if len(plan.Launch) == 0 {
		kind = decisionlog.KindScaleDown
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: actor},
		Kind:    kind,
		Subject: poolSubject(pool),
		Summary: fmt.Sprintf("Recommended launching %d and reclaiming %d hosts in pool %s",
			len(plan.Launch), len(plan.Reclaim), pool.Name),
		Reason: "No host provisioner is configured, so the scaler only recommends (" + plan.Reason + ").",
		Rule:   "hostpool." + plan.Reason,
		Signals: []decisionlog.Signal{{Name: "launch", Value: float64(len(plan.Launch))},
			{Name: "reclaim", Value: float64(len(plan.Reclaim))}},
		Status: decisionlog.StatusPending,
		Epoch:  epoch,
		Attrs: map[string]string{"pool": pool.Name, "launch": strings.Join(nodes, ","),
			"reclaim": strings.Join(plan.Reclaim, ",")},
	})
}

// samePlan reports whether two plans would journal the same recommendation.
func samePlan(left, right Plan) bool {
	return left.Reason == right.Reason && slices.Equal(left.Launch, right.Launch) && slices.Equal(left.Reclaim, right.Reclaim)
}
