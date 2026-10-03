package insights

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

const (
	// DefaultInterval is how often Run evaluates the rules.
	DefaultInterval = 15 * time.Second
	// changeCapacity bounds the change history kept for summaries.
	changeCapacity = 2048
	// decisionWindow is how far back rules and summaries read decisions.
	// decisionWindow is the repeated-hold rule's window.
	decisionWindow = time.Hour
	maxDecisions   = decisionlog.MaxQueryLimit
)

// Config wires an engine's providers. Every provider except Region is
// optional.
type Config struct {
	// Region is the local region token.
	Region string
	// Cluster supplies the cell-wide snapshot; Local is used when Cluster
	// is nil or fails.
	Cluster observability.ClusterSource
	Local   observability.SnapshotSource
	History observability.HistorySource
	// Decisions supplies this region's recent decisions.
	Decisions    decisionlog.Source
	Rollouts     RolloutProvider
	Volumes      VolumeProvider
	Certificates CertificateProvider
	NetBird      NetBirdProvider
	Autoscalers  AutoscalerProvider
	Budgets      BudgetProvider
	Reachability ReachabilityProvider
	Holds        HoldProvider
	Thresholds   Thresholds
	// Rules replaces DefaultRules.
	Rules    []Rule
	Interval time.Duration
	Now      func() time.Time
}

// Inputs is what one evaluation's rules read. Optional data is nil when its
// provider is missing or failed.
type Inputs struct {
	Now          time.Time
	Region       string
	Thresholds   Thresholds
	Cluster      *observability.ClusterSnapshot
	History      observability.HistorySource
	Decisions    []decisionlog.Decision
	Rollouts     []Rollout
	Volumes      []Volume
	Certificates []Certificate
	Peers        []NetBirdPeer
	Autoscalers  []Autoscaler
	Budgets      []Budget
	Reachability []RegionReach
	Holds        []Hold

	conditions map[string]time.Time
	touched    map[string]struct{}
}

// Since marks a condition as true in this evaluation and returns how long
// it has been continuously true. A condition not marked in an evaluation
// resets.
func (inputs *Inputs) Since(key string) time.Duration {
	inputs.touched[key] = struct{}{}
	started, ok := inputs.conditions[key]
	if !ok {
		inputs.conditions[key] = inputs.Now
		return 0
	}
	return inputs.Now.Sub(started)
}

// Rule is one named check.
type Rule struct {
	Name        string
	Description string
	Evaluate    func(inputs *Inputs) []Insight
}

// Evaluation is the result of one pass.
type Evaluation struct {
	At       time.Time `json:"at"`
	Insights []Insight `json:"insights"`
	Counts   Counts    `json:"counts"`
	// Unavailable names inputs that could not be read this pass.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Source is the read side the dashboard and the region provider use.
// Engine implements it.
type Source interface {
	// Current returns the latest evaluation's ranked insights.
	Current() Evaluation
	// Changes returns transitions at or after since, oldest first.
	Changes(since time.Time) []Change
	// Subscribe streams transitions until ctx ends.
	Subscribe(ctx context.Context, buffer int) <-chan Change
}

// Engine evaluates rules and tracks open insights.
type Engine struct {
	// droppedThrough is the time of the newest change dropped for capacity.
	droppedThrough time.Time
	config         Config
	rules          []Rule

	mu          sync.Mutex
	conditions  map[string]time.Time
	open        map[string]Insight
	current     Evaluation
	changes     []Change
	subscribers map[*changeSubscriber]struct{}
}

type changeSubscriber struct{ changes chan Change }

// NewEngine returns an engine over config.
func NewEngine(config Config) *Engine {
	if config.Interval <= 0 {
		config.Interval = DefaultInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.Region = strings.ToLower(config.Region)
	config.Thresholds = config.Thresholds.withDefaults()
	rules := config.Rules
	if rules == nil {
		rules = DefaultRules()
	}
	return &Engine{config: config, rules: rules, conditions: map[string]time.Time{}, open: map[string]Insight{},
		subscribers: map[*changeSubscriber]struct{}{}}
}

// Run evaluates every Interval until ctx ends.
func (engine *Engine) Run(ctx context.Context) error {
	ticker := time.NewTicker(engine.config.Interval)
	defer ticker.Stop()
	for {
		engine.Evaluate(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// gather reads every provider with a bounded deadline.
func (engine *Engine) gather(ctx context.Context, now time.Time) (*Inputs, []string) {
	config := engine.config
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	inputs := &Inputs{Now: now, Region: config.Region, Thresholds: config.Thresholds, History: config.History}
	var unavailable []string
	fail := func(name string) { unavailable = append(unavailable, name) }
	if config.Cluster != nil {
		if cluster, err := config.Cluster.Cluster(ctx, false); err == nil {
			inputs.Cluster = &cluster
		} else {
			fail("cluster")
		}
	}
	if inputs.Cluster == nil && config.Local != nil {
		if snapshot, err := config.Local.Snapshot(ctx, false); err == nil {
			inputs.Cluster = &observability.ClusterSnapshot{Cell: snapshot.Cell, ObservedAt: snapshot.ObservedAt,
				Members: []observability.MemberSnapshot{snapshot}}
		} else {
			fail("snapshot")
		}
	}
	if config.Decisions != nil {
		// Only the repeated-hold rule reads decisions: ask for exactly the
		// holds in its window, and treat an incomplete answer as no input
		// rather than as fewer holds.
		result, err := config.Decisions.Query(ctx, decisionlog.Query{Regions: []string{config.Region},
			Kinds: []decisionlog.Kind{decisionlog.KindHeld}, Since: now.Add(-decisionWindow), Limit: maxDecisions})
		switch {
		case err != nil || result.Truncated || result.Partial:
			fail("decisions")
		default:
			inputs.Decisions = result.Decisions
		}
	}
	check := func(name string, err error) {
		if err != nil {
			fail(name)
		}
	}
	var err error
	if config.Rollouts != nil {
		inputs.Rollouts, err = config.Rollouts.Rollouts(ctx)
		check("rollouts", err)
	}
	if config.Volumes != nil {
		inputs.Volumes, err = config.Volumes.Volumes(ctx)
		check("volumes", err)
	}
	if config.Certificates != nil {
		inputs.Certificates, err = config.Certificates.Certificates(ctx)
		check("certificates", err)
	}
	if config.NetBird != nil {
		inputs.Peers, err = config.NetBird.Peers(ctx)
		check("netbird", err)
	}
	if config.Autoscalers != nil {
		inputs.Autoscalers, err = config.Autoscalers.Autoscalers(ctx)
		check("autoscalers", err)
	}
	if config.Budgets != nil {
		inputs.Budgets, err = config.Budgets.Budgets(ctx)
		check("budgets", err)
	}
	if config.Reachability != nil {
		inputs.Reachability = config.Reachability.Reachability(ctx)
	}
	if config.Holds != nil {
		inputs.Holds = config.Holds.Holds(now)
	}
	if inputs.Cluster != nil {
		sections := map[string]bool{}
		for _, member := range inputs.Cluster.Members {
			for section := range member.Errors {
				sections[section] = true
			}
		}
		for _, section := range slices.Sorted(maps.Keys(sections)) {
			fail("section " + section)
		}
	}
	return inputs, unavailable
}

// ruleInputs names the inputs each rule reads beyond history: when one is
// unavailable, the rule's open insights and condition timers are kept
// rather than resolved, since a missing observation is not a recovery.
var ruleInputs = map[string][]string{
	"quorum_at_risk":       {"cluster", "snapshot"},
	"no_leader":            {"cluster", "snapshot", "section authority"},
	"member_not_ready":     {"cluster", "snapshot"},
	"jetstream_replicas":   {"cluster", "snapshot", "section nats"},
	"consumer_backlog":     {"cluster", "snapshot", "section nats"},
	"mixed_versions":       {"cluster", "snapshot"},
	"rollout_stalled":      {"cluster", "snapshot", "section placement"},
	"rollout_deadline":     {"rollouts"},
	"member_held":          {"cluster", "snapshot", "section placement", "decisions"},
	"volume_stuck":         {"cluster", "snapshot", "section placement", "volumes"},
	"disk_time_to_full":    {"cluster", "snapshot", "section system"},
	"memory_pressure":      {"cluster", "snapshot", "section system"},
	"oci_errors":           {"cluster", "snapshot", "section oci"},
	"certificate_expiring": {"certificates"},
	"netbird_peer":         {"netbird"},
	"autoscaler_at_max":    {"autoscalers"},
	"budget_ceiling":       {"budgets"},
}

// blindRules lists the rules that lacked an input on this pass.
func blindRules(unavailable []string) map[string]bool {
	blind := map[string]bool{}
	for rule, inputs := range ruleInputs {
		for _, input := range inputs {
			if slices.Contains(unavailable, input) {
				blind[rule] = true
			}
		}
	}
	return blind
}

// Evaluate runs every rule once, updates open insights and notifies
// subscribers of changes. It returns the new evaluation.
func (engine *Engine) Evaluate(ctx context.Context) Evaluation {
	now := engine.config.Now().UTC()
	inputs, unavailable := engine.gather(ctx, now)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	inputs.conditions = engine.conditions
	inputs.touched = map[string]struct{}{}
	found := map[string]Insight{}
	for _, rule := range engine.rules {
		for _, insight := range rule.Evaluate(inputs) {
			if insight.Rule == "" {
				insight.Rule = rule.Name
			}
			if insight.Key == "" {
				insight.Key = insight.Rule + ":" + insight.Entity.Kind + ":" + insight.Entity.ID
			}
			if insight.Region == "" {
				insight.Region = engine.config.Region
			}
			if insight.Entity.Region == "" {
				insight.Entity.Region = insight.Region
			}
			if existing, duplicate := found[insight.Key]; duplicate && existing.Severity.Rank() >= insight.Severity.Rank() {
				continue
			}
			found[insight.Key] = insight
		}
	}
	blind := blindRules(unavailable)
	// Untouched condition timers are reset only when every input was read:
	// a rule that could not look keeps its duration-gated timers.
	if len(blind) == 0 {
		for key := range engine.conditions {
			if _, touched := inputs.touched[key]; !touched {
				delete(engine.conditions, key)
			}
		}
	}
	var changes []Change
	for _, key := range slices.Sorted(maps.Keys(found)) {
		insight := found[key]
		insight.LastSeen = now
		previous, wasOpen := engine.open[key]
		switch {
		case !wasOpen:
			insight.FirstSeen = now
			changes = append(changes, Change{Type: ChangeOpened, Time: now, Insight: insight})
		default:
			insight.FirstSeen = previous.FirstSeen
			if insight.Severity.Rank() > previous.Severity.Rank() {
				changes = append(changes, Change{Type: ChangeEscalated, Time: now, Insight: insight})
			}
		}
		engine.open[key] = insight
	}
	for _, key := range slices.Sorted(maps.Keys(engine.open)) {
		if _, still := found[key]; !still {
			if blind[engine.open[key].Rule] {
				// Not observed this pass: keep it open until a successful
				// observation clears it.
				continue
			}
			resolved := engine.open[key]
			resolved.LastSeen = now
			changes = append(changes, Change{Type: ChangeResolved, Time: now, Insight: resolved})
			delete(engine.open, key)
		}
	}
	insights := slices.Collect(maps.Values(engine.open))
	Rank(insights)
	engine.current = Evaluation{At: now, Insights: insights, Counts: Count(insights), Unavailable: unavailable}
	for _, change := range changes {
		engine.changes = append(engine.changes, change)
		for subscriber := range engine.subscribers {
			select {
			case subscriber.changes <- change:
			default:
			}
		}
	}
	if overflow := len(engine.changes) - changeCapacity; overflow > 0 {
		engine.droppedThrough = engine.changes[overflow-1].Time
		engine.changes = slices.Delete(engine.changes, 0, overflow)
	}
	return engine.current
}

// Current returns the latest evaluation.
func (engine *Engine) Current() Evaluation {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	current := engine.current
	current.Insights = slices.Clone(current.Insights)
	return current
}

// ChangesComplete reports whether every transition at or after since is
// still held: the engine keeps only the newest changeCapacity.
func (engine *Engine) ChangesComplete(since time.Time) bool {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.droppedThrough.IsZero() || engine.droppedThrough.Before(since)
}

// Changes returns transitions at or after since, oldest first.
func (engine *Engine) Changes(since time.Time) []Change {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	index, _ := slices.BinarySearchFunc(engine.changes, since, func(change Change, at time.Time) int {
		return change.Time.Compare(at)
	})
	return slices.Clone(engine.changes[index:])
}

// Subscribe streams transitions until ctx ends; a subscriber more than
// buffer changes behind loses changes.
func (engine *Engine) Subscribe(ctx context.Context, buffer int) <-chan Change {
	if buffer <= 0 {
		buffer = 32
	}
	subscriber := &changeSubscriber{changes: make(chan Change, buffer)}
	engine.mu.Lock()
	engine.subscribers[subscriber] = struct{}{}
	engine.mu.Unlock()
	context.AfterFunc(ctx, func() {
		engine.mu.Lock()
		delete(engine.subscribers, subscriber)
		engine.mu.Unlock()
		close(subscriber.changes)
	})
	return subscriber.changes
}

var _ Source = (*Engine)(nil)
