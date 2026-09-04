package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// Rollout executes one verified delivery (D-67): the home-Region canary
// host first, then host by host across the target Regions, each step gated
// on drain, health, and catch-up, with automatic rollback on gate failure.
// Worker and Snippet deliveries ride the edge promoter instead of hosts.
type Rollout struct {
	config RolloutConfig
}

// RolloutConfig is the fully explicit rollout configuration.
type RolloutConfig struct {
	// Spec is the declared estate; its Regions and home Region shape the
	// canary and the per-Region host walk. Required.
	Spec estate.Spec
	// Hosts lists one Region's hosts in rollout order; the first host of the
	// home Region is the canary. Required.
	Hosts HostInventory
	// Control is the ts-node surface (I-3a): cordon, drain status, and
	// converge (the systemd symlink flip and restart ride the converge
	// plan). Required for host rollouts.
	Control HostControl
	// Gates run in order after every converge: drain, health, catch-up.
	// Required for host rollouts.
	Gates []Gate
	// Edge promotes Workers and Snippets through the Cloudflare reconcilers.
	// Required for site and package deliveries.
	Edge EdgePromoter
	// GateTimeout bounds one gate's polling. Defaults to 10 minutes.
	GateTimeout time.Duration
	// Now overrides the clock for tests.
	Now func() time.Time
	// Wait sleeps for at most the requested duration, or returns when the
	// context is canceled. It is injectable so gate polling can be
	// deterministic in tests.
	Wait func(context.Context, time.Duration) error
}

// HostInventory lists the hosts of one Region in rollout order. The
// control-plane directory feeds the live implementation.
type HostInventory interface {
	Hosts(ctx context.Context, region string) ([]string, error)
}

// HostControl is I-3a's ts-node command surface, consumed as defined: the
// cordon and drain-status request-reply subjects and the converge plan that
// flips the /opt/terrascale/<component>/current symlink and restarts under
// drain. This package never redefines the wire shapes.
type HostControl interface {
	// Cordon refuses new work on the host (cordoned=false releases it).
	Cordon(ctx context.Context, host string, cordoned bool) error
	// DrainStatus reports the host's cordon and drain state.
	DrainStatus(ctx context.Context, host string) (DrainReport, error)
	// Converge drives the host to one serialized runtime plan.
	Converge(ctx context.Context, host string, plan []byte) error
}

// DrainReport is the drained/cordoned answer of one host.
type DrainReport struct {
	Cordoned bool
	Drained  bool
}

// Gate is one rollout gate. A nil error passes the gate; any error fails
// the step and triggers rollback.
type Gate interface {
	Name() string
	Check(ctx context.Context, host, digest string) error
}

// EdgePromoter promotes Worker and Snippet deliveries through the
// Cloudflare reconcilers (gradual deployments where the plan allows, else
// route flip; the cloudflare package owns the mechanics).
type EdgePromoter interface {
	PromoteWorker(ctx context.Context, service, digest string) error
	PromoteSnippet(ctx context.Context, service, digest string) error
}

// NewRollout validates the configuration.
func NewRollout(config RolloutConfig) (*Rollout, error) {
	if err := config.Spec.Validate(); err != nil {
		return nil, err
	}
	if config.Hosts == nil {
		return nil, errors.New("delivery: rollout requires a host inventory")
	}
	if config.GateTimeout <= 0 {
		config.GateTimeout = 10 * time.Minute
	}
	if config.Now == nil {
		config.Now = defaultRolloutNow
	}
	if config.Wait == nil {
		config.Wait = waitRollout
	}
	return &Rollout{config: config}, nil
}

// Roll executes one delivery and reports the terminal result. It implements
// Roller, so the delivery API drives it directly.
func (r *Rollout) Roll(ctx context.Context, request *Request, artifact *ReleaseArtifact) (RolloutResult, error) {
	if r == nil || request == nil || request.Target == nil || request.Artifact == nil || artifact == nil {
		return RolloutResult{}, errors.New("delivery: rollout requires a request and artifact")
	}
	regions, err := r.targetRegions(request)
	if err != nil {
		return r.failure("target_invalid", err)
	}
	switch request.Artifact.Kind {
	case "service":
		if r.config.Control == nil {
			return r.failure("host_control_missing", errors.New("no host control is configured"))
		}
		if len(r.config.Gates) == 0 {
			return r.failure("rollout_gates_missing", errors.New("no rollout gates are configured"))
		}
		return r.rollHosts(ctx, request, artifact, regions)
	case "site":
		if r.config.Edge == nil {
			return r.failure("edge_promoter_missing", errors.New("no edge promoter is configured"))
		}
		return r.rollEdge(ctx, request, artifact, r.config.Edge.PromoteWorker, r.config.Edge.PromoteWorker)
	case "package":
		if r.config.Edge == nil {
			return r.failure("edge_promoter_missing", errors.New("no edge promoter is configured"))
		}
		return r.rollEdge(ctx, request, artifact, r.config.Edge.PromoteSnippet, r.config.Edge.PromoteSnippet)
	default:
		return r.failure("artifact_kind_invalid", fmt.Errorf("artifact kind %s is not deployable", request.Artifact.Kind))
	}
}

// targetRegions resolves the request's Regions against the declared estate
// in declaration order.
func (r *Rollout) targetRegions(request *Request) ([]string, error) {
	declared := make(map[string]struct{}, len(r.config.Spec.Regions))
	for _, region := range r.config.Spec.Regions {
		declared[region.Code] = struct{}{}
	}
	var regions []string
	for _, region := range r.config.Spec.Regions {
		for _, wanted := range request.Target.Regions {
			if region.Code == wanted {
				regions = append(regions, region.Code)
				break
			}
		}
	}
	if len(regions) != len(request.Target.Regions) {
		for _, wanted := range request.Target.Regions {
			if _, ok := declared[wanted]; !ok {
				return nil, fmt.Errorf("target region %s is not declared in the estate", wanted)
			}
		}
		return nil, errors.New("delivery: target regions are invalid")
	}
	return regions, nil
}

// rollHosts walks the canary host, then every remaining host Region by
// Region, rolling back everything touched on the first gate failure.
func (r *Rollout) rollHosts(ctx context.Context, request *Request, artifact *ReleaseArtifact, regions []string) (RolloutResult, error) {
	home := r.config.Spec.HomeRegion
	// The canary is the home Region's first host when the home Region is
	// targeted; otherwise the first host of the first target Region (D-67:
	// the GRU canary is the home-Region canary).
	canaryRegion := regions[0]
	for _, region := range regions {
		if region == home {
			canaryRegion = region
			break
		}
	}
	steps, err := r.hostSteps(ctx, regions, canaryRegion)
	if err != nil {
		return r.failure("rollout_unprepared", err)
	}

	checks := []*HealthCheck{}
	var touched []string
	fail := func(rollbackErr error) (RolloutResult, error) {
		return r.rollbackTouched(ctx, request, artifact, touched, checks, rollbackErr)
	}

	for _, step := range steps {
		hostChecks, err := r.step(ctx, step, artifact)
		checks = append(checks, hostChecks...)
		if err != nil {
			touched = append(touched, step.host)
			return fail(err)
		}
		touched = append(touched, step.host)
	}
	return RolloutResult{
		Status:    StatusSucceeded,
		Checks:    checks,
		Converged: true,
		Rollback:  &Rollback{Status: RollbackNotRequired},
	}, nil
}

// hostStep is one host's rollout step.
type hostStep struct {
	host   string
	region string
	canary bool
}

func (r *Rollout) hostSteps(ctx context.Context, regions []string, canaryRegion string) ([]hostStep, error) {
	var steps []hostStep
	seenCanary := false
	for _, region := range regions {
		hosts, err := r.config.Hosts.Hosts(ctx, region)
		if err != nil {
			return nil, err
		}
		if len(hosts) == 0 {
			return nil, fmt.Errorf("region %s reports no hosts", region)
		}
		for index, host := range hosts {
			canary := !seenCanary && region == canaryRegion && index == 0
			if canary {
				seenCanary = true
			}
			steps = append(steps, hostStep{host: host, region: region, canary: canary})
		}
	}
	if !seenCanary {
		return nil, errors.New("delivery: no canary host was scheduled")
	}
	return steps, nil
}

// step runs one host: cordon, drain gate, converge (the ts-node symlink
// flip and restart), the configured gates, uncordon.
func (r *Rollout) step(ctx context.Context, step hostStep, artifact *ReleaseArtifact) ([]*HealthCheck, error) {
	label := step.host
	if step.canary {
		label = step.host + " (canary)"
	}
	checks := []*HealthCheck{}

	if err := r.config.Control.Cordon(ctx, step.host, true); err != nil {
		return r.failStep(checks, "cordon:"+label, err)
	}
	if err := waitForGate(ctx, r.config.GateTimeout, r.now, r.wait, func() (bool, error) {
		report, err := r.config.Control.DrainStatus(ctx, step.host)
		if err != nil {
			return false, err
		}
		return report.Cordoned && report.Drained, nil
	}); err != nil {
		return r.failStep(checks, "drain:"+label, err)
	}
	checks = append(checks, &HealthCheck{Name: "drain:" + label, Status: "passed"})

	plan, err := hostPlan(artifact.Service, artifact.Digest)
	if err != nil {
		return r.failStep(checks, "converge:"+label, err)
	}
	if err := r.config.Control.Converge(ctx, step.host, plan); err != nil {
		return r.failStep(checks, "converge:"+label, err)
	}
	for _, gate := range r.config.Gates {
		if err := gate.Check(ctx, step.host, artifact.Digest); err != nil {
			return r.failStep(checks, gate.Name()+":"+label, err)
		}
		checks = append(checks, &HealthCheck{Name: gate.Name() + ":" + label, Status: "passed"})
	}
	if err := r.config.Control.Cordon(ctx, step.host, false); err != nil {
		return r.failStep(checks, "uncordon:"+label, err)
	}
	return checks, nil
}

func (r *Rollout) failStep(checks []*HealthCheck, name string, err error) ([]*HealthCheck, error) {
	checks = append(checks, &HealthCheck{Name: name, Status: "failed"})
	return checks, err
}

// rollbackTouched converges every touched host back to the prior artifact
// (the ts-node symlink flip), newest first, and reports the terminal
// outcome: rolled_back when every host returned, failed when the rollback
// itself failed or no prior artifact was declared.
func (r *Rollout) rollbackTouched(ctx context.Context, request *Request, artifact *ReleaseArtifact, touched []string, checks []*HealthCheck, cause error) (RolloutResult, error) {
	message := "The rollout failed a gate and was rolled back."
	if cause != nil {
		message = "The rollout failed a gate: " + cause.Error()
	}
	result := RolloutResult{
		Status: StatusFailed,
		Checks: checks,
		Error:  &Error{Code: ptr("rollout_gate_failed"), Message: ptr(message), Remediation: ptr("Inspect the failing gate on the named host, then retry with a fresh operation ID.")},
		Rollback: &Rollback{
			Attempted: false,
			Status:    RollbackNotRequired,
		},
	}
	if request.Rollback == nil {
		result.Error.Message = ptr(message + " No rollback artifact was declared, so the failed host keeps its prior release.")
		return result, nil
	}
	result.Rollback.Attempted = true
	result.Rollback.TargetArtifactDigest = ptr(request.Rollback.ArtifactDigest)
	result.Rollback.TargetManifestDigest = ptr(request.Rollback.ManifestDigest)
	result.Rollback.Status = RollbackSucceeded

	for i := len(touched) - 1; i >= 0; i-- {
		host := touched[i]
		plan, err := hostPlan(artifact.Service, request.Rollback.ArtifactDigest)
		if err != nil {
			result.Rollback.Status = RollbackFailed
			result.Error.Message = ptr("The rollback artifact identity is invalid: " + err.Error())
			return result, nil
		}
		if err := r.config.Control.Converge(ctx, host, plan); err != nil {
			result.Rollback.Status = RollbackFailed
			result.Error.Message = ptr(fmt.Sprintf("The rollback of host %s failed: %s", host, err.Error()))
			return result, nil
		}
		if err := r.config.Control.Cordon(ctx, host, false); err != nil {
			result.Rollback.Status = RollbackFailed
			result.Error.Message = ptr(fmt.Sprintf("The rollback uncordon of host %s failed: %s", host, err.Error()))
			return result, nil
		}
	}
	if result.Rollback.Status == RollbackSucceeded {
		result.Status = StatusRolledBack
		result.Error = &Error{Code: ptr("rollout_gate_failed"), Message: ptr(message), Remediation: ptr("Inspect the failing gate on the named host, then retry with a fresh operation ID.")}
	}
	return result, nil
}

// rollEdge promotes a Worker or Snippet through the Cloudflare reconcilers;
// rollback promotes the prior digest back.
func (r *Rollout) rollEdge(ctx context.Context, request *Request, artifact *ReleaseArtifact, promote, rollback func(context.Context, string, string) error) (RolloutResult, error) {
	name := "worker-promotion:" + artifact.Service
	if request.Artifact.Kind == "package" {
		name = "snippet-promotion:" + artifact.Service
	}
	checks := []*HealthCheck{}
	if err := promote(ctx, artifact.Service, artifact.Digest); err != nil {
		return r.rollbackEdge(ctx, request, append(checks, &HealthCheck{Name: name, Status: "failed"}), err, rollback)
	}
	checks = append(checks, &HealthCheck{Name: name, Status: "passed"})
	return RolloutResult{Status: StatusSucceeded, Checks: checks, Converged: true, Rollback: &Rollback{Status: RollbackNotRequired}}, nil
}

func (r *Rollout) rollbackEdge(ctx context.Context, request *Request, checks []*HealthCheck, cause error, promote func(context.Context, string, string) error) (RolloutResult, error) {
	message := "The edge promotion failed: " + cause.Error()
	if request.Rollback == nil {
		return RolloutResult{
			Status: StatusFailed,
			Checks: checks,
			Error:  &Error{Code: ptr("edge_promotion_failed"), Message: ptr(message), Remediation: ptr("Inspect the Cloudflare plan output, then retry with a fresh operation ID.")},
			Rollback: &Rollback{
				Attempted: false,
				Status:    RollbackNotRequired,
			},
		}, nil
	}
	if promote == nil {
		return RolloutResult{
			Status:   StatusFailed,
			Checks:   checks,
			Error:    &Error{Code: ptr("edge_rollback_unavailable"), Message: ptr(message + " No edge rollback implementation is configured."), Remediation: ptr("Configure the Cloudflare edge promoter, then retry with a fresh operation ID.")},
			Rollback: &Rollback{Attempted: true, TargetArtifactDigest: ptr(request.Rollback.ArtifactDigest), TargetManifestDigest: ptr(request.Rollback.ManifestDigest), Status: RollbackFailed},
		}, nil
	}
	if err := promote(ctx, request.Target.Service, request.Rollback.ArtifactDigest); err != nil {
		return RolloutResult{
			Status:   StatusFailed,
			Checks:   checks,
			Error:    &Error{Code: ptr("edge_rollback_failed"), Message: ptr(message + " Edge rollback failed: " + err.Error()), Remediation: ptr("Restore the prior Cloudflare edge digest, then retry with a fresh operation ID.")},
			Rollback: &Rollback{Attempted: true, TargetArtifactDigest: ptr(request.Rollback.ArtifactDigest), TargetManifestDigest: ptr(request.Rollback.ManifestDigest), Status: RollbackFailed},
		}, nil
	}
	return RolloutResult{
		Status: StatusRolledBack,
		Checks: checks,
		Error:  &Error{Code: ptr("edge_promotion_failed"), Message: ptr(message), Remediation: ptr("Inspect the Cloudflare plan output, then retry with a fresh operation ID.")},
		Rollback: &Rollback{
			Attempted:            true,
			TargetArtifactDigest: ptr(request.Rollback.ArtifactDigest),
			Status:               RollbackSucceeded,
			TargetManifestDigest: ptr(request.Rollback.ManifestDigest),
		},
	}, nil
}

func (r *Rollout) failure(code string, cause error) (RolloutResult, error) {
	return RolloutResult{
		Status: StatusFailed,
		Checks: []*HealthCheck{{Name: "prepare", Status: "failed"}},
		Error:  &Error{Code: ptr(code), Message: ptr(cause.Error()), Remediation: ptr("Correct the delivery target and retry with a fresh operation ID.")},
		Rollback: &Rollback{
			Attempted: false,
			Status:    RollbackNotRequired,
		},
	}, nil
}

// hostPlan builds the converged systemd plan for one component version:
// the artifact digest is the version (D-69). Unknown components fail
// closed.
func hostPlan(component, digest string) ([]byte, error) {
	role, err := componentRole(component)
	if err != nil {
		return nil, err
	}
	digestHex := strings.TrimPrefix(digest, "sha256:")
	artifactDigest, err := runtime.NewArtifactDigest(digestHex)
	if err != nil {
		return nil, err
	}
	allocation, err := runtime.NewRuntimeAllocationId(component)
	if err != nil {
		return nil, err
	}
	plan, err := runtime.NewHostRuntimePlan(
		role,
		runtime.RuntimeDriverNativeSystemd,
		allocation,
		artifactDigest,
		runtime.HostArchitectureArm64,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return plan.MarshalJSON()
}

// componentRole maps a delivery service onto the admitted runtime role
// catalog. The catalog is closed; unmapped components fail closed.
func componentRole(component string) (runtime.AdmittedRole, error) {
	switch component {
	case "terrabase":
		return runtime.AdmittedRoleTerraBaseMember, nil
	case "ts-dashboard":
		return runtime.AdmittedRoleDashboard, nil
	default:
		return 0, fmt.Errorf("delivery: component %s has no admitted runtime role", component)
	}
}

// waitForGate polls one gate condition until it holds or the timeout ends.
// now and wait are injected so the rollout's deadline and polling do not
// depend on ambient wall-clock time or an unbounded real sleep. The wait
// budget also bounds the loop when a test clock jumps backwards or a custom
// waiter returns immediately.
func waitForGate(ctx context.Context, timeout time.Duration, now func() time.Time, wait func(context.Context, time.Duration) error, condition func() (bool, error)) error {
	if now == nil {
		now = defaultRolloutNow
	}
	if wait == nil {
		wait = waitRollout
	}
	deadline := now().Add(timeout)
	waited := time.Duration(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := condition()
		if err == nil && ok {
			return nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		current := now()
		if !current.Before(deadline) || waited >= timeout {
			if err != nil {
				return fmt.Errorf("gate did not pass within %s: %w", timeout, err)
			}
			return fmt.Errorf("gate did not pass within %s", timeout)
		}
		remaining := deadline.Sub(current)
		if budget := timeout - waited; budget < remaining {
			remaining = budget
		}
		interval := 50 * time.Millisecond
		if remaining < interval {
			interval = remaining
		}
		if err := wait(ctx, interval); err != nil {
			return err
		}
		waited += interval
	}
}

func (r *Rollout) now() time.Time {
	if r != nil && r.config.Now != nil {
		return r.config.Now()
	}
	return defaultRolloutNow()
}

func (r *Rollout) wait(ctx context.Context, duration time.Duration) error {
	if r != nil && r.config.Wait != nil {
		return r.config.Wait(ctx, duration)
	}
	return waitRollout(ctx, duration)
}

// defaultRolloutNow is the production clock adapter. Rollout logic only
// calls the injected function above, leaving this ambient dependency at the
// composition boundary.
func defaultRolloutNow() time.Time { return time.Now() }

// waitRollout is the production bounded waiter used by rollout polling.
func waitRollout(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// HealthGate checks host health through a source the member control plane
// feeds. A missing report fails closed.
type HealthGate struct {
	Source HealthSource
}

// HealthSource reports one host's health for one artifact digest; the
// member control plane implements it over its own observations.
type HealthSource interface {
	Healthy(ctx context.Context, host, digest string) error
}

// Name identifies the gate in receipts.
func (g HealthGate) Name() string { return "health" }

// Check asks the health source.
func (g HealthGate) Check(ctx context.Context, host, digest string) error {
	if g.Source == nil {
		return errors.New("delivery: health gate has no source")
	}
	return g.Source.Healthy(ctx, host, digest)
}

// CatchUpGate checks replication and backup catch-up for members; the
// member control plane implements the source.
type CatchUpGate struct {
	Source CatchUpSource
}

// CatchUpSource reports whether a member's replication and backups have
// caught up after its restart.
type CatchUpSource interface {
	CaughtUp(ctx context.Context, host string) error
}

// Name identifies the gate in receipts.
func (g CatchUpGate) Name() string { return "catch-up" }

// Check asks the catch-up source.
func (g CatchUpGate) Check(ctx context.Context, host, digest string) error {
	if g.Source == nil {
		return errors.New("delivery: catch-up gate has no source")
	}
	return g.Source.CaughtUp(ctx, host)
}

// HostReports is the control-plane-fed health and catch-up store behind the
// gates: members report, the rollout reads. Missing reports fail closed.
//
// ponytail: process-local map; the live member control plane streams
// reports over the control bus and the wiring adapts that stream into Feed.
type HostReports struct {
	mu      sync.Mutex
	health  map[string]error
	catchUp map[string]error
}

// NewHostReports returns an empty report store.
func NewHostReports() *HostReports {
	return &HostReports{health: map[string]error{}, catchUp: map[string]error{}}
}

// FeedHealth records one host's health for one digest.
func (s *HostReports) FeedHealth(host, digest string, healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if healthy {
		s.health[host+"\x00"+digest] = nil
		return
	}
	s.health[host+"\x00"+digest] = fmt.Errorf("host %s is unhealthy", host)
}

// Healthy fails closed when no report exists.
func (s *HostReports) Healthy(_ context.Context, host, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err, ok := s.health[host+"\x00"+digest]
	if !ok {
		return fmt.Errorf("host %s has no health report", host)
	}
	return err
}

// FeedCatchUp records one host's catch-up state.
func (s *HostReports) FeedCatchUp(host string, caughtUp bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if caughtUp {
		s.catchUp[host] = nil
		return
	}
	s.catchUp[host] = fmt.Errorf("host %s has not caught up", host)
}

// CaughtUp fails closed when no report exists.
func (s *HostReports) CaughtUp(_ context.Context, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err, ok := s.catchUp[host]
	if !ok {
		return fmt.Errorf("host %s has no catch-up report", host)
	}
	return err
}
