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
	// KV is the delivery run's KV publish ordering hook (D-67: the same run
	// also publishes KV placement). When set it fires exactly once, after
	// every gate has passed and the estate serves the release, so the
	// ts-proxy Worker's Region-health and placement maps are republished in
	// the delivery order (health before placement; D-58). Optional: nil
	// skips publication and leaves freshness to the periodic KV writer.
	KV KVPublisher
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

// WorkerGradualPromoter is an optional stronger edge seam. Implementations
// use Cloudflare gradual deployments (with their provider-side health
// controls) and only return after the requested digest is serving. The basic
// EdgePromoter remains source-compatible for local and non-Cloudflare fakes.
type WorkerGradualPromoter interface {
	PromoteWorkerGradual(ctx context.Context, service, digest string) error
}

// SnippetZoneRuleCoordinator coordinates Snippet activation with the zone
// rules that admit the sync gate. It is intentionally separate from Worker
// promotion: Snippet code and its rule are one atomic orchestration unit, and
// a rule failure must trigger edge rollback before a receipt is issued.
type SnippetZoneRuleCoordinator interface {
	CoordinateSnippetZoneRules(ctx context.Context, service, digest string) error
}

// KVPublisher is the KV publish ordering hook of the delivery run (D-67: the
// same run also publishes KV placement). It fires exactly once, after every
// gate has passed and the estate serves the release — never between hosts,
// never after a failed or rolled-back step — because first-contact REST
// routes from the KV maps (D-58) and a mid-rollout publish would race hosts
// that are still cordoned. Implementations write Region health before
// database placement; the periodic KV writer owns freshness during the walk.
type KVPublisher interface {
	PublishKV(ctx context.Context, service, digest string) error
}

// NewRollout validates the configuration.
func NewRollout(config RolloutConfig) (*Rollout, error) {
	if err := config.Spec.Validate(); err != nil {
		return nil, err
	}
	if config.Hosts == nil {
		return nil, errors.New("delivery: rollout requires a host inventory")
	}
	for _, gate := range config.Gates {
		if gate == nil || strings.TrimSpace(gate.Name()) == "" {
			return nil, errors.New("delivery: rollout gates require non-empty names")
		}
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
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || request == nil || request.Target == nil || request.Artifact == nil || artifact == nil {
		return RolloutResult{}, errors.New("delivery: rollout requires a request and artifact")
	}
	if artifact.Service != request.Target.Service || !SameDigest(artifact.Digest, request.Artifact.Digest) ||
		len(artifact.Body) == 0 || !SameDigest(SHA256Digest(artifact.Body), artifact.Digest) ||
		(artifact.Architecture != "" && artifact.Architecture != request.Artifact.Architecture) {
		return r.failure("artifact_identity_mismatch", errors.New("verified rollout artifact does not match the requested candidate identity"))
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
		return r.rollEdge(ctx, request, artifact, r.promoteWorker, r.promoteWorker)
	case "package":
		if r.config.Edge == nil {
			return r.failure("edge_promoter_missing", errors.New("no edge promoter is configured"))
		}
		return r.rollEdge(ctx, request, artifact, r.promoteSnippet, r.promoteSnippet)
	default:
		return r.failure("artifact_kind_invalid", fmt.Errorf("artifact kind %s is not deployable", request.Artifact.Kind))
	}
}

// RollFenced is the authoritative rollout entry point. Provider-facing
// controls are wrapped so the durable fence is checked immediately before
// every mutating call, rather than relying on a context value captured at
// admission time.
func (r *Rollout) RollFenced(ctx context.Context, request *Request, artifact *ReleaseArtifact, fence OperationFence, check FenceChecker) (RolloutResult, error) {
	if r == nil || check == nil {
		return RolloutResult{}, ErrOperationLeaseActive
	}
	copy := *r
	copy.config.Control = &fencedHostControl{inner: r.config.Control, fence: fence, check: check}
	if r.config.Edge != nil {
		copy.config.Edge = &fencedEdgePromoter{inner: r.config.Edge, fence: fence, check: check}
	}
	if r.config.KV != nil {
		copy.config.KV = &fencedKVPublisher{inner: r.config.KV, fence: fence, check: check}
	}
	if err := check(fence); err != nil {
		return RolloutResult{}, err
	}
	return copy.Roll(ctx, request, artifact)
}

func (r *Rollout) promoteWorker(ctx context.Context, service, digest string) error {
	if gradual, ok := r.config.Edge.(WorkerGradualPromoter); ok {
		return gradual.PromoteWorkerGradual(ctx, service, digest)
	}
	return r.config.Edge.PromoteWorker(ctx, service, digest)
}

func (r *Rollout) promoteSnippet(ctx context.Context, service, digest string) error {
	if err := r.config.Edge.PromoteSnippet(ctx, service, digest); err != nil {
		return err
	}
	if coordinator, ok := r.config.Edge.(SnippetZoneRuleCoordinator); ok {
		return coordinator.CoordinateSnippetZoneRules(ctx, service, digest)
	}
	return nil
}

type fencedHostControl struct {
	inner HostControl
	fence OperationFence
	check FenceChecker
}

func (c *fencedHostControl) before() error {
	if c == nil || c.inner == nil || c.check == nil {
		return ErrOperationLeaseActive
	}
	return c.check(c.fence)
}

func (c *fencedHostControl) Cordon(ctx context.Context, host string, cordoned bool) error {
	if err := c.before(); err != nil {
		return err
	}
	return c.inner.Cordon(ctx, host, cordoned)
}

func (c *fencedHostControl) DrainStatus(ctx context.Context, host string) (DrainReport, error) {
	if err := c.before(); err != nil {
		return DrainReport{}, err
	}
	return c.inner.DrainStatus(ctx, host)
}

func (c *fencedHostControl) Converge(ctx context.Context, host string, plan []byte) error {
	if err := c.before(); err != nil {
		return err
	}
	return c.inner.Converge(ctx, host, plan)
}

type fencedEdgePromoter struct {
	inner EdgePromoter
	fence OperationFence
	check FenceChecker
}

func (p *fencedEdgePromoter) before() error {
	if p == nil || p.inner == nil || p.check == nil {
		return ErrOperationLeaseActive
	}
	return p.check(p.fence)
}

func (p *fencedEdgePromoter) PromoteWorker(ctx context.Context, service, digest string) error {
	if err := p.before(); err != nil {
		return err
	}
	return p.inner.PromoteWorker(ctx, service, digest)
}

func (p *fencedEdgePromoter) PromoteWorkerGradual(ctx context.Context, service, digest string) error {
	if err := p.before(); err != nil {
		return err
	}
	if gradual, ok := p.inner.(WorkerGradualPromoter); ok {
		return gradual.PromoteWorkerGradual(ctx, service, digest)
	}
	return p.inner.PromoteWorker(ctx, service, digest)
}

func (p *fencedEdgePromoter) PromoteSnippet(ctx context.Context, service, digest string) error {
	if err := p.before(); err != nil {
		return err
	}
	return p.inner.PromoteSnippet(ctx, service, digest)
}

func (p *fencedEdgePromoter) CoordinateSnippetZoneRules(ctx context.Context, service, digest string) error {
	if err := p.before(); err != nil {
		return err
	}
	if coordinator, ok := p.inner.(SnippetZoneRuleCoordinator); ok {
		return coordinator.CoordinateSnippetZoneRules(ctx, service, digest)
	}
	return nil
}

type fencedKVPublisher struct {
	inner KVPublisher
	fence OperationFence
	check FenceChecker
}

func (p *fencedKVPublisher) PublishKV(ctx context.Context, service, digest string) error {
	if p == nil || p.inner == nil || p.check == nil {
		return ErrOperationLeaseActive
	}
	if err := p.check(p.fence); err != nil {
		return err
	}
	return p.inner.PublishKV(ctx, service, digest)
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
		hostChecks, touchedHost, err := r.step(ctx, step, artifact)
		checks = append(checks, hostChecks...)
		if err != nil {
			if touchedHost {
				touched = append(touched, step.host)
			}
			return fail(err)
		}
		touched = append(touched, step.host)
	}
	// KV publish order (D-67): the run republishes the KV maps only after
	// the estate serves the release. A gate failure above returns before
	// this point, so a failed or rolled-back run never publishes.
	published, err := r.publishKV(ctx, artifact)
	if err != nil {
		return r.kvPublishFailure(artifact, checks, err)
	}
	if published {
		checks = append(checks, kvPublishCheck(artifact.Service, "passed"))
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
	seenHosts := make(map[string]struct{})
	// Always schedule the canary Region first, even if a custom estate's
	// declaration order places another Region ahead of the home Region.
	orderedRegions := make([]string, 0, len(regions))
	orderedRegions = append(orderedRegions, canaryRegion)
	for _, region := range regions {
		if region != canaryRegion {
			orderedRegions = append(orderedRegions, region)
		}
	}
	seenCanary := false
	for _, region := range orderedRegions {
		hosts, err := r.config.Hosts.Hosts(ctx, region)
		if err != nil {
			return nil, err
		}
		// TerraBase launches with RF=2. A rolling activation must never drain
		// the only member of a Region or silently continue with an inventory
		// that cannot preserve that replication factor.
		if len(hosts) < 2 {
			return nil, fmt.Errorf("region %s reports %d hosts; at least two are required to preserve RF=2", region, len(hosts))
		}
		for index, host := range hosts {
			if strings.TrimSpace(host) == "" {
				return nil, fmt.Errorf("region %s reports an empty host", region)
			}
			if _, exists := seenHosts[host]; exists {
				return nil, fmt.Errorf("host %s appears more than once in the rollout inventory", host)
			}
			seenHosts[host] = struct{}{}
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
func (r *Rollout) step(ctx context.Context, step hostStep, artifact *ReleaseArtifact) ([]*HealthCheck, bool, error) {
	label := step.host
	if step.canary {
		label = step.host + " (canary)"
	}
	checks := []*HealthCheck{}

	if err := r.config.Control.Cordon(ctx, step.host, true); err != nil {
		failedChecks, failedErr := r.failStep(checks, "cordon:"+label, err)
		return failedChecks, false, failedErr
	}
	if err := waitForGate(ctx, r.config.GateTimeout, r.now, r.wait, func() (bool, error) {
		report, err := r.config.Control.DrainStatus(ctx, step.host)
		if err != nil {
			return false, err
		}
		return report.Cordoned && report.Drained, nil
	}); err != nil {
		failedChecks, failedErr := r.failStep(checks, "drain:"+label, err)
		return failedChecks, true, failedErr
	}
	checks = append(checks, &HealthCheck{Name: "drain:" + label, Status: "passed"})

	plan, err := hostPlanForArtifact(artifact)
	if err != nil {
		failedChecks, failedErr := r.failStep(checks, "converge:"+label, err)
		return failedChecks, true, failedErr
	}
	if err := r.config.Control.Converge(ctx, step.host, plan); err != nil {
		failedChecks, failedErr := r.failStep(checks, "converge:"+label, err)
		return failedChecks, true, failedErr
	}
	for _, gate := range r.config.Gates {
		if gate == nil {
			failedChecks, failedErr := r.failStep(checks, "gate:"+label, errors.New("delivery: rollout contains a nil gate"))
			return failedChecks, true, failedErr
		}
		if err := waitForGate(ctx, r.config.GateTimeout, r.now, r.wait, func() (bool, error) {
			gateErr := gate.Check(ctx, step.host, artifact.Digest)
			return gateErr == nil, gateErr
		}); err != nil {
			failedChecks, failedErr := r.failStep(checks, gate.Name()+":"+label, err)
			return failedChecks, true, failedErr
		}
		checks = append(checks, &HealthCheck{Name: gate.Name() + ":" + label, Status: "passed"})
	}
	if err := r.config.Control.Cordon(ctx, step.host, false); err != nil {
		failedChecks, failedErr := r.failStep(checks, "uncordon:"+label, err)
		return failedChecks, true, failedErr
	}
	return checks, true, nil
}

func (r *Rollout) failStep(checks []*HealthCheck, name string, err error) ([]*HealthCheck, error) {
	checks = append(checks, &HealthCheck{Name: name, Status: "failed"})
	return checks, err
}

// publishKV runs the KV publish ordering hook once, after the estate serves
// the release. It reports whether a publisher is configured; a nil publisher
// skips publication and freshness stays with the periodic KV writer.
func (r *Rollout) publishKV(ctx context.Context, artifact *ReleaseArtifact) (bool, error) {
	if r == nil || r.config.KV == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return true, r.config.KV.PublishKV(ctx, artifact.Service, artifact.Digest)
}

func kvPublishCheck(service, status string) *HealthCheck {
	return &HealthCheck{Name: "kv-publish:" + service, Status: status}
}

// kvPublishFailure is the terminal result of a converged rollout whose KV
// publication failed. The estate already serves the release and every gate
// passed, so hosts are not rolled back; the periodic KV writer keeps
// republishing Region health and the receipt makes the incomplete run
// visible instead of claiming success.
func (r *Rollout) kvPublishFailure(artifact *ReleaseArtifact, checks []*HealthCheck, err error) (RolloutResult, error) {
	checks = append(checks, kvPublishCheck(artifact.Service, "failed"))
	return RolloutResult{
		Status:    StatusFailed,
		Checks:    checks,
		Converged: true,
		Rollback:  &Rollback{Status: RollbackNotRequired},
		Error: &Error{
			Code:        ptr("kv_publish_failed"),
			Message:     ptr("The rollout converged, but publishing the KV maps failed: " + err.Error()),
			Remediation: ptr("The periodic KV writer republishes Region health every 10 s; inspect Cloudflare KV and retry with a fresh operation ID if placement stays stale."),
		},
	}, nil
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
	// Rollback is recovery, not customer work. It must continue after the
	// caller cancels the forward rollout, otherwise a canceled request can
	// leave a partially activated host running the candidate indefinitely.
	rollbackContext := ctx
	if rollbackContext == nil {
		rollbackContext = context.Background()
	} else {
		rollbackContext = context.WithoutCancel(rollbackContext)
	}
	rollbackContext, cancel := context.WithTimeout(rollbackContext, rolloutRecoveryTimeout)
	defer cancel()
	if len(touched) == 0 {
		result.Error.Message = ptr(message + " No host mutation was recorded, so rollback was not required.")
		return result, nil
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
		plan, err := hostPlanForArtifact(&ReleaseArtifact{Service: artifact.Service, Digest: request.Rollback.ArtifactDigest, Architecture: request.Rollback.Architecture})
		if err != nil {
			result.Rollback.Status = RollbackFailed
			result.Error.Message = ptr("The rollback artifact identity is invalid: " + err.Error())
			return result, nil
		}
		if err := r.config.Control.Converge(rollbackContext, host, plan); err != nil {
			result.Rollback.Status = RollbackFailed
			result.Error.Message = ptr(fmt.Sprintf("The rollback of host %s failed: %s", host, err.Error()))
			return result, nil
		}
		if err := r.config.Control.Cordon(rollbackContext, host, false); err != nil {
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
	// The ts-proxy Worker routes first contact from the KV maps, so a Worker
	// promotion ends its run by republishing them (D-67). Snippet deliveries
	// never publish: the sync gate reads no KV (D-58).
	if request.Artifact.Kind != "package" {
		published, err := r.publishKV(ctx, artifact)
		if err != nil {
			return r.kvPublishFailure(artifact, checks, err)
		}
		if published {
			checks = append(checks, kvPublishCheck(artifact.Service, "passed"))
		}
	}
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
	rollbackContext := ctx
	if rollbackContext == nil {
		rollbackContext = context.Background()
	} else {
		rollbackContext = context.WithoutCancel(rollbackContext)
	}
	rollbackContext, cancel := context.WithTimeout(rollbackContext, rolloutRecoveryTimeout)
	defer cancel()
	if err := promote(rollbackContext, request.Target.Service, request.Rollback.ArtifactDigest); err != nil {
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
	return hostPlanForArtifact(&ReleaseArtifact{Service: component, Digest: digest})
}

func hostPlanForArtifact(artifact *ReleaseArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, errors.New("delivery: host plan requires an artifact")
	}
	component, digest := artifact.Service, artifact.Digest
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
	architecture := runtime.HostArchitectureArm64
	if artifact.Architecture == "linux/amd64" {
		architecture = runtime.HostArchitectureX64
	} else if artifact.Architecture != "" && artifact.Architecture != "linux/arm64" && artifact.Architecture != "multi" {
		return nil, fmt.Errorf("delivery: unsupported host architecture %s", artifact.Architecture)
	}
	plan, err := runtime.NewHostRuntimePlan(
		role,
		runtime.RuntimeDriverNativeSystemd,
		allocation,
		artifactDigest,
		architecture,
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
