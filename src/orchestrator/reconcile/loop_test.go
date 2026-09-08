package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// fakeProvider is an in-memory Reconciler: Apply moves the observed state
// toward the plan (creates and updates; deletes configurable), with optional
// error injection and apply-latency recording.
type fakeProvider struct {
	mu         sync.Mutex
	kinds      []estate.ResourceKind
	state      map[string]Resource
	observeErr error
	applyErr   error
	applies    int
	delay      time.Duration
	onApply    func()
}

func newFakeProvider(kinds ...estate.ResourceKind) *fakeProvider {
	return &fakeProvider{kinds: kinds, state: map[string]Resource{}}
}

func (p *fakeProvider) Kinds() []estate.ResourceKind { return p.kinds }

func (p *fakeProvider) Observe(_ context.Context) (State, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.observeErr != nil {
		return State{}, p.observeErr
	}
	state := State{}
	for _, resource := range p.state {
		state.Resources = append(state.Resources, resource)
	}
	return state, nil
}

func (p *fakeProvider) Apply(_ context.Context, plan Plan) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if p.onApply != nil {
		p.onApply()
	}
	if p.applyErr != nil {
		return p.applyErr
	}
	p.applies++
	for _, action := range plan.Actions {
		key := RefKey(action.Ref)
		switch action.Kind {
		case ActionCreate, ActionUpdate:
			p.state[key] = Resource{Ref: action.Ref, Attributes: action.Attributes}
		case ActionDelete:
			delete(p.state, key)
		}
	}
	return nil
}

func (p *fakeProvider) put(resource Resource) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state[RefKey(resource.Ref)] = resource
}

// captureAudit records every entry in order.
type captureAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *captureAudit) Append(_ context.Context, entry AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, entry)
	return nil
}

type captureDrift struct {
	mu     sync.Mutex
	events []DriftEvent
}

func (d *captureDrift) PublishDrift(_ context.Context, events []DriftEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, events...)
	return nil
}

func testConfig(providers []Reconciler, audit AuditSink, drift DriftSink) LoopConfig {
	return LoopConfig{
		Spec:         estate.Default(),
		Providers:    providers,
		Interval:     time.Hour,
		AllowDeletes: true,
		Audit:        audit,
		Drift:        drift,
	}
}

func TestLoopConvergesAndDetectsDrift(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket, estate.ResourceDNS)
	audit := &captureAudit{}
	drift := &captureDrift{}
	loop, err := NewLoop(testConfig([]Reconciler{provider}, audit, drift))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}

	// First pass plans every declared bucket and DNS record as creates.
	plan, err := loop.Pass(context.Background())
	if err != nil {
		t.Fatalf("first pass failed: %v", err)
	}
	if plan.Empty() {
		t.Fatal("empty observation produced no plan")
	}
	if len(drift.events) != len(plan.Actions) {
		t.Fatalf("drift events = %d, want one per action (%d)", len(drift.events), len(plan.Actions))
	}
	status := loop.Status()
	if status.DriftCount != len(plan.Actions) || status.Converged {
		t.Fatalf("status after first pass = %+v", status)
	}

	// Second pass observes the applied state and converges.
	plan, err = loop.Pass(context.Background())
	if err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("loop did not converge, remaining actions: %+v", plan.Actions)
	}
	status = loop.Status()
	if !status.Converged || status.DriftCount != 0 {
		t.Fatalf("status after convergence = %+v", status)
	}

	// External mutation is drift on the next pass.
	provider.put(Resource{
		Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"},
		Attributes: []Attribute{
			{Name: "bucket.purpose", Value: "database-backup"},
			{Name: "bucket.versioning", Value: "true"},
			{Name: "bucket.lifecycle-rule", Value: "expire-history|delete|7"},
		},
	})
	plan, err = loop.Pass(context.Background())
	if err != nil {
		t.Fatalf("drift pass failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionUpdate {
		t.Fatalf("drift pass planned %+v, want one update", plan.Actions)
	}
	found := false
	for _, event := range drift.events {
		if event.Ref.Name == "backups" && event.Action == ActionUpdate {
			found = true
		}
	}
	if !found {
		t.Fatal("no drift event for the mutated bucket")
	}

	// The audit trail covers planned and applied transitions in order.
	results := map[string]int{}
	for _, entry := range audit.entries {
		results[entry.Result]++
	}
	if results["planned"] == 0 || results["applied"] == 0 {
		t.Fatalf("audit trail results = %v", results)
	}
}

func TestLoopRefreshesDesiredAutoscaleTargetBeforeEachPass(t *testing.T) {
	provider := newFakeProvider(estate.ResourceCompute)
	base := estate.Default()
	if len(base.Regions) == 0 {
		t.Fatal("default estate has no regions")
	}
	region := base.Regions[0].Code
	pass := 0
	desired := func(context.Context) (estate.Spec, error) {
		pass++
		spec := base
		spec.Regions = append([]estate.Region(nil), base.Regions...)
		spec.Regions[0].Members.Count = base.Regions[0].Members.Count
		if pass <= 2 {
			spec.Regions[0].Members.Count++
		}
		return spec, nil
	}
	config := testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{})
	config.Spec = base
	config.Desired = desired
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}

	plan, err := loop.Pass(t.Context())
	if err != nil {
		t.Fatalf("expansion pass failed: %v", err)
	}
	var expansion *Action
	for index := range plan.Actions {
		if plan.Actions[index].Ref.Region == region {
			expansion = &plan.Actions[index]
			break
		}
	}
	if expansion == nil || expansion.Kind != ActionCreate {
		t.Fatalf("expansion plan = %+v, want a compute create for %s", plan.Actions, region)
	}
	wantExpanded := strconv.FormatUint(uint64(base.Regions[0].Members.Count+1), 10)
	if got := attributeValue(expansion.Attributes, "member.count"); got != wantExpanded {
		t.Fatalf("expansion declared count = %q, want %s", got, wantExpanded)
	}

	plan, err = loop.Pass(t.Context())
	if err != nil {
		t.Fatalf("convergence pass failed: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("target 3 did not converge: %+v", plan.Actions)
	}

	plan, err = loop.Pass(t.Context())
	if err != nil {
		t.Fatalf("contraction pass failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionUpdate {
		t.Fatalf("contraction plan = %+v, want one compute update", plan.Actions)
	}
	wantContracted := strconv.FormatUint(uint64(base.Regions[0].Members.Count), 10)
	if got := attributeValue(plan.Actions[0].Attributes, "member.count"); got != wantContracted {
		t.Fatalf("contraction declared count = %q, want %s", got, wantContracted)
	}
}

func TestLoopHoldsLastDeclarationWhenDesiredProjectionFails(t *testing.T) {
	provider := newFakeProvider(estate.ResourceCompute)
	config := testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{})
	config.Desired = func(context.Context) (estate.Spec, error) {
		return estate.Spec{}, errors.New("autoscale target unavailable")
	}
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	plan, err := loop.Pass(t.Context())
	if err == nil || !strings.Contains(err.Error(), "autoscale target unavailable") {
		t.Fatalf("projection failure = %v, want source error", err)
	}
	if !plan.Empty() {
		t.Fatalf("projection failure produced plan %+v", plan.Actions)
	}
	if provider.applies != 0 {
		t.Fatalf("projection failure applied %d provider plans", provider.applies)
	}
}

func attributeValue(attributes []Attribute, name string) string {
	for _, attribute := range attributes {
		if attribute.Name == name {
			return attribute.Value
		}
	}
	return ""
}

func TestLoopSkipsAndAppliesDeletesPerPolicy(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket)
	provider.put(Resource{
		Ref:        estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "clicked-in-console"},
		Attributes: []Attribute{{Name: "bucket.purpose", Value: "unknown"}},
	})
	audit := &captureAudit{}
	config := testConfig([]Reconciler{provider}, audit, &captureDrift{})
	config.AllowDeletes = false
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	plan, err := loop.Pass(context.Background())
	if err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	if plan.Empty() {
		t.Fatal("undeclared bucket produced no plan")
	}
	provider.mu.Lock()
	_, stillThere := provider.state[RefKey(plan.Actions[0].Ref)]
	provider.mu.Unlock()
	if !stillThere {
		t.Fatal("delete was applied despite the policy")
	}
	skipped := 0
	for _, entry := range audit.entries {
		if entry.Result == "skipped" {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatal("skipped delete was not audited")
	}
}

func TestLoopAppliesAreRateLimited(t *testing.T) {
	first := newFakeProvider(estate.ResourceBucket)
	second := newFakeProvider(estate.ResourceDNS)
	audit := &captureAudit{}
	config := testConfig([]Reconciler{first, second}, audit, &captureDrift{})
	// 25 applies/s with burst 1: two provider applies must be spaced ~40ms.
	config.Rate = 25
	config.Burst = 1
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	start := time.Now()
	if _, err := loop.Pass(context.Background()); err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 30*time.Millisecond {
		t.Fatalf("two rate-limited applies completed in %v, want spacing enforced", elapsed)
	}
}

func TestLoopRecordsApplyFailures(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket)
	provider.applyErr = errors.New("oci is down")
	audit := &captureAudit{}
	loop, err := NewLoop(testConfig([]Reconciler{provider}, audit, &captureDrift{}))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	if _, err := loop.Pass(context.Background()); err == nil {
		t.Fatal("apply failure must fail the pass")
	}
	failed := 0
	for _, entry := range audit.entries {
		if entry.Result == "failed" {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("failed apply was not audited")
	}
	if loop.Status().LastPassError == "" {
		t.Fatal("apply failure was not recorded in the status")
	}
}

type appliedOutcomeFailureProgress struct {
	inner ProgressStore
}

func (s appliedOutcomeFailureProgress) Load(ctx context.Context, key string) (Progress, bool, error) {
	return s.inner.Load(ctx, key)
}

func (s appliedOutcomeFailureProgress) Save(ctx context.Context, progress Progress) error {
	if progress.Outcome == "applied" {
		return errors.New("progress journal unavailable after provider success")
	}
	return s.inner.Save(ctx, progress)
}

func TestLoopFailsClosedWhenAppliedOutcomeCannotBePersisted(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket)
	config := testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{})
	config.Progress = appliedOutcomeFailureProgress{inner: NewMemoryProgressStore()}
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	if _, err := loop.Pass(context.Background()); err == nil || !IsUnknownOutcome(err) {
		t.Fatalf("progress persistence failure = %v, want unknown outcome", err)
	}
	provider.mu.Lock()
	applies := provider.applies
	provider.mu.Unlock()
	if applies != 1 {
		t.Fatalf("provider applies = %d, want one committed apply before the persistence failure", applies)
	}
}

func TestLoopFailsClosedForPersistedPendingOutcome(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket)
	config := testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{})
	progress := NewMemoryProgressStore()
	action := Action{Kind: ActionCreate, Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"}}
	if err := progress.Save(context.Background(), Progress{Key: OperationKey(action), Action: action.Kind, Ref: RefKey(action.Ref), Attempt: 1, Outcome: "pending", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed pending progress: %v", err)
	}
	config.Progress = progress
	loop, err := NewLoop(config)
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	if err := loop.applyWithRetry(context.Background(), provider, Plan{Actions: []Action{action}}); err == nil || !IsUnknownOutcome(err) {
		t.Fatalf("pending outcome error = %v, want unknown outcome", err)
	}
	provider.mu.Lock()
	applies := provider.applies
	provider.mu.Unlock()
	if applies != 0 {
		t.Fatalf("pending outcome was replayed: applies=%d", applies)
	}
}

func TestLoopRejectsOverlappingKindOwnership(t *testing.T) {
	first := newFakeProvider(estate.ResourceBucket)
	second := newFakeProvider(estate.ResourceBucket, estate.ResourceDNS)
	if _, err := NewLoop(testConfig([]Reconciler{first, second}, &captureAudit{}, &captureDrift{})); err == nil {
		t.Fatal("overlapping kind ownership must be rejected")
	}
}

// One provider's outage must not stop the other's self-healing (D-67): the
// healthy provider still plans, applies, and reports drift, the blind
// provider's kinds are excluded (a missing observation must not read as
// drift to create), and the pass surfaces the partial failure.
func TestLoopRepairsHealthyProvidersWhenOneObservationFails(t *testing.T) {
	oci := newFakeProvider(estate.ResourceBucket)
	oci.observeErr = errors.New("oci is down")
	cloud := newFakeProvider(estate.ResourceDNS)
	audit := &captureAudit{}
	drift := &captureDrift{}
	loop, err := NewLoop(testConfig([]Reconciler{oci, cloud}, audit, drift))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	plan, err := loop.Pass(context.Background())
	if err == nil {
		t.Fatal("a partial observation failure must surface as a pass error")
	}
	if plan.Empty() {
		t.Fatal("the healthy provider's drift was not planned")
	}
	for _, action := range plan.Actions {
		if action.Ref.Kind == estate.ResourceBucket {
			t.Fatalf("planned %s from a failed observation; blind kinds must be excluded", RefKey(action.Ref))
		}
	}
	cloud.mu.Lock()
	applied := len(cloud.state)
	cloud.mu.Unlock()
	if applied == 0 {
		t.Fatal("the healthy provider's plan was not applied")
	}
	oci.mu.Lock()
	ociApplies := oci.applies
	oci.mu.Unlock()
	if ociApplies != 0 {
		t.Fatal("the blind provider was applied")
	}
	if status := loop.Status(); status.Converged {
		t.Fatal("a pass with a blind provider must not report converged")
	} else if status.LastPassError == "" {
		t.Fatal("the observation failure was not recorded in the status")
	}
}

func TestLoopPassFailsWhenEveryObservationFails(t *testing.T) {
	first := newFakeProvider(estate.ResourceBucket)
	first.observeErr = errors.New("oci is down")
	second := newFakeProvider(estate.ResourceDNS)
	second.observeErr = errors.New("cloudflare is down")
	audit := &captureAudit{}
	drift := &captureDrift{}
	loop, err := NewLoop(testConfig([]Reconciler{first, second}, audit, drift))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	plan, err := loop.Pass(context.Background())
	if err == nil {
		t.Fatal("a pass with no usable observation must fail")
	}
	if !plan.Empty() {
		t.Fatalf("blind pass planned %+v", plan.Actions)
	}
	if len(drift.events) != 0 {
		t.Fatalf("a blind pass published %d drift events", len(drift.events))
	}
	for _, provider := range []*fakeProvider{first, second} {
		provider.mu.Lock()
		applies := provider.applies
		provider.mu.Unlock()
		if applies != 0 {
			t.Fatal("a blind pass must not apply")
		}
	}
}

func TestRunRequiresProvidersAndInterval(t *testing.T) {
	loop, err := NewLoop(testConfig(nil, &captureAudit{}, &captureDrift{}))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("running without providers must be rejected")
	}
	provider := newFakeProvider(estate.ResourceBucket)
	loop, err = NewLoop(testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{}))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := loop.Run(ctx); err == nil {
		t.Fatal("run must surface context cancellation")
	}
}

func TestStatusHandlerServesReconcilerStatus(t *testing.T) {
	provider := newFakeProvider(estate.ResourceBucket)
	loop, err := NewLoop(testConfig([]Reconciler{provider}, &captureAudit{}, &captureDrift{}))
	if err != nil {
		t.Fatalf("loop creation failed: %v", err)
	}
	if _, err := loop.Pass(context.Background()); err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	recorder := httptest.NewRecorder()
	loop.StatusHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status handler code = %d", recorder.Code)
	}
	var status Status
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("status payload is not JSON: %v", err)
	}
	if status.LastPassAt == "" || status.Passes != 1 || status.DriftCount == 0 {
		t.Fatalf("status payload = %+v", status)
	}
}

func TestLogSinksWriteStructuredLines(t *testing.T) {
	auditBuffer := &bytes.Buffer{}
	driftBuffer := &bytes.Buffer{}
	audit := NewLogAuditSink(auditBuffer)
	drift := NewLogDriftSink(driftBuffer)
	if err := audit.Append(context.Background(), AuditEntry{At: "2026-09-04T00:00:00Z", Result: "applied"}); err != nil {
		t.Fatalf("audit append failed: %v", err)
	}
	if err := drift.PublishDrift(context.Background(), []DriftEvent{{At: "2026-09-04T00:00:00Z"}}); err != nil {
		t.Fatalf("drift publish failed: %v", err)
	}
	for _, payload := range []string{auditBuffer.String(), driftBuffer.String()} {
		if !strings.Contains(payload, "\"at\":\"2026-09-04T00:00:00Z\"") {
			t.Fatalf("sink output is not structured JSON: %q", payload)
		}
	}
}
