package vmqualsuite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/edge"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/objectstore"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/oci"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type Scenario string

const (
	ScenarioBootstrap      Scenario = "bootstrap"
	ScenarioAddRegion      Scenario = "add-region"
	ScenarioR3             Scenario = "control-r3"
	ScenarioFourthRegion   Scenario = "fourth-region"
	ScenarioReconcile      Scenario = "reconcile"
	ScenarioSignedDelivery Scenario = "signed-delivery"
	ScenarioRollback       Scenario = "rollback"
	ScenarioEdge           Scenario = "edge-promotion"
	ScenarioKV             Scenario = "kv-routing"
	ScenarioEstate         Scenario = "estate-publication"
	ScenarioSelfHeal       Scenario = "self-heal"
	ScenarioKeyRotation    Scenario = "key-rotation"
	ScenarioFaultMatrix    Scenario = "fault-matrix"
	ScenarioRestore        Scenario = "restore"
	ScenarioDegraded       Scenario = "degraded"
	ScenarioPartition      Scenario = "partition-heal"
	ScenarioPlacement      Scenario = "placement"
	ScenarioCleanup        Scenario = "cleanup"
)

var RequiredScenarios = []Scenario{
	ScenarioBootstrap,
	ScenarioAddRegion,
	ScenarioR3,
	ScenarioFourthRegion,
	ScenarioReconcile,
	ScenarioSignedDelivery,
	ScenarioRollback,
	ScenarioEdge,
	ScenarioKV,
	ScenarioEstate,
	ScenarioSelfHeal,
	ScenarioKeyRotation,
	ScenarioFaultMatrix,
	ScenarioRestore,
	ScenarioDegraded,
	ScenarioPartition,
	ScenarioPlacement,
	ScenarioCleanup,
}

type ScenarioDriver interface {
	Run(context.Context, Scenario) error
}

// ScenarioEvidence is an optional extension implemented by local drivers.
// Evidence is checked after every scenario so a successful HTTP response
// cannot hide a provider that did not actually retain the mutation.
type ScenarioEvidence interface {
	Evidence() []Evidence
}

// ScenarioCleanupHook is an optional ownership hook for drivers that allocate
// local resources. RunSuite invokes it even when a scenario or stack fails.
type ScenarioCleanupHook interface {
	Close() error
}

// StackParticipant binds scenario proof to the guests that RunSuite started;
// provider HTTP success alone cannot qualify an unrelated stack.
type StackParticipant interface {
	AttachStack(*vmqual.Stack) error
}

// LocalProviderConfig bounds the in-process provider endpoints used by
// vm-test. It intentionally contains no credentials or external URLs.
type LocalProviderConfig struct {
	StateRoot  string
	OCI        oci.Config
	Cloudflare cloudflare.Config
	Object     objectstore.Config
	Edge       edge.Options
}

// LocalProviderEndpoints owns the local OCI, Cloudflare, object-storage, and
// edge handlers. Each endpoint is mounted on a loopback httptest listener,
// exactly as a production HTTP client sees its provider. Object stores are
// independent for GRU, SFO, and FRA.
type LocalProviderEndpoints struct {
	OCI        *oci.Server
	Cloudflare *cloudflare.Server
	Object     map[vmnet.RegionCode]*objectstore.Server
	Edge       *edge.Handler

	OCIURL        string
	CloudflareURL string
	ObjectURL     map[vmnet.RegionCode]string
	EdgeURL       string
	ZoneID        string
	AccountID     string
	edgeKey       []byte

	servers  []*httptest.Server
	close    sync.Once
	closedMu sync.RWMutex
	closed   bool
}

// NewLocalProviderEndpoints starts the complete provider fixture for the
// six-guest topology. The returned value must be closed by its owner.
func NewLocalProviderEndpoints(config LocalProviderConfig) (*LocalProviderEndpoints, error) {
	if config.StateRoot != "" && !filepath.IsAbs(config.StateRoot) {
		return nil, errors.New("vmqual: local provider state root must be absolute")
	}
	p := &LocalProviderEndpoints{Object: make(map[vmnet.RegionCode]*objectstore.Server), ObjectURL: make(map[vmnet.RegionCode]string)}
	if len(config.Edge.Key) == 0 && len(config.Edge.Keys) == 0 {
		config.Edge.Key = []byte("vmqual-local-capability-key")
	}
	if len(config.Edge.Key) != 0 {
		p.edgeKey = append([]byte(nil), config.Edge.Key...)
	} else {
		for _, key := range config.Edge.Keys {
			if len(key) != 0 {
				p.edgeKey = append([]byte(nil), key...)
				break
			}
		}
	}
	if config.Edge.Origin == nil && config.Edge.Fetch == nil {
		config.Edge.Origin = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/msgpack")
			w.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=60, immutable")
			_, _ = io.WriteString(w, "local-qualification-frame")
		})
	}
	p.OCI = oci.New(config.OCI)
	p.Cloudflare = cloudflare.New(config.Cloudflare)
	p.Edge = edge.New(config.Edge)

	ociServer := httptest.NewServer(p.OCI)
	cfServer := httptest.NewServer(p.Cloudflare)
	edgeServer := httptest.NewServer(p.Edge)
	p.servers = append(p.servers, ociServer, cfServer, edgeServer)
	p.OCIURL, p.CloudflareURL, p.EdgeURL = ociServer.URL, cfServer.URL, edgeServer.URL
	p.ZoneID, p.AccountID = p.Cloudflare.ClientConfig()
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		objectConfig := config.Object
		objectConfig.Namespace = "terrascale-" + strings.ToLower(string(region))
		if config.StateRoot != "" {
			objectConfig.Root = filepath.Join(config.StateRoot, "providers", "object", strings.ToLower(string(region)))
		} else if config.Object.Root != "" {
			objectConfig.Root = filepath.Join(config.Object.Root, strings.ToLower(string(region)))
		}
		store, err := objectstore.New(objectConfig)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("local object store %s: %w", region, err)
		}
		server := httptest.NewServer(store)
		p.Object[region], p.ObjectURL[region] = store, server.URL
		p.servers = append(p.servers, server)
	}
	return p, nil
}

// NewLocalScenarioDriverFromConfig constructs both the local endpoints and
// their ordered driver. The caller owns the returned endpoints and must close
// them after the suite (Run's cleanup scenario also closes them).
func NewLocalScenarioDriverFromConfig(config LocalProviderConfig) (*LocalProviderEndpoints, *LocalScenarioDriver, error) {
	endpoints, err := NewLocalProviderEndpoints(config)
	if err != nil {
		return nil, nil, err
	}
	driver, err := NewLocalScenarioDriver(endpoints)
	if err != nil {
		_ = endpoints.Close()
		return nil, nil, err
	}
	return endpoints, driver, nil
}

// Close tears down only endpoints owned by this fixture. It is safe to call
// repeatedly and is suitable for deferred cleanup after a failed scenario.
func (p *LocalProviderEndpoints) Close() error {
	if p == nil {
		return nil
	}
	p.close.Do(func() {
		for _, server := range p.servers {
			server.Close()
		}
		for _, store := range p.Object {
			_ = store.Close()
		}
		if p.OCI != nil {
			_ = p.OCI.Close()
		}
		p.closedMu.Lock()
		p.closed = true
		p.closedMu.Unlock()
	})
	return nil
}

// Closed reports whether every listener and durable local endpoint owned by
// this fixture has completed its idempotent Close path.
func (p *LocalProviderEndpoints) Closed() bool {
	if p == nil {
		return true
	}
	p.closedMu.RLock()
	defer p.closedMu.RUnlock()
	return p.closed
}

// LocalScenarioDriver returns the ordered local proof driver for these
// endpoints. A new driver starts at bootstrap and must be run in suite order.
func (p *LocalProviderEndpoints) LocalScenarioDriver() (*LocalScenarioDriver, error) {
	return NewLocalScenarioDriver(p)
}

// LocalScenarioDriver executes the qualification journey against the bounded
// provider contracts. It is deliberately a test-only scenario coordinator;
// it does not expose a production orchestration API.
type LocalScenarioDriver struct {
	Endpoints *LocalProviderEndpoints
	Client    *http.Client

	runMu     sync.Mutex
	mu        sync.Mutex
	completed []Scenario
	evidence  []Evidence
	stack     *vmqual.Stack
	control   scenarioControlProof
	cleanup   *ProviderCleanupObservation
	state     scenarioState
}

// Evidence is a bounded, non-secret proof record included in qualification
// diagnostics. Details are intentionally short and provider identifiers are
// not copied into the report.
type Evidence struct {
	Scenario Scenario `json:"scenario"`
	Check    string   `json:"check"`
	Passed   bool     `json:"passed"`
	Detail   string   `json:"detail,omitempty"`
}

func NewLocalScenarioDriver(endpoints *LocalProviderEndpoints) (*LocalScenarioDriver, error) {
	if endpoints == nil || endpoints.OCI == nil || endpoints.Cloudflare == nil || endpoints.Edge == nil || len(endpoints.Object) != 3 {
		return nil, errors.New("vmqual: complete local provider endpoints are required")
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if endpoints.Object[region] == nil || endpoints.ObjectURL[region] == "" {
			return nil, fmt.Errorf("vmqual: local object endpoint %s is missing", region)
		}
	}
	return &LocalScenarioDriver{Endpoints: endpoints, Client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Completed returns a copy of the ordered proof steps already run.
func (d *LocalScenarioDriver) Completed() []Scenario {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Scenario(nil), d.completed...)
}

// Evidence returns a copy of all bounded checks collected so far.
func (d *LocalScenarioDriver) Evidence() []Evidence {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Evidence(nil), d.evidence...)
}

func (d *LocalScenarioDriver) AttachStack(stack *vmqual.Stack) error {
	if d == nil || stack == nil {
		return errors.New("vmqual: local scenario stack is missing")
	}
	if len(stack.Guests()) != 6 {
		return errors.New("vmqual: local scenario requires six started guests")
	}
	d.mu.Lock()
	d.stack = stack
	if d.control == nil {
		d.control = &runtimeControlProof{stack: stack, journalRoot: filepath.Join(stack.Config().StateRoot, "control-contract")}
	}
	d.state = scenarioState{}
	d.mu.Unlock()
	if binder, ok := stack.Config().VMFactory.(interface {
		BindLocalProviderEndpoints(*LocalProviderEndpoints) error
	}); ok {
		if err := binder.BindLocalProviderEndpoints(d.Endpoints); err != nil {
			return fmt.Errorf("vmqual: bind local provider endpoints: %w", err)
		}
	}
	return nil
}

// Close releases all provider listeners and durable local stores owned by the
// driver. It is idempotent and lets RunSuite recover cleanup after failure.
func (d *LocalScenarioDriver) Close() error {
	if d == nil || d.Endpoints == nil {
		return nil
	}
	d.mu.Lock()
	bound := d.stack != nil && d.control != nil
	d.mu.Unlock()
	if !bound {
		return d.Endpoints.Close()
	}
	_, err := d.CleanupAndObserveProviderState(context.Background())
	return err
}

// prove records an observed qualification fact. Failed facts stay in the
// report and return an error; callers cannot turn a failed observation into a
// passing scenario by merely appending a descriptive string.
func (d *LocalScenarioDriver) prove(s Scenario, check string, passed bool, detail string) error {
	if strings.TrimSpace(check) == "" {
		return errors.New("vmqual: evidence check name is empty")
	}
	d.mu.Lock()
	d.evidence = append(d.evidence, Evidence{Scenario: s, Check: check, Passed: passed, Detail: detail})
	d.mu.Unlock()
	if !passed {
		return fmt.Errorf("vmqual: scenario %s failed evidence check %s", s, check)
	}
	return nil
}

func (d *LocalScenarioDriver) evidenceCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.evidence)
}

func (d *LocalScenarioDriver) verifyEvidence(ctx context.Context, scenario Scenario, first int) error {
	if scenario == ScenarioCleanup {
		observation, ok := d.ProviderCleanupEvidence()
		if !ok {
			return d.prove(scenario, "owned-provider-cleanup", false, "provider cleanup has no post-cleanup observation")
		}
		err := observation.Validate()
		return d.prove(scenario, "owned-provider-cleanup", err == nil, fmt.Sprintf("paths=%d listeners=%d", len(observation.Paths), len(observation.Listeners)))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	stack := d.stack
	d.mu.Unlock()
	if stack == nil {
		return errors.New("vmqual: scenario has no participating VM stack")
	}
	if err := stack.EnforceBudget(ctx); err != nil {
		return fmt.Errorf("VM stack participation check: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if first < 0 || first >= len(d.evidence) {
		return fmt.Errorf("vmqual: scenario %s returned no substantive evidence", scenario)
	}
	for _, proof := range d.evidence[first:] {
		if proof.Scenario != scenario || !proof.Passed || strings.TrimSpace(proof.Check) == "" {
			return fmt.Errorf("vmqual: scenario %s returned invalid evidence", scenario)
		}
	}
	return nil
}

func (d *LocalScenarioDriver) Run(ctx context.Context, scenario Scenario) error {
	if d == nil || d.Endpoints == nil {
		return errors.New("vmqual: local scenario driver is unavailable")
	}
	if ctx == nil {
		return errors.New("vmqual: local scenario context is nil")
	}
	d.runMu.Lock()
	defer d.runMu.Unlock()
	d.mu.Lock()
	index := len(d.completed)
	if index >= len(RequiredScenarios) || RequiredScenarios[index] != scenario {
		d.mu.Unlock()
		return fmt.Errorf("vmqual: scenario %s is out of order", scenario)
	}
	firstEvidence := len(d.evidence)
	d.mu.Unlock()
	var err error
	switch scenario {
	case ScenarioBootstrap:
		err = d.scenarioBootstrap(ctx)
	case ScenarioAddRegion:
		err = d.scenarioAddRegions(ctx)
	case ScenarioR3:
		err = d.scenarioR3(ctx)
	case ScenarioFourthRegion:
		err = d.scenarioFourthRegion(ctx)
	case ScenarioReconcile:
		err = d.scenarioReconcile(ctx)
	case ScenarioSignedDelivery:
		err = d.scenarioSignedDelivery(ctx)
	case ScenarioRollback:
		err = d.scenarioRollback(ctx)
	case ScenarioEdge:
		err = d.scenarioEdge(ctx)
	case ScenarioKV:
		err = d.scenarioKV(ctx)
	case ScenarioEstate:
		err = d.scenarioEstate(ctx)
	case ScenarioSelfHeal:
		err = d.scenarioSelfHeal(ctx)
	case ScenarioKeyRotation:
		err = d.scenarioKeyRotation(ctx)
	case ScenarioFaultMatrix:
		err = d.scenarioFaultMatrix(ctx)
	case ScenarioRestore:
		err = d.scenarioRestore(ctx)
	case ScenarioDegraded:
		err = d.scenarioDegraded(ctx)
	case ScenarioPartition:
		err = d.scenarioPartition(ctx)
	case ScenarioPlacement:
		err = d.scenarioPlacement(ctx)
	case ScenarioCleanup:
		err = d.scenarioCleanup(ctx)
	default:
		err = fmt.Errorf("vmqual: unknown scenario %s", scenario)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", scenario, err)
	}
	if err := d.verifyEvidence(ctx, scenario, firstEvidence); err != nil {
		return fmt.Errorf("%s evidence: %w", scenario, err)
	}
	d.mu.Lock()
	d.completed = append(d.completed, scenario)
	d.mu.Unlock()
	return nil
}

type HTTPScenarioDriver struct {
	BaseURL string
	Client  *http.Client
	Timeout time.Duration
}

func (d HTTPScenarioDriver) Run(c context.Context, s Scenario) error {
	u, e := url.Parse(d.BaseURL)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return errors.New("vmqual: scenario endpoint must be an HTTP URL")
	}
	u.Path = path.Join(u.Path, "qualification", string(s))
	cc := d.Client
	if cc == nil {
		cc = &http.Client{}
	}
	t := d.Timeout
	if t <= 0 {
		t = 2 * time.Minute
	}
	x, cancel := context.WithTimeout(c, t)
	defer cancel()
	q, e := http.NewRequestWithContext(x, http.MethodPost, u.String(), bytes.NewBufferString(`{"qualification":"firecracker"}`))
	if e != nil {
		return e
	}
	q.Header.Set("Content-Type", "application/json")
	r, e := cc.Do(q)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if readErr != nil || len(body) > 64<<10 {
		return fmt.Errorf("scenario %s returned an invalid proof body", s)
	}
	if r.StatusCode < 200 || r.StatusCode > 299 {
		return fmt.Errorf("scenario %s returned %s", s, r.Status)
	}
	var proof struct {
		Scenario Scenario   `json:"scenario"`
		Passed   bool       `json:"passed"`
		Evidence []Evidence `json:"evidence"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return fmt.Errorf("scenario %s did not return substantive repository proof", s)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("scenario %s returned ambiguous proof", s)
	}
	if proof.Scenario != s || !proof.Passed || len(proof.Evidence) == 0 {
		return fmt.Errorf("scenario %s did not return substantive repository proof", s)
	}
	for _, evidence := range proof.Evidence {
		if evidence.Scenario != s || !evidence.Passed || evidence.Check == "" {
			return fmt.Errorf("scenario %s returned invalid evidence", s)
		}
	}
	return nil
}

type ScenarioResult struct {
	Scenario Scenario      `json:"scenario"`
	Passed   bool          `json:"passed"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}
type SuiteReport struct {
	StartedAt       time.Time                     `json:"startedAt"`
	FinishedAt      time.Time                     `json:"finishedAt"`
	CleanupDuration time.Duration                 `json:"cleanupDuration"`
	Resources       vmqual.StackResourceReport    `json:"resources"`
	Sampling        vmqual.ResourceSamplingReport `json:"sampling"`
	Diagnostics     []vmqual.FailureDiagnostic    `json:"diagnostics,omitempty"`
	ProviderCleanup *ProviderCleanupObservation   `json:"providerCleanup,omitempty"`
	Scenarios       []ScenarioResult              `json:"scenarios"`
	Evidence        []Evidence                    `json:"evidence,omitempty"`
}

func (r SuiteReport) OK() bool {
	if len(r.Scenarios) != len(RequiredScenarios) {
		return false
	}
	proved := make(map[Scenario]bool, len(RequiredScenarios))
	for _, proof := range r.Evidence {
		if proof.Passed && strings.TrimSpace(proof.Check) != "" {
			proved[proof.Scenario] = true
		}
	}
	for index, s := range r.Scenarios {
		if s.Scenario != RequiredScenarios[index] || !s.Passed || !proved[s.Scenario] {
			return false
		}
	}
	return true
}
func WriteSuiteReport(w io.Writer, r SuiteReport) error { return json.NewEncoder(w).Encode(r) }
func RunSuite(c context.Context, s *vmqual.Stack, d ScenarioDriver) (r SuiteReport, e error) {
	if s == nil || d == nil {
		return r, errors.New("vmqual: stack and provider-contract driver are required")
	}
	evidenceDriver, hasEvidence := d.(ScenarioEvidence)
	if !hasEvidence {
		return r, errors.New("vmqual: scenario driver must expose state-derived evidence")
	}
	participant, participates := d.(StackParticipant)
	if !participates {
		return r, errors.New("vmqual: scenario driver must participate in the started VM stack")
	}
	r.StartedAt = time.Now().UTC()
	var sampler *vmqual.StackResourceSampler
	defer func() {
		if sampler != nil {
			samplingErr := sampler.Stop()
			r.Sampling = sampler.Report()
			productionFactory := s.Config().RequireResourceEvidence
			if e == nil && samplingErr == nil && productionFactory {
				samplingErr = r.Sampling.Validate(s.Guests())
			}
			e = errors.Join(e, samplingErr)
		}
		if e != nil {
			diagnosticCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			diagnostics, diagnosticErr := s.CollectFailureDiagnostics(diagnosticCtx)
			cancel()
			r.Diagnostics = diagnostics
			e = errors.Join(e, diagnosticErr)
		}
		cleanupStarted := time.Now()
		e = errors.Join(e, s.Cleanup(context.Background()))
		if cleanup, ok := d.(ScenarioCleanupHook); ok {
			e = errors.Join(e, cleanup.Close())
		}
		if cleanup, ok := d.(interface {
			ProviderCleanupEvidence() (ProviderCleanupObservation, bool)
		}); ok {
			if observation, exists := cleanup.ProviderCleanupEvidence(); exists {
				r.ProviderCleanup = &observation
			}
		}
		r.CleanupDuration = time.Since(cleanupStarted)
		r.Resources = s.ResourceReport()
		r.FinishedAt = time.Now().UTC()
	}()
	if e = participant.AttachStack(s); e != nil {
		return r, e
	}
	sampler, e = vmqual.StartStackResourceSampler(c, s)
	if e != nil {
		return r, e
	}
	if e = s.StartBootstrap(c); e != nil {
		return r, e
	}
	for _, x := range RequiredScenarios {
		if x == ScenarioAddRegion {
			if e = s.StartRegions(c, vmnet.SFO, vmnet.FRA); e != nil {
				return r, e
			}
		}
		st := time.Now()
		z := ScenarioResult{Scenario: x}
		firstEvidence := len(evidenceDriver.Evidence())
		if zerr := d.Run(c, x); zerr != nil {
			z.Error = boundedSuiteDiagnostic(zerr)
			e = zerr
		}
		proofs := evidenceDriver.Evidence()
		if e == nil {
			if firstEvidence >= len(proofs) {
				e = fmt.Errorf("vmqual: scenario %s returned no state-derived evidence", x)
				z.Error = boundedSuiteDiagnostic(e)
			} else {
				for _, proof := range proofs[firstEvidence:] {
					if proof.Scenario != x || !proof.Passed || strings.TrimSpace(proof.Check) == "" {
						e = fmt.Errorf("vmqual: scenario %s returned invalid evidence", x)
						z.Error = boundedSuiteDiagnostic(e)
						break
					}
				}
			}
		}
		z.Passed = z.Error == ""
		z.Duration = time.Since(st)
		r.Scenarios = append(r.Scenarios, z)
		r.Evidence = proofs
		if e != nil {
			break
		}
	}
	r.Evidence = evidenceDriver.Evidence()
	if e == nil && !r.OK() {
		e = errors.New("vmqual: suite incomplete")
	}
	return r, e
}

func boundedSuiteDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	const maximum = 4096
	diagnostic := err.Error()
	if len(diagnostic) <= maximum {
		return diagnostic
	}
	return diagnostic[:maximum-len("...[truncated]")] + "...[truncated]"
}
