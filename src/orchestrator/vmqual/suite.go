package vmqual

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"net/http/httptest"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/edge"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/objectstore"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/oci"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
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
	AttachStack(*Stack) error
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

// NewLocalProviders is a concise compatibility name for callers wiring
// vm-test's local provider contract.
func NewLocalProviders(config LocalProviderConfig) (*LocalProviderEndpoints, error) {
	return NewLocalProviderEndpoints(config)
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
	stack     *Stack
	control   *ControlContract
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

func (d *LocalScenarioDriver) AttachStack(stack *Stack) error {
	if d == nil || stack == nil {
		return errors.New("vmqual: local scenario stack is missing")
	}
	if len(stack.Guests()) != 6 {
		return errors.New("vmqual: local scenario requires six started guests")
	}
	control, err := NewControlContract(filepath.Join(stack.config.StateRoot, "control-contract"))
	if err != nil {
		return fmt.Errorf("vmqual: initialize control qualification: %w", err)
	}
	d.mu.Lock()
	d.stack = stack
	d.control = control
	d.state = scenarioState{}
	d.mu.Unlock()
	if binder, ok := stack.config.VMFactory.(interface {
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

func (d *LocalScenarioDriver) request(ctx context.Context, method, target string, body io.Reader, statuses ...int) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	wanted := false
	for _, status := range statuses {
		wanted = wanted || response.StatusCode == status
	}
	if !wanted {
		defer response.Body.Close()
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("%s returned %s: %s", target, response.Status, strings.TrimSpace(string(payload)))
	}
	return response, nil
}

func (d *LocalScenarioDriver) ociCreate(ctx context.Context, name string) error {
	body := strings.NewReader(`{"compartmentId":"ocid1.compartment.oc1.local.terrascale","displayName":"` + name + `","shape":"VM.Standard.A1.Flex","availabilityDomain":"AD-1","freeformTags":{"terrascale-managed":"true"}}`)
	response, err := d.request(ctx, http.MethodPost, d.Endpoints.OCIURL+"/20160918/instances", body, http.StatusAccepted)
	if response != nil {
		response.Body.Close()
	}
	return err
}

func (d *LocalScenarioDriver) bucket(ctx context.Context, region vmnet.RegionCode) error {
	base := d.Endpoints.ObjectURL[region]
	response, err := d.request(ctx, http.MethodPost, base+"/n/"+d.Endpoints.Object[region].Namespace()+"/b/", strings.NewReader(`{"name":"control"}`), http.StatusOK, http.StatusConflict)
	if response != nil {
		response.Body.Close()
	}
	return err
}

func (d *LocalScenarioDriver) object(ctx context.Context, region vmnet.RegionCode, name string, value []byte) error {
	base := d.Endpoints.ObjectURL[region] + "/n/" + d.Endpoints.Object[region].Namespace() + "/b/control/o/" + name
	response, err := d.request(ctx, http.MethodPut, base, bytes.NewReader(value), http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	return err
}

func (d *LocalScenarioDriver) readObject(ctx context.Context, region vmnet.RegionCode, name string) ([]byte, error) {
	base := d.Endpoints.ObjectURL[region] + "/n/" + d.Endpoints.Object[region].Namespace() + "/b/control/o/" + name
	response, err := d.request(ctx, http.MethodGet, base, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("vmqual: local object exceeds evidence bound")
	}
	return body, nil
}

func (d *LocalScenarioDriver) legacyBootstrap(ctx context.Context) error {
	before := d.Endpoints.OCI.Stats()
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	if err := d.ociCreate(ctx, "gru-member-1"); err != nil {
		return err
	}
	if err := d.ociCreate(ctx, "gru-member-2"); err != nil {
		return err
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.bucket(ctx, region); err != nil {
			return fmt.Errorf("%s bucket: %w", region, err)
		}
	}
	after := d.Endpoints.OCI.Stats()
	bucketsReady := true
	for _, store := range d.Endpoints.Object {
		bucketsReady = bucketsReady && store.Stats().Buckets == 1
	}
	return d.prove(ScenarioBootstrap, "empty-provider-gru-members", before.Resources == 0 && after.Resources == 2 && bucketsReady, fmt.Sprintf("resources=%d bucketsReady=%t", after.Resources, bucketsReady))
}

func (d *LocalScenarioDriver) legacyAddRegions(ctx context.Context) error {
	for _, region := range []vmnet.RegionCode{vmnet.SFO, vmnet.FRA} {
		for member := 1; member <= 2; member++ {
			if err := d.ociCreate(ctx, strings.ToLower(string(region))+"-member-"+fmt.Sprint(member)); err != nil {
				return fmt.Errorf("%s member %d: %w", region, member, err)
			}
		}
	}
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/instances?limit=10", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	got := d.Endpoints.OCI.Stats().Resources
	return d.prove(ScenarioAddRegion, "regional-members-observed", got == 6, fmt.Sprintf("provider resources=%d", got))
}

func (d *LocalScenarioDriver) legacyPromoteR3(ctx context.Context) error {
	value := []byte(`{"controlEpoch":3,"replicas":["GRU","SFO","FRA"],"authority":"permanent"}`)
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "control/r3.json", value); err != nil {
			return err
		}
	}
	matched := 0
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		observed, err := d.readObject(ctx, region, "control/r3.json")
		if err != nil {
			return err
		}
		if bytes.Equal(observed, value) {
			matched++
		}
	}
	return d.prove(ScenarioR3, "r3-object-replicas", matched == 3, fmt.Sprintf("matching replicas=%d", matched))
}

func (d *LocalScenarioDriver) legacyReconcile(ctx context.Context) error {
	response, err := d.request(ctx, http.MethodPost, d.Endpoints.CloudflareURL+"/zones/"+d.Endpoints.ZoneID+"/dns_records", strings.NewReader(`{"type":"A","name":"sync.terrascale.tech","content":"10.77.0.10","ttl":60,"proxied":true}`), http.StatusOK)
	if response != nil {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		if readErr != nil || !bytes.Contains(body, []byte(`"success":true`)) || !bytes.Contains(body, []byte(`"result"`)) {
			return errors.New("reconcile provider did not retain the declared DNS record")
		}
	}
	if err != nil {
		return err
	}
	response, err = d.request(ctx, http.MethodGet, d.Endpoints.CloudflareURL+"/zones/"+d.Endpoints.ZoneID+"/dns_records", nil, http.StatusOK)
	if response != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	return d.prove(ScenarioReconcile, "dns-provider-state", response != nil, "declared DNS state was returned by the provider contract")
}

func (d *LocalScenarioDriver) legacyDelivery(ctx context.Context) error {
	artifact := []byte("ts-node-release-candidate-signed-digest")
	matched := 0
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "releases/ts-node-candidate", artifact); err != nil {
			return err
		}
		observed, err := d.readObject(ctx, region, "releases/ts-node-candidate")
		if err != nil {
			return err
		}
		if bytes.Equal(observed, artifact) {
			matched++
		}
	}
	return d.prove(ScenarioSignedDelivery, "artifact-object-replicas", matched == 3, fmt.Sprintf("matching replicas=%d", matched))
}

func (d *LocalScenarioDriver) legacyRollback(ctx context.Context) error {
	artifact := []byte("ts-node-release-v1-prior-digest")
	matched := 0
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "releases/ts-node-current", artifact); err != nil {
			return err
		}
		observed, err := d.readObject(ctx, region, "releases/ts-node-current")
		if err != nil {
			return err
		}
		if bytes.Equal(observed, artifact) {
			matched++
		}
	}
	return d.prove(ScenarioRollback, "prior-object-replicas", matched == 3, fmt.Sprintf("matching replicas=%d", matched))
}

func (d *LocalScenarioDriver) legacyEdgeProof(ctx context.Context) error {
	now := time.Now().UTC()
	capability, err := edge.MintCapability(d.Endpoints.edgeKey, "vmqual", 1, "rule:v1", 1, "GRU", now)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.Endpoints.EdgeURL+"/api/v1/reactive/views/vmqual/1/log?offset=0", nil)
	if err != nil {
		return err
	}
	request.Header.Set(edge.CapabilityHeader, capability)
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("edge promotion returned %s", response.Status)
	}
	metrics := d.Endpoints.Edge.Metrics()
	return d.prove(ScenarioEdge, "capability-before-cache", metrics.CacheableResponses > 0, fmt.Sprintf("cacheable responses=%d", metrics.CacheableResponses))
}

func (d *LocalScenarioDriver) legacyEstate(ctx context.Context) error {
	response, err := d.request(ctx, http.MethodPost, d.Endpoints.CloudflareURL+"/accounts/"+d.Endpoints.AccountID+"/secrets_store/stores", strings.NewReader(`{"name":"qualification"}`), http.StatusOK, http.StatusConflict)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	return d.prove(ScenarioEstate, "provider-backed-estate-state", response != nil, "estate backing resource was returned by the provider contract")
}

func (d *LocalScenarioDriver) legacySelfHeal(ctx context.Context) error {
	d.Endpoints.OCI.SetFaultScript([]oci.FaultRule{{Method: http.MethodGet, Path: "/20160918/availabilityDomains", Kind: oci.FaultResponse, Status: http.StatusServiceUnavailable, Count: 1}})
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusServiceUnavailable)
	faultObserved := response != nil && response.StatusCode == http.StatusServiceUnavailable
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.Endpoints.OCI.ClearFaults()
	response, err = d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusOK)
	recovered := response != nil && response.StatusCode == http.StatusOK
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	return d.prove(ScenarioSelfHeal, "provider-fault-recovery", faultObserved && recovered, fmt.Sprintf("faultObserved=%t recovered=%t", faultObserved, recovered))
}

func (d *LocalScenarioDriver) legacyKeyRotation(ctx context.Context) error {
	response, err := d.request(ctx, http.MethodPut, d.Endpoints.CloudflareURL+"/accounts/"+d.Endpoints.AccountID+"/secrets_store/stores/qualification/secrets/capability", strings.NewReader(`{"name":"capability","value":"rotated"}`), http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	return d.prove(ScenarioKeyRotation, "overlap-secret-write", response != nil && response.StatusCode == http.StatusOK, "provider accepted the bounded overlap write")
}

func (d *LocalScenarioDriver) legacyRestore(ctx context.Context) error {
	value := []byte(`{"restore":"snapshot-1","placement":"br-only","epoch":3}`)
	if err := d.object(ctx, vmnet.GRU, "restore/qualification.json", value); err != nil {
		return err
	}
	observed, err := d.readObject(ctx, vmnet.GRU, "restore/qualification.json")
	if err != nil {
		return err
	}
	return d.prove(ScenarioRestore, "snapshot-readback", bytes.Equal(observed, value), fmt.Sprintf("bytes=%d", len(observed)))
}

func (d *LocalScenarioDriver) legacyDegraded(ctx context.Context) error {
	// Closing a provider endpoint must not affect an already-admitted local
	// edge read. The edge handler has no provider dependency by design.
	d.Endpoints.Edge.SetOriginError(nil)
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	return d.prove(ScenarioDegraded, "admitted-data-path", response != nil && response.StatusCode == http.StatusOK, "admitted request remained available")
}

func (d *LocalScenarioDriver) legacyPartition(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The vmnet controller proves actual link partitioning; this provider proof
	// records that each local Region endpoint remains independently reachable.
	reachable := 0
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		response, err := d.request(ctx, http.MethodGet, d.Endpoints.ObjectURL[region]+"/n/"+d.Endpoints.Object[region].Namespace()+"/b/", nil, http.StatusOK)
		if response != nil {
			response.Body.Close()
		}
		if err != nil {
			return err
		}
		reachable++
	}
	return d.prove(ScenarioPartition, "regional-autonomy", reachable == 3, fmt.Sprintf("reachable stores=%d", reachable))
}

func (d *LocalScenarioDriver) legacyPlacement(ctx context.Context) error {
	value := []byte(`{"placementLock":"br-only","regions":["GRU"],"immutable":true}`)
	if err := d.object(ctx, vmnet.GRU, "placement/lock.json", value); err != nil {
		return err
	}
	observed, err := d.readObject(ctx, vmnet.GRU, "placement/lock.json")
	if err != nil {
		return err
	}
	return d.prove(ScenarioPlacement, "residency-lock", bytes.Equal(observed, value), fmt.Sprintf("bytes=%d", len(observed)))
}

func (d *LocalScenarioDriver) legacyCleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return d.Endpoints.Close()
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
	StartedAt       time.Time                   `json:"startedAt"`
	FinishedAt      time.Time                   `json:"finishedAt"`
	CleanupDuration time.Duration               `json:"cleanupDuration"`
	Resources       StackResourceReport         `json:"resources"`
	Sampling        ResourceSamplingReport      `json:"sampling"`
	Diagnostics     []FailureDiagnostic         `json:"diagnostics,omitempty"`
	ProviderCleanup *ProviderCleanupObservation `json:"providerCleanup,omitempty"`
	Scenarios       []ScenarioResult            `json:"scenarios"`
	Evidence        []Evidence                  `json:"evidence,omitempty"`
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
func RunSuite(c context.Context, s *Stack, d ScenarioDriver) (r SuiteReport, e error) {
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
	var sampler *stackResourceSampler
	defer func() {
		if sampler != nil {
			samplingErr := sampler.Stop()
			r.Sampling = sampler.Report()
			_, productionFactory := s.config.VMFactory.(*firecrackerFactory)
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
	sampler, e = startStackResourceSampler(c, s)
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
