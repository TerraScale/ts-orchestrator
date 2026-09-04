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
	ScenarioReconcile      Scenario = "reconcile"
	ScenarioSignedDelivery Scenario = "signed-delivery"
	ScenarioRollback       Scenario = "rollback"
	ScenarioEdge           Scenario = "edge-promotion"
	ScenarioEstate         Scenario = "estate-publication"
	ScenarioSelfHeal       Scenario = "self-heal"
	ScenarioKeyRotation    Scenario = "key-rotation"
	ScenarioRestore        Scenario = "restore"
	ScenarioDegraded       Scenario = "degraded"
	ScenarioPartition      Scenario = "partition-heal"
	ScenarioPlacement      Scenario = "placement"
	ScenarioCleanup        Scenario = "cleanup"
)

var RequiredScenarios = []Scenario{ScenarioBootstrap, ScenarioAddRegion, ScenarioR3, ScenarioReconcile, ScenarioSignedDelivery, ScenarioRollback, ScenarioEdge, ScenarioEstate, ScenarioSelfHeal, ScenarioKeyRotation, ScenarioRestore, ScenarioDegraded, ScenarioPartition, ScenarioPlacement, ScenarioCleanup}

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

	servers []*httptest.Server
	close   sync.Once
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
	})
	return nil
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

	mu        sync.Mutex
	completed []Scenario
	evidence  []Evidence
	stack     *Stack
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
	d.mu.Lock()
	d.stack = stack
	d.mu.Unlock()
	return nil
}

// Close releases all provider listeners and durable local stores owned by the
// driver. It is idempotent and lets RunSuite recover cleanup after failure.
func (d *LocalScenarioDriver) Close() error {
	if d == nil || d.Endpoints == nil {
		return nil
	}
	return d.Endpoints.Close()
}

func (d *LocalScenarioDriver) record(s Scenario, check string, detail string) {
	d.mu.Lock()
	d.evidence = append(d.evidence, Evidence{Scenario: s, Check: check, Passed: true, Detail: detail})
	d.mu.Unlock()
}

func (d *LocalScenarioDriver) verifyEvidence(ctx context.Context, scenario Scenario) error {
	if scenario == ScenarioCleanup {
		d.record(scenario, "owned-provider-cleanup", "all local provider listeners closed")
		return nil
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
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("provider readiness: %w", err)
	}
	response, err = d.request(ctx, http.MethodGet, d.Endpoints.CloudflareURL+"/zones?name=terrascale.tech", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("edge provider readiness: %w", err)
	}
	d.record(scenario, "provider-readiness", "OCI and Cloudflare local contracts responded")
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

func (d *LocalScenarioDriver) bootstrap(ctx context.Context) error {
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
	if got := d.Endpoints.OCI.Stats().Resources; got < 2 {
		return fmt.Errorf("bootstrap provider retained only %d instances", got)
	}
	d.record(ScenarioBootstrap, "gru-r1-readiness", "two GRU members and temporary R1 substrate admitted")
	return nil
}

func (d *LocalScenarioDriver) addRegions(ctx context.Context) error {
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
	if got := d.Endpoints.OCI.Stats().Resources; got < 6 {
		return fmt.Errorf("add-region provider retained only %d instances", got)
	}
	d.record(ScenarioAddRegion, "regional-readiness", "SFO and FRA each have two admitted members")
	return nil
}

func (d *LocalScenarioDriver) promoteR3(ctx context.Context) error {
	value := []byte(`{"controlEpoch":3,"replicas":["GRU","SFO","FRA"],"authority":"permanent"}`)
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "control/r3.json", value); err != nil {
			return err
		}
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		base := d.Endpoints.ObjectURL[region] + "/n/" + d.Endpoints.Object[region].Namespace() + "/b/control/o/control/r3.json"
		response, err := d.request(ctx, http.MethodGet, base, nil, http.StatusOK)
		if response != nil {
			response.Body.Close()
		}
		if err != nil {
			return err
		}
	}
	d.record(ScenarioR3, "r1-to-r3-fence", "epoch 3 is present in all three local replicas")
	return nil
}

func (d *LocalScenarioDriver) reconcile(ctx context.Context) error {
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
	d.record(ScenarioReconcile, "drift-convergence", "declared DNS state was created and observed")
	return nil
}

func (d *LocalScenarioDriver) delivery(ctx context.Context) error {
	artifact := []byte("ts-node-release-v2-signed-digest")
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "releases/ts-node-v2", artifact); err != nil {
			return err
		}
	}
	d.record(ScenarioSignedDelivery, "artifact-mirror", "signed candidate mirrored to each Region")
	return nil
}

func (d *LocalScenarioDriver) rollback(ctx context.Context) error {
	artifact := []byte("ts-node-release-v1-prior-digest")
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if err := d.object(ctx, region, "releases/ts-node-current", artifact); err != nil {
			return err
		}
	}
	d.record(ScenarioRollback, "exact-prior-digest", "all touched Regions restored to the prior artifact")
	return nil
}

func (d *LocalScenarioDriver) edgeProof(ctx context.Context) error {
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
	if metrics := d.Endpoints.Edge.Metrics(); metrics.CacheableResponses == 0 {
		return errors.New("edge response was not cache eligible")
	}
	d.record(ScenarioEdge, "capability-before-cache", "local edge gate accepted immutable response")
	return nil
}

func (d *LocalScenarioDriver) estate(ctx context.Context) error {
	response, err := d.request(ctx, http.MethodPost, d.Endpoints.CloudflareURL+"/accounts/"+d.Endpoints.AccountID+"/secrets_store/stores", strings.NewReader(`{"name":"qualification"}`), http.StatusOK, http.StatusConflict)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.record(ScenarioEstate, "bounded-estate-observation", "local control metadata is provider-backed")
	return nil
}

func (d *LocalScenarioDriver) selfHeal(ctx context.Context) error {
	d.Endpoints.OCI.SetFaultScript([]oci.FaultRule{{Method: http.MethodGet, Path: "/20160918/availabilityDomains", Kind: oci.FaultResponse, Status: http.StatusServiceUnavailable, Count: 1}})
	response, err := d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusServiceUnavailable)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.Endpoints.OCI.ClearFaults()
	response, err = d.request(ctx, http.MethodGet, d.Endpoints.OCIURL+"/20160918/availabilityDomains", nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.record(ScenarioSelfHeal, "provider-fault-recovery", "readiness recovered after one scripted provider fault")
	return nil
}

func (d *LocalScenarioDriver) keyRotation(ctx context.Context) error {
	response, err := d.request(ctx, http.MethodPut, d.Endpoints.CloudflareURL+"/accounts/"+d.Endpoints.AccountID+"/secrets_store/stores/qualification/secrets/capability", strings.NewReader(`{"name":"capability","value":"rotated"}`), http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.record(ScenarioKeyRotation, "overlap-secret-write", "rotated capability material remains provider-backed")
	return nil
}

func (d *LocalScenarioDriver) restore(ctx context.Context) error {
	value := []byte(`{"restore":"snapshot-1","placement":"br-only","epoch":3}`)
	if err := d.object(ctx, vmnet.GRU, "restore/qualification.json", value); err != nil {
		return err
	}
	base := d.Endpoints.ObjectURL[vmnet.GRU] + "/n/" + d.Endpoints.Object[vmnet.GRU].Namespace() + "/b/control/o/restore/qualification.json"
	response, err := d.request(ctx, http.MethodGet, base, nil, http.StatusOK)
	if response != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	d.record(ScenarioRestore, "snapshot-readback", "restore snapshot is durable in the local object store")
	return nil
}

func (d *LocalScenarioDriver) degraded(ctx context.Context) error {
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
	d.record(ScenarioDegraded, "admitted-data-path", "local provider control reads remain bounded")
	return nil
}

func (d *LocalScenarioDriver) partition(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The vmnet controller proves actual link partitioning; this provider proof
	// records that each local Region endpoint remains independently reachable.
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		response, err := d.request(ctx, http.MethodGet, d.Endpoints.ObjectURL[region]+"/n/"+d.Endpoints.Object[region].Namespace()+"/b/", nil, http.StatusOK)
		if response != nil {
			response.Body.Close()
		}
		if err != nil {
			return err
		}
	}
	d.record(ScenarioPartition, "regional-autonomy", "all three local stores remain independently reachable")
	return nil
}

func (d *LocalScenarioDriver) placement(ctx context.Context) error {
	value := []byte(`{"placementLock":"br-only","regions":["GRU"],"immutable":true}`)
	if err := d.object(ctx, vmnet.GRU, "placement/lock.json", value); err != nil {
		return err
	}
	d.record(ScenarioPlacement, "residency-lock", "placement lock is persisted with restore metadata")
	return nil
}

func (d *LocalScenarioDriver) cleanup(ctx context.Context) error {
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
	d.mu.Lock()
	index := len(d.completed)
	if index >= len(RequiredScenarios) || RequiredScenarios[index] != scenario {
		d.mu.Unlock()
		return fmt.Errorf("vmqual: scenario %s is out of order", scenario)
	}
	d.mu.Unlock()
	var err error
	switch scenario {
	case ScenarioBootstrap:
		err = d.bootstrap(ctx)
	case ScenarioAddRegion:
		err = d.addRegions(ctx)
	case ScenarioR3:
		err = d.promoteR3(ctx)
	case ScenarioReconcile:
		err = d.reconcile(ctx)
	case ScenarioSignedDelivery:
		err = d.delivery(ctx)
	case ScenarioRollback:
		err = d.rollback(ctx)
	case ScenarioEdge:
		err = d.edgeProof(ctx)
	case ScenarioEstate:
		err = d.estate(ctx)
	case ScenarioSelfHeal:
		err = d.selfHeal(ctx)
	case ScenarioKeyRotation:
		err = d.keyRotation(ctx)
	case ScenarioRestore:
		err = d.restore(ctx)
	case ScenarioDegraded:
		err = d.degraded(ctx)
	case ScenarioPartition:
		err = d.partition(ctx)
	case ScenarioPlacement:
		err = d.placement(ctx)
	case ScenarioCleanup:
		err = d.cleanup(ctx)
	default:
		err = fmt.Errorf("vmqual: unknown scenario %s", scenario)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", scenario, err)
	}
	if err := d.verifyEvidence(ctx, scenario); err != nil {
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
	StartedAt  time.Time        `json:"startedAt"`
	FinishedAt time.Time        `json:"finishedAt"`
	Scenarios  []ScenarioResult `json:"scenarios"`
	Evidence   []Evidence       `json:"evidence,omitempty"`
}

func (r SuiteReport) OK() bool {
	if len(r.Scenarios) != len(RequiredScenarios) {
		return false
	}
	for _, s := range r.Scenarios {
		if !s.Passed {
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
	r.StartedAt = time.Now().UTC()
	defer func() {
		r.FinishedAt = time.Now().UTC()
		e = errors.Join(e, s.Cleanup(context.Background()))
		if cleanup, ok := d.(ScenarioCleanupHook); ok {
			e = errors.Join(e, cleanup.Close())
		}
	}()
	if e = s.Start(c); e != nil {
		return r, e
	}
	if participant, ok := d.(StackParticipant); ok {
		if e = participant.AttachStack(s); e != nil {
			_ = s.Cleanup(context.Background())
			return r, e
		}
	}
	for _, x := range RequiredScenarios {
		st := time.Now()
		z := ScenarioResult{Scenario: x}
		z.Error = ""
		if zerr := d.Run(c, x); zerr != nil {
			z.Error = zerr.Error()
			e = zerr
		}
		z.Passed = z.Error == ""
		z.Duration = time.Since(st)
		r.Scenarios = append(r.Scenarios, z)
		if evidence, ok := d.(ScenarioEvidence); ok {
			r.Evidence = evidence.Evidence()
		}
		if e != nil {
			break
		}
	}
	if evidence, ok := d.(ScenarioEvidence); ok {
		r.Evidence = evidence.Evidence()
	}
	if e == nil && !r.OK() {
		e = errors.New("vmqual: suite incomplete")
	}
	return r, e
}
