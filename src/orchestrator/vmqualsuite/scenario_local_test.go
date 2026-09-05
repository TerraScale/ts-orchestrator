package vmqualsuite

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type scenarioTestVM struct {
	guest   vmqual.Guest
	owner   *scenarioTestFactory
	running bool
	stopped bool
	deleted bool
}

func (v *scenarioTestVM) StartReady(ctx context.Context) error {
	v.owner.mu.Lock()
	v.owner.starts++
	shouldCancel := v.owner.cancelOnStart != 0 && v.owner.starts == v.owner.cancelOnStart
	cancel := v.owner.cancel
	failStart := v.guest.ID == v.owner.failStartID
	if !shouldCancel && !failStart {
		v.running = true
	}
	v.owner.mu.Unlock()
	if failStart {
		return errors.New("local orchestrator unavailable")
	}
	if shouldCancel {
		cancel()
		return context.Canceled
	}
	return ctx.Err()
}

func (v *scenarioTestVM) Stop(context.Context) error {
	v.owner.mu.Lock()
	v.running = false
	v.stopped = true
	v.owner.mu.Unlock()
	return nil
}

func (v *scenarioTestVM) Delete(context.Context) error {
	v.owner.mu.Lock()
	v.deleted = true
	v.owner.mu.Unlock()
	return nil
}

func (v *scenarioTestVM) Inspect(context.Context) (vmqual.VMObservation, error) {
	v.owner.mu.Lock()
	defer v.owner.mu.Unlock()
	return vmqual.VMObservation{ID: v.guest.ID, Region: v.guest.Region, Running: v.running, Ready: v.running, MemoryMiB: v.guest.MemoryMiB}, nil
}

func TestHTTPScenarioDriverRejectsUnstructuredSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	if err := (HTTPScenarioDriver{BaseURL: server.URL}).Run(context.Background(), ScenarioBootstrap); err == nil {
		t.Fatal("accepted an unstructured 204 as qualification proof")
	}
}

func TestHTTPScenarioDriverRequiresMatchingEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"scenario":"bootstrap","passed":true,"evidence":[]}`))
	}))
	defer server.Close()
	if err := (HTTPScenarioDriver{BaseURL: server.URL}).Run(context.Background(), ScenarioBootstrap); err == nil {
		t.Fatal("accepted a proof without substantive evidence")
	}
}

type scenarioTestFactory struct {
	faultContractFactory

	mu                  sync.Mutex
	vms                 map[string]*scenarioTestVM
	createOrder         []string
	starts              int
	cancelOnStart       int
	failStartID         string
	cancel              context.CancelFunc
	activeDigest        map[string]string
	cordoned            map[string]bool
	persistentData      []byte
	badDeliveryEvidence bool
}

func newScenarioTestFactory() *scenarioTestFactory {
	return &scenarioTestFactory{
		vms:          make(map[string]*scenarioTestVM),
		activeDigest: make(map[string]string),
		cordoned:     make(map[string]bool),
	}
}

func (f *scenarioTestFactory) Create(_ context.Context, guest vmqual.Guest) (vmqual.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	vm := &scenarioTestVM{guest: guest, owner: f}
	f.vms[guest.ID] = vm
	f.createOrder = append(f.createOrder, guest.ID)
	return vm, nil
}

func (f *scenarioTestFactory) Cordon(_ context.Context, host string, cordoned bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cordoned[host] = cordoned
	return nil
}

func (f *scenarioTestFactory) DrainStatus(_ context.Context, host string) (delivery.DrainReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return delivery.DrainReport{Cordoned: f.cordoned[host], Drained: f.cordoned[host]}, nil
}

func (f *scenarioTestFactory) Converge(_ context.Context, host string, plan []byte) error {
	digest, err := digestFromDeliveryPlan(plan)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.activeDigest[host] = digest
	f.mu.Unlock()
	return nil
}

func (f *scenarioTestFactory) QualifyTSNode(_ context.Context, host string, qualification vmqual.TSNodeGuestQualification) (vmqual.TSNodeGuestObservation, error) {
	native := "linux/" + runtime.GOARCH
	candidate, ok := qualification.Candidates[native]
	if !ok {
		return vmqual.TSNodeGuestObservation{}, errors.New("test guest architecture is not in the delivery manifest")
	}
	observation := vmqual.TSNodeGuestObservation{
		Host:                    host,
		NativeArchitecture:      native,
		InstalledDigest:         candidate.Identity.Digest,
		ActiveDigest:            candidate.Identity.Digest,
		SystemdUnit:             qualification.ExpectedSystemdUnit,
		PersistentBeforeRestart: append([]byte(nil), qualification.PersistenceSentinel...),
		PersistentAfterRestart:  append([]byte(nil), qualification.PersistenceSentinel...),
		InstallAttempts: []vmqual.TSNodeInstallAttempt{
			{Name: "candidate", Architecture: native, Digest: candidate.Identity.Digest, Accepted: true},
			{Name: "bad-signature", Architecture: native, Digest: qualification.BadSignature[native].Identity.Digest, Accepted: false},
			{Name: "bad-digest", Architecture: native, Digest: qualification.BadDigest[native].Identity.Digest, Accepted: false},
		},
	}
	f.mu.Lock()
	f.activeDigest[host] = candidate.Identity.Digest
	f.persistentData = append([]byte(nil), qualification.PersistenceSentinel...)
	bad := f.badDeliveryEvidence
	f.mu.Unlock()
	if bad {
		observation.SystemdUnit += "\n# altered"
	}
	return observation, nil
}

func (*scenarioTestFactory) CheckDeliveryGate(_ context.Context, host, digest, gate string) (vmqual.DeliveryGuestGateObservation, error) {
	return vmqual.DeliveryGuestGateObservation{Host: host, Digest: digest, Gate: gate, Passed: true}, nil
}

func (f *scenarioTestFactory) ObserveDeliveryGuest(_ context.Context, host string) (vmqual.DeliveryGuestObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return vmqual.DeliveryGuestObservation{
		Host:           host,
		ActiveDigest:   f.activeDigest[host],
		Cordoned:       f.cordoned[host],
		UnitActive:     f.activeDigest[host] != "",
		PersistentData: append([]byte(nil), f.persistentData...),
	}, nil
}

type scenarioTestNetwork struct {
	plan vmnet.NetworkPlan
	faultContractNetwork
	mu      sync.Mutex
	applied bool
	cleaned bool
}

func (n *scenarioTestNetwork) Apply(context.Context) error {
	n.mu.Lock()
	n.applied = true
	n.cleaned = false
	n.mu.Unlock()
	return nil
}

func (n *scenarioTestNetwork) Plan() vmnet.NetworkPlan { return n.plan }
func (n *scenarioTestNetwork) Journal() vmnet.Journal  { return n.plan.Journal }

func (n *scenarioTestNetwork) Cleanup(context.Context) error {
	n.mu.Lock()
	n.applied = false
	n.cleaned = true
	n.mu.Unlock()
	return nil
}

func newScenarioHarness(t *testing.T, factory *scenarioTestFactory, network *scenarioTestNetwork) (*LocalProviderEndpoints, *LocalScenarioDriver, *vmqual.Stack) {
	t.Helper()
	stateRoot := t.TempDir()
	networkConfig := vmnet.DefaultConfig()
	networkConfig.RunID = "abcdef0123456789abcdef0123456789"
	networkConfig.CoordinationRoot = filepath.Join(stateRoot, "network-locks")
	toolsRoot := t.TempDir()
	toolPaths := map[string]string{}
	for _, name := range []string{"ip", "nft", "tc", "sysctl"} {
		path := filepath.Join(toolsRoot, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		toolPaths[name] = path
	}
	networkConfig.Tools = vmnet.ToolPaths{IP: toolPaths["ip"], NFT: toolPaths["nft"], TC: toolPaths["tc"], Sysctl: toolPaths["sysctl"]}
	networkConfig.Regions = append(networkConfig.Regions, vmnet.RegionSpec{Code: vmqual.FourthRegion, Guests: []vmnet.GuestSpec{{ID: "iad-member-1"}, {ID: "iad-member-2"}}})
	plan, err := vmnet.Plan(networkConfig)
	if err != nil {
		t.Fatal(err)
	}
	network.plan = plan
	providers, err := NewLocalProviderEndpoints(LocalProviderConfig{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := providers.LocalScenarioDriver()
	if err != nil {
		providers.Close()
		t.Fatal(err)
	}
	stack, err := vmqual.NewStack(vmqual.StackConfig{
		Guests:      vmqual.LaunchGuests(256),
		VMFactory:   factory,
		Network:     network,
		StateRoot:   stateRoot,
		JournalPath: filepath.Join(stateRoot, "cleanup.json"),
	})
	if err != nil {
		providers.Close()
		t.Fatal(err)
	}
	return providers, driver, stack
}

func assertScenarioResourcesClean(t *testing.T, providers *LocalProviderEndpoints, factory *scenarioTestFactory, network *scenarioTestNetwork) {
	t.Helper()
	if !providers.Closed() {
		t.Fatal("provider endpoints remain open")
	}
	network.mu.Lock()
	cleaned, applied := network.cleaned, network.applied
	network.mu.Unlock()
	if !cleaned || applied {
		t.Fatalf("network cleanup state cleaned=%t applied=%t", cleaned, applied)
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	for id, vm := range factory.vms {
		if vm.running || !vm.stopped || !vm.deleted {
			t.Fatalf("VM %s cleanup state running=%t stopped=%t deleted=%t", id, vm.running, vm.stopped, vm.deleted)
		}
	}
}

func TestLocalScenarioJourneyUsesAllProviderEndpoints(t *testing.T) {
	factory := newScenarioTestFactory()
	network := &scenarioTestNetwork{}
	providers, driver, stack := newScenarioHarness(t, factory, network)
	report, err := RunSuite(context.Background(), stack, driver)
	if err != nil {
		t.Fatalf("local suite failed: %v\nreport=%+v\nevidence=%+v", err, report, driver.Evidence())
	}
	if !report.OK() || len(driver.Completed()) != len(RequiredScenarios) {
		t.Fatalf("report not complete: ok=%v completed=%v", report.OK(), driver.Completed())
	}
	if len(driver.Evidence()) < len(RequiredScenarios) {
		t.Fatalf("evidence count=%d", len(driver.Evidence()))
	}
	checks := make(map[Scenario]map[string]bool)
	for _, proof := range driver.Evidence() {
		if checks[proof.Scenario] == nil {
			checks[proof.Scenario] = make(map[string]bool)
		}
		checks[proof.Scenario][proof.Check] = proof.Passed
	}
	for _, scenario := range RequiredScenarios {
		if len(checks[scenario]) == 0 {
			t.Errorf("scenario %s has no named evidence", scenario)
		}
		for check, passed := range checks[scenario] {
			if check == "" || !passed {
				t.Errorf("scenario %s invalid evidence %q passed=%t", scenario, check, passed)
			}
		}
	}
	factory.mu.Lock()
	createOrder := append([]string(nil), factory.createOrder...)
	factory.mu.Unlock()
	wantFirst := []string{"gru-member-1", "gru-member-2"}
	if len(createOrder) != 8 || createOrder[0] != wantFirst[0] || createOrder[1] != wantFirst[1] {
		t.Fatalf("VM startup was not GRU-first: %v", createOrder)
	}
	assertScenarioResourcesClean(t, providers, factory, network)
}

func TestRunSuiteCleansAfterCancellation(t *testing.T) {
	factory := newScenarioTestFactory()
	network := &scenarioTestNetwork{}
	providers, driver, stack := newScenarioHarness(t, factory, network)
	ctx, cancel := context.WithCancel(context.Background())
	factory.cancelOnStart = 1
	factory.cancel = cancel
	defer cancel()
	if _, err := RunSuite(ctx, stack, driver); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunSuite cancellation error = %v", err)
	}
	assertScenarioResourcesClean(t, providers, factory, network)
}

func TestRunSuiteCleansAfterFailedScenarioAssertion(t *testing.T) {
	factory := newScenarioTestFactory()
	factory.badDeliveryEvidence = true
	network := &scenarioTestNetwork{}
	providers, driver, stack := newScenarioHarness(t, factory, network)
	report, err := RunSuite(context.Background(), stack, driver)
	if err == nil {
		t.Fatal("RunSuite accepted altered guest delivery evidence")
	}
	if len(report.Scenarios) == 0 || report.Scenarios[len(report.Scenarios)-1].Scenario != ScenarioSignedDelivery || report.Scenarios[len(report.Scenarios)-1].Passed {
		t.Fatalf("failed scenario report = %+v", report.Scenarios)
	}
	assertScenarioResourcesClean(t, providers, factory, network)
}

type noEvidenceScenarioDriver struct{}

func (noEvidenceScenarioDriver) Run(context.Context, Scenario) error { return nil }
func (noEvidenceScenarioDriver) Evidence() []Evidence                { return nil }
func (noEvidenceScenarioDriver) AttachStack(*vmqual.Stack) error     { return nil }

func TestRunSuiteRejectsMissingScenarioEvidence(t *testing.T) {
	factory := newScenarioTestFactory()
	network := &scenarioTestNetwork{}
	stateRoot := t.TempDir()
	stack, err := vmqual.NewStack(vmqual.StackConfig{
		Guests:      vmqual.LaunchGuests(256),
		VMFactory:   factory,
		Network:     network,
		StateRoot:   stateRoot,
		JournalPath: filepath.Join(stateRoot, "cleanup.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunSuite(context.Background(), stack, noEvidenceScenarioDriver{}); err == nil {
		t.Fatal("RunSuite accepted a driver without scenario evidence")
	}
	// This driver owns no provider fixture; stack cleanup must still run.
	network.mu.Lock()
	cleaned := network.cleaned
	network.mu.Unlock()
	if !cleaned {
		t.Fatal("stack was not cleaned after missing evidence")
	}
}

type lifecycleOnlyScenarioFactory struct{}

func (lifecycleOnlyScenarioFactory) Create(_ context.Context, guest vmqual.Guest) (vmqual.VM, error) {
	owner := newScenarioTestFactory()
	return &scenarioTestVM{guest: guest, owner: owner, running: true}, nil
}

func TestLocalScenarioDriverRejectsMissingDeliveryCapability(t *testing.T) {
	stateRoot := t.TempDir()
	providers, err := NewLocalProviderEndpoints(LocalProviderConfig{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	driver, err := providers.LocalScenarioDriver()
	if err != nil {
		t.Fatal(err)
	}
	stack, err := vmqual.NewStack(vmqual.StackConfig{Guests: vmqual.LaunchGuests(256), VMFactory: lifecycleOnlyScenarioFactory{}, Network: &scenarioTestNetwork{}, StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.AttachStack(stack); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.deliveryProof(context.Background()); err == nil {
		t.Fatal("delivery proof accepted a lifecycle-only VM factory")
	}
}

func TestLocalScenarioDriverRejectsOutOfOrderProof(t *testing.T) {
	providers, err := NewLocalProviderEndpoints(LocalProviderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	driver, err := providers.LocalScenarioDriver()
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Run(context.Background(), ScenarioR3); err == nil {
		t.Fatal("out-of-order R3 was accepted")
	}
	if got := driver.Completed(); len(got) != 0 {
		t.Fatalf("completed after rejected scenario = %v", got)
	}
	if got := vmnet.StableCIDR(vmnet.GRU); got == "" {
		t.Fatal("GRU topology is not configured")
	}
}

func TestFourthRegionRequiresBothNewGuestsBeforeReportingSuccess(t *testing.T) {
	factory := newScenarioTestFactory()
	factory.failStartID = "iad-member-2"
	network := &scenarioTestNetwork{}
	providers, driver, stack := newScenarioHarness(t, factory, network)
	report, err := RunSuite(context.Background(), stack, driver)
	if err == nil || len(report.Scenarios) != 4 || report.Scenarios[3].Scenario != ScenarioFourthRegion || report.Scenarios[3].Passed {
		t.Fatalf("fourth region falsely admitted: %+v, %v", report.Scenarios, err)
	}
	for _, proof := range report.Evidence {
		if proof.Check == "two-live-fourth-region-members-with-local-orchestrators" && proof.Passed {
			t.Fatal("provider-only admission became live-host evidence")
		}
	}
	if len(factory.createOrder) != 8 {
		t.Fatalf("both new host attempts were not made: %v", factory.createOrder)
	}
	assertScenarioResourcesClean(t, providers, factory, network)
}
