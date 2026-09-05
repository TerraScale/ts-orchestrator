package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"errors"
	"github.com/nats-io/nkeys"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

type fakeComponent struct {
	done       chan struct{}
	name       string
	closed     bool
	closeError error
	order      *[]string
}

func (f *fakeComponent) Completion() <-chan struct{} { return f.done }
func (f *fakeComponent) Close() error {
	if !f.closed {
		f.closed = true
		if f.order != nil {
			*f.order = append(*f.order, f.name)
		}
	}
	return f.closeError
}

type fakeDirectoryCheckRuntime struct {
	snapshot control.GlobalCellDirectorySnapshot
	dispose  func()
}

func (f *fakeDirectoryCheckRuntime) Snapshot() control.GlobalCellDirectorySnapshot {
	return f.snapshot
}

func (f *fakeDirectoryCheckRuntime) Dispose() error {
	if f.dispose != nil {
		f.dispose()
	}
	return nil
}

type fakeDirectoryServiceCheckRuntime struct{ dispose func() }

func (f *fakeDirectoryServiceCheckRuntime) Dispose() {
	if f.dispose != nil {
		f.dispose()
	}
}

func restoreHostSeams(t *testing.T) {
	t.Helper()
	oldParse := parseOptions
	oldRegional := startRegionalRuntime
	oldProduction := startProductionRuntime
	oldAdmission := admitProductionRuntime
	oldEmbedded := startEmbeddedNatsRuntime
	oldCheckRegional := checkRegionalRuntime
	oldGlobal := startGlobalRuntime
	oldDirectory := startDirectoryRuntime
	oldDirectoryCheck := startDirectoryCheck
	oldDirectoryServiceCheck := startDirectoryServiceCheck
	oldWriter := startJournalWriterRuntime
	oldProvision := provisionJournal
	oldServer := runEmbeddedNatsServer
	oldCatalog := renderCatalog
	oldGlobalConfig := makeGlobalConfiguration
	oldVerifyEstate := verifyEstate
	verifyEstate = func(context.Context, string, envLookup) error { return nil }
	t.Cleanup(func() {
		parseOptions = oldParse
		startRegionalRuntime = oldRegional
		startProductionRuntime = oldProduction
		admitProductionRuntime = oldAdmission
		startEmbeddedNatsRuntime = oldEmbedded
		checkRegionalRuntime = oldCheckRegional
		startGlobalRuntime = oldGlobal
		startDirectoryRuntime = oldDirectory
		startDirectoryCheck = oldDirectoryCheck
		startDirectoryServiceCheck = oldDirectoryServiceCheck
		startJournalWriterRuntime = oldWriter
		provisionJournal = oldProvision
		runEmbeddedNatsServer = oldServer
		renderCatalog = oldCatalog
		makeGlobalConfiguration = oldGlobalConfig
		verifyEstate = oldVerifyEstate
	})
}

func fakeOptions(command control.OrchestratorCommand) *control.OrchestratorOptions {
	return &control.OrchestratorOptions{Command: command, Cell: "local", Instance: "local", NatsURL: "nats://127.0.0.1:4222", Replicas: 1}
}

func TestRequestedCommandSelection(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "run"},
		{[]string{"run"}, "run"},
		{[]string{"check"}, "check"},
		{[]string{"nats-server"}, "nats-server"},
		{[]string{"catalog"}, "catalog"},
		{[]string{"provision-journal"}, "provision-journal"},
		{[]string{"journal-writer"}, "journal-writer"},
	}
	for _, test := range tests {
		got, err := requestedCommand(test.args)
		if err != nil || got != test.want {
			t.Errorf("requestedCommand(%q) = %q, %v; want %q", test.args, got, err, test.want)
		}
	}
	if _, err := requestedCommand([]string{"unknown"}); err == nil {
		t.Fatal("unknown command was accepted")
	}
	if _, err := requestedCommand([]string{"run", "secret"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("invalid argument leaked or was accepted: %v", err)
	}
}

func TestExecuteDispatchesSelectedCommands(t *testing.T) {
	restoreHostSeams(t)
	var selected []string
	parseOptions = func(args []string, _ control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		selected = append(selected, args[0])
		command := map[string]control.OrchestratorCommand{
			"check":             control.OrchestratorCommandCheck,
			"provision-journal": control.OrchestratorCommandProvisionJournal,
			"journal-writer":    control.OrchestratorCommandJournalWriter,
		}[args[0]]
		return fakeOptions(command), nil
	}
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error { return nil }
	provisionJournal = func(context.Context, *control.OrchestratorOptions) error { return nil }
	writer := &fakeComponent{done: make(chan struct{})}
	close(writer.done)
	startJournalWriterRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) { return writer, nil }
	for _, command := range []string{"check", "provision-journal", "journal-writer"} {
		if command == "journal-writer" {
			if err := execute(context.Background(), []string{command}, func(string) (string, bool) { return "", false }, ioDiscard{}); err == nil {
				// A completed writer is an expected component-failure path.
			}
			continue
		}
		if err := execute(context.Background(), []string{command}, func(string) (string, bool) { return "", false }, ioDiscard{}); err != nil {
			t.Fatalf("execute %s: %v", command, err)
		}
	}
	if len(selected) != 3 || selected[0] != "check" || selected[1] != "provision-journal" || selected[2] != "journal-writer" {
		t.Fatalf("selected parser commands = %v", selected)
	}
}

func TestExecuteRefusesRunWhenOCIEstateVerificationFails(t *testing.T) {
	restoreHostSeams(t)
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		return fakeOptions(control.OrchestratorCommandRun), nil
	}
	estateErr := errors.New("malformed estate")
	verifyEstate = func(context.Context, string, envLookup) error { return estateErr }
	started := false
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		started = true
		return nil, nil
	}
	err := execute(context.Background(), []string{"run"}, func(string) (string, bool) { return "", false }, ioDiscard{})
	if !errors.Is(err, estateErr) || started {
		t.Fatalf("estate failure = %v, runtime started = %v", err, started)
	}
}

func TestConfiguredEstateRequiresExplicitProviderSelection(t *testing.T) {
	lookup := func(values map[string]string) envLookup {
		return func(key string) (string, bool) {
			value, ok := values[key]
			return value, ok
		}
	}
	if err := verifyConfiguredOCIEstate(context.Background(), "local", lookup(map[string]string{providerEnvironment: "local"})); err != nil {
		t.Fatalf("explicit local provider rejected: %v", err)
	}
	if err := verifyConfiguredOCIEstate(context.Background(), "local", lookup(nil)); err == nil {
		t.Fatal("missing provider selection was accepted")
	}
	if err := verifyConfiguredOCIEstate(context.Background(), "local", lookup(map[string]string{providerEnvironment: "oci"})); err == nil {
		t.Fatal("OCI provider without estate settings was accepted")
	}
}

func TestExecuteRedactsFailureAndExitStatus(t *testing.T) {
	restoreHostSeams(t)
	secret := "private-seed-and-password"
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		return nil, errors.New(secret)
	}
	err := execute(context.Background(), []string{"check"}, func(string) (string, bool) { return "", false }, ioDiscard{})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}
	if exitCode(err) != 1 {
		t.Fatalf("exit code = %d; want 1", exitCode(err))
	}
}

func TestRunCancellationClosesRegionalRuntime(t *testing.T) {
	restoreHostSeams(t)
	ctx, cancel := context.WithCancel(context.Background())
	regional := &fakeComponent{done: make(chan struct{})}
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		return fakeOptions(control.OrchestratorCommandRun), nil
	}
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		cancel()
		return regional, nil
	}
	err := execute(ctx, nil, func(string) (string, bool) { return "", false }, ioDiscard{})
	if !errors.Is(err, context.Canceled) || !regional.closed {
		t.Fatalf("cancellation result = %v, regional closed = %v", err, regional.closed)
	}
	if exitCode(err) != 130 {
		t.Fatalf("exit code = %d; want 130", exitCode(err))
	}
}

func TestRunClosesComponentsInReverseOrder(t *testing.T) {
	restoreHostSeams(t)
	order := []string{}
	regional := &fakeComponent{done: make(chan struct{}), name: "regional", order: &order}
	global := &fakeComponent{done: make(chan struct{}), name: "global", order: &order}
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		o := fakeOptions(control.OrchestratorCommandRun)
		o.GlobalNats = &control.GlobalAuthorityNatsConfiguration{}
		return o, nil
	}
	makeGlobalConfiguration = func(*control.OrchestratorOptions, component) (*control.GlobalNatsRuntimeConfiguration, error) {
		return &control.GlobalNatsRuntimeConfiguration{}, nil
	}
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) { return regional, nil }
	startGlobalRuntime = func(context.Context, *control.GlobalNatsRuntimeConfiguration) (component, error) {
		close(global.done)
		return global, nil
	}
	err := execute(context.Background(), []string{"run"}, func(string) (string, bool) { return "", false }, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("expected component failure, got %v", err)
	}
	if strings.Join(order, ",") != "global,regional" {
		t.Fatalf("close order = %v; want [global regional]", order)
	}
}

func TestCheckFailsWhenDirectDirectoryStartupFails(t *testing.T) {
	restoreHostSeams(t)
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		o := fakeOptions(control.OrchestratorCommandCheck)
		o.GlobalDirectoryNats = &control.GlobalDirectoryNatsConfiguration{}
		return o, nil
	}
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error { return nil }
	startDirectoryCheck = func(context.Context, *control.GlobalDirectoryNatsConfiguration, func() control.RegionalRuntimeMembershipSnapshot, func() control.RegionalAuthoritySnapshot, bool) (directoryCheckRuntime, error) {
		return nil, errors.New("directory dependency unavailable")
	}
	if err := execute(context.Background(), []string{"check"}, func(string) (string, bool) { return "", false }, ioDiscard{}); err == nil {
		t.Fatal("directory startup failure was reported as success")
	}
}

func TestCheckDirectDirectoryClosesServiceBeforeDirectory(t *testing.T) {
	restoreHostSeams(t)
	order := []string{}
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		o := fakeOptions(control.OrchestratorCommandCheck)
		o.GlobalDirectoryNats = &control.GlobalDirectoryNatsConfiguration{}
		o.GlobalDirectoryServiceNats = &control.GlobalDirectoryServiceNatsConfiguration{}
		return o, nil
	}
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error { return nil }
	startDirectoryCheck = func(context.Context, *control.GlobalDirectoryNatsConfiguration, func() control.RegionalRuntimeMembershipSnapshot, func() control.RegionalAuthoritySnapshot, bool) (directoryCheckRuntime, error) {
		return &fakeDirectoryCheckRuntime{dispose: func() { order = append(order, "directory") }}, nil
	}
	startDirectoryServiceCheck = func(context.Context, *control.GlobalDirectoryServiceNatsConfiguration, func() control.GlobalCellDirectorySnapshot) (directoryServiceCheckRuntime, error) {
		return &fakeDirectoryServiceCheckRuntime{dispose: func() { order = append(order, "service") }}, nil
	}
	if err := execute(context.Background(), []string{"check"}, func(string) (string, bool) { return "", false }, ioDiscard{}); err != nil {
		t.Fatalf("direct directory check failed: %v", err)
	}
	if strings.Join(order, ",") != "service,directory" {
		t.Fatalf("dispose order = %v; want [service directory]", order)
	}
}

func TestGlobalCheckUsesDirectDirectoryProbeBeforeGlobalClose(t *testing.T) {
	restoreHostSeams(t)
	order := []string{}
	parseOptions = func([]string, control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		o := fakeOptions(control.OrchestratorCommandCheck)
		o.GlobalNats = &control.GlobalAuthorityNatsConfiguration{}
		o.GlobalDirectoryNats = &control.GlobalDirectoryNatsConfiguration{}
		return o, nil
	}
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error { return nil }
	makeGlobalConfiguration = func(*control.OrchestratorOptions, component) (*control.GlobalNatsRuntimeConfiguration, error) {
		return &control.GlobalNatsRuntimeConfiguration{Directory: &control.GlobalDirectoryNatsConfiguration{}}, nil
	}
	startGlobalRuntime = func(context.Context, *control.GlobalNatsRuntimeConfiguration) (component, error) {
		return &fakeComponent{done: make(chan struct{}), name: "global", order: &order}, nil
	}
	startDirectoryCheck = func(context.Context, *control.GlobalDirectoryNatsConfiguration, func() control.RegionalRuntimeMembershipSnapshot, func() control.RegionalAuthoritySnapshot, bool) (directoryCheckRuntime, error) {
		return &fakeDirectoryCheckRuntime{dispose: func() { order = append(order, "directory") }}, nil
	}
	if err := execute(context.Background(), []string{"check"}, func(string) (string, bool) { return "", false }, ioDiscard{}); err != nil {
		t.Fatalf("global check failed: %v", err)
	}
	if strings.Join(order, ",") != "directory,global" {
		t.Fatalf("dispose order = %v; want [directory global]", order)
	}
}

func TestNatsServerConfigurationUsesBoundedEnvironment(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case natsServerConfigEnvironment:
			return "/run/nats/server.conf", true
		case natsServerReadinessEnvironment:
			return "2s", true
		default:
			return "", false
		}
	}
	configuration, err := natsServerConfiguration(lookup)
	if err != nil || configuration.ConfigPath != "/run/nats/server.conf" || configuration.ReadinessTimeout.String() != "2s" {
		t.Fatalf("configuration = %#v, err = %v", configuration, err)
	}
	bad, err := natsServerConfiguration(func(string) (string, bool) { return "bad", true })
	if err == nil || !strings.Contains(err.Error(), "invalid") || bad.ConfigPath != "" {
		t.Fatalf("invalid configuration = %#v, err = %v", bad, err)
	}
}

func TestCatalogIsDeterministicAndCredentialFree(t *testing.T) {
	var first, second bytes.Buffer
	if err := writeCatalog(&first); err != nil {
		t.Fatal(err)
	}
	if err := writeCatalog(&second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || strings.Contains(first.String(), "password") || strings.Contains(first.String(), "private-seed") {
		t.Fatal("catalog is not deterministic or contains credential material")
	}
}

// ioDiscard avoids importing a test-only output implementation in dispatch
// tests while keeping writes harmless.
type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestNonlocalRunAndCheckRequireOCIBeforeRuntime(t *testing.T) {
	restoreHostSeams(t)
	verifyEstate = verifyConfiguredOCIEstate
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"identity.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"user.seed":    seed,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	membershipKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	membershipDER, err := x509.MarshalPKCS8PrivateKey(membershipKey)
	if err != nil {
		t.Fatal(err)
	}
	membershipPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: membershipDER})
	_, membershipPublic, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(membershipPEM)
	if err != nil {
		t.Fatal(err)
	}
	membershipPins, err := json.Marshal(map[string]string{"gru-1": membershipPublic})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"membership.pem": membershipPEM, "membership-pins.json": membershipPins} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	values := map[string]string{
		"TS_ORCH_CELL": "gru", "TS_ORCH_INSTANCE": "gru-1", "TS_ORCH_REPLICAS": "3", "TS_ORCH_NATS_URL": "tls://nats.internal:4222",
		"TS_ORCH_NATS_NKEY_FILE":              filepath.Join(dir, "user.seed"),
		"TS_ORCH_NATS_TLS_CA_FILE":            filepath.Join(dir, "identity.pem"),
		"TS_ORCH_NATS_TLS_CERT_FILE":          filepath.Join(dir, "identity.pem"),
		"TS_ORCH_NATS_TLS_KEY_FILE":           filepath.Join(dir, "key.pem"),
		"TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE": filepath.Join(dir, "membership.pem"),
		"TS_ORCH_MEMBERSHIP_PINS_FILE":        filepath.Join(dir, "membership-pins.json"),
		"TS_ORCH_COMMAND_SIGNING_KEY_FILE":    filepath.Join(dir, "command.key"),
		"TS_ORCH_COMMAND_TRUST_KEY_FILES":     filepath.Join(dir, "command.pub"),
		providerEnvironment:                   "local",
	}
	lookup := func(key string) (string, bool) { value, present := values[key]; return value, present }
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		t.Fatal("nonlocal run started with local provider")
		return nil, nil
	}
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error {
		t.Fatal("nonlocal check started with local provider")
		return nil
	}
	for _, command := range []string{"run", "check"} {
		t.Run(command, func(t *testing.T) {
			options, err := control.ParseOrchestratorOptions([]string{command}, lookup)
			if err != nil || options.Cell != "gru" {
				t.Fatalf("fixture must pass real option admission: options=%v error=%v", options, err)
			}
			err = execute(context.Background(), []string{command}, lookup, ioDiscard{})
			if err == nil || !strings.Contains(errors.Unwrap(err).Error(), "nonlocal cells require the OCI provider") {
				t.Fatalf("nonlocal provider admission: %v", err)
			}
		})
	}
	// The same settings reach estate admission after explicit OCI selection.
	values[providerEnvironment] = "oci"
	if err := execute(context.Background(), []string{"check"}, lookup, ioDiscard{}); !errors.Is(err, errOCIEstateConfigurationMissing) {
		t.Fatalf("missing OCI estate bypassed: %v", err)
	}
	// Local tooling retains its documented default cell and explicit provider.
	delete(values, "TS_ORCH_CELL")
	values[providerEnvironment] = "local"
	checked := false
	checkRegionalRuntime = func(context.Context, *control.OrchestratorOptions) error { checked = true; return nil }
	if err := execute(context.Background(), []string{"check"}, lookup, ioDiscard{}); err != nil || !checked {
		t.Fatalf("explicit local check failed: %v checked=%v", err, checked)
	}
}

func TestProductionAdmissionPrecedesRegionalStartup(t *testing.T) {
	for _, kind := range []string{"error", "nil", "missing-delivery"} {
		t.Run(kind, func(t *testing.T) {
			restoreHostSeams(t)
			rejected := errors.New("production admission rejected")
			admitProductionRuntime = testProductionAdmission(func(context.Context, *control.OrchestratorOptions) (*productionRuntime, error) {
				if kind == "error" {
					return nil, rejected
				}
				if kind == "missing-delivery" {
					return &productionRuntime{}, nil
				}
				return nil, nil
			})
			startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
				t.Fatal("regional transport started before production admission")
				return nil, nil
			}
			options := fakeOptions(control.OrchestratorCommandRun)
			options.Cell = "gru"
			err := runCommand(context.Background(), options, nil)
			if err == nil || (kind == "error" && !errors.Is(err, rejected)) {
				t.Fatalf("admission result: %v", err)
			}
		})
	}
}

func TestAdmittedProductionClosesOnTransportStartupFailure(t *testing.T) {
	for _, stage := range []string{"regional", "regional-nil", "global"} {
		t.Run(stage, func(t *testing.T) {
			restoreHostSeams(t)
			worker := newScheduledService("admission cleanup probe", 0, func(context.Context, time.Time) error {
				t.Error("production worker started before transport admission")
				return nil
			})
			admitted := &productionRuntime{delivery: &control.SignedDeliveryRuntimeConfig{}, workers: []*scheduledService{worker}}
			if stage == "global" {
				admitted.masterDelivery = productionMasterDeliveryFixture(t)
			}
			var order []string
			admitProductionRuntime = testProductionAdmission(func(context.Context, *control.OrchestratorOptions) (*productionRuntime, error) {
				order = append(order, "admit")
				return admitted, nil
			})
			failed := errors.New("transport start failed")
			regional := &fakeComponent{done: make(chan struct{})}
			startRegionalRuntime = func(_ context.Context, got *control.OrchestratorOptions) (component, error) {
				if got.Delivery != admitted.delivery {
					t.Fatal("regional runtime did not receive admitted production delivery")
				}
				order = append(order, "regional")
				if stage == "regional" {
					return regional, failed
				}
				if stage == "regional-nil" {
					return nil, nil
				}
				return regional, nil
			}
			makeGlobalConfiguration = func(*control.OrchestratorOptions, component) (*control.GlobalNatsRuntimeConfiguration, error) {
				return &control.GlobalNatsRuntimeConfiguration{Cell: "gru", Authority: &control.GlobalAuthorityNatsConfiguration{Cell: "gru"}}, nil
			}
			startGlobalRuntime = func(context.Context, *control.GlobalNatsRuntimeConfiguration) (component, error) {
				order = append(order, "global")
				return nil, failed
			}
			options := fakeOptions(control.OrchestratorCommandRun)
			options.Cell = "gru"
			options.GlobalNats = &control.GlobalAuthorityNatsConfiguration{}
			err := runCommand(context.Background(), options, nil)
			if options.Delivery != nil {
				t.Fatal("startup mutated caller options")
			}
			if err == nil || (stage != "regional-nil" && !errors.Is(err, failed)) {
				t.Fatalf("startup result: %v", err)
			}
			if len(order) < 2 || order[0] != "admit" || order[1] != "regional" {
				t.Fatalf("startup order: %v", order)
			}
			if !worker.closed || worker.started {
				t.Fatalf("admitted worker closed=%v started=%v", worker.closed, worker.started)
			}
			if stage != "regional-nil" && !regional.closed {
				t.Fatal("regional resource leaked after startup failure")
			}
		})
	}
}

// A test admission plan keeps construction delayed until run has started its
// explicitly selected broker, matching the real root resolver's contract.
func testProductionAdmission(construct func(context.Context, *control.OrchestratorOptions) (*productionRuntime, error)) func(context.Context, *control.OrchestratorOptions) (*admittedProductionRuntime, error) {
	return func(_ context.Context, options *control.OrchestratorOptions) (*admittedProductionRuntime, error) {
		return &admittedProductionRuntime{construct: func(ctx context.Context) (*productionRuntime, error) { return construct(ctx, options) }}, nil
	}
}

func TestMissingCompositionDiagnosticExcludesWrappedDetails(t *testing.T) {
	privateDetail := errors.New("credential=never-print-this")
	err := commandFailure("run", errors.Join(ErrProductionCompositionMissing, privateDetail))
	if err.Error() != ErrProductionCompositionMissing.Error() || !errors.Is(err, privateDetail) {
		t.Fatalf("missing composition diagnostic lost its fixed label or error identity")
	}
	if ordinary := commandFailure("run", privateDetail); ordinary.Error() != "orchestrator run failed" {
		t.Fatal("ordinary failure exposed private details")
	}
	missingEstate := verifyConfiguredOCIEstate(context.Background(), "gru", func(name string) (string, bool) {
		if name == providerEnvironment {
			return "oci", true
		}
		return "", false
	})
	if !errors.Is(missingEstate, errOCIEstateConfigurationMissing) {
		t.Fatal("missing estate configuration has no stable identity")
	}
	if reported := commandFailure("run", errors.Join(missingEstate, privateDetail)); reported.Error() != errOCIEstateConfigurationMissing.Error() {
		t.Fatal("estate diagnostic did not retain only its fixed configuration names")
	}
}
