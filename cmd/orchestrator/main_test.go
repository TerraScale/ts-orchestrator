package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
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
	verifyEstate = func(context.Context, envLookup) error { return nil }
	t.Cleanup(func() {
		parseOptions = oldParse
		startRegionalRuntime = oldRegional
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
	verifyEstate = func(context.Context, envLookup) error { return estateErr }
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
	if err := verifyConfiguredOCIEstate(context.Background(), lookup(map[string]string{providerEnvironment: "local"})); err != nil {
		t.Fatalf("explicit local provider rejected: %v", err)
	}
	if err := verifyConfiguredOCIEstate(context.Background(), lookup(nil)); err == nil {
		t.Fatal("missing provider selection was accepted")
	}
	if err := verifyConfiguredOCIEstate(context.Background(), lookup(map[string]string{providerEnvironment: "oci"})); err == nil {
		t.Fatal("OCI provider without estate settings was accepted")
	}
}

func TestConfiguredEstateUsesMetadataCredentialsWhenExplicitCredentialsAreAbsent(t *testing.T) {
	oldSource := newOCIInstancePrincipalCredentialSource
	t.Cleanup(func() { newOCIInstancePrincipalCredentialSource = oldSource })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	newOCIInstancePrincipalCredentialSource = func() (provider.InstancePrincipalCredentialSource, error) {
		calls++
		return testInstancePrincipalSource{credentials: provider.InstancePrincipalCredentials{KeyID: "metadata-key", Key: key}}, nil
	}
	reader, err := newConfiguredOCIEstateReader(context.Background(), testCommandOCIEstateSpec(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := reader.Transports[provider.OCIServiceCore].Signer.(*provider.InstancePrincipalSigner)
	if !ok || signer.KeyID != "metadata-key" || calls != 1 {
		t.Fatalf("metadata credential composition signer=%T/%q factoryCalls=%d", reader.Transports[provider.OCIServiceCore].Signer, signerKeyID(signer), calls)
	}
}

func TestConfiguredEstatePrefersExplicitKeyFileCredentials(t *testing.T) {
	oldSource := newOCIInstancePrincipalCredentialSource
	t.Cleanup(func() { newOCIInstancePrincipalCredentialSource = oldSource })
	newOCIInstancePrincipalCredentialSource = func() (provider.InstancePrincipalCredentialSource, error) {
		t.Fatal("metadata source was selected despite explicit credentials")
		return nil, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := t.TempDir() + "/oci-key.pem"
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := newConfiguredOCIEstateReader(context.Background(), testCommandOCIEstateSpec(), "explicit-key", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := reader.Transports[provider.OCIServiceCore].Signer.(*provider.InstancePrincipalSigner)
	if !ok || signer.KeyID != "explicit-key" {
		t.Fatalf("explicit credential composition signer=%T/%q", reader.Transports[provider.OCIServiceCore].Signer, signerKeyID(signer))
	}
}

type testInstancePrincipalSource struct {
	credentials provider.InstancePrincipalCredentials
}

func (s testInstancePrincipalSource) Retrieve(context.Context) (provider.InstancePrincipalCredentials, error) {
	return s.credentials, nil
}

func testCommandOCIEstateSpec() provider.OCIEstateSpec {
	return provider.OCIEstateSpec{
		Region: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1.x",
		ControlCompartmentID: "ocid1.compartment.oc1.control", NetworkCompartmentID: "ocid1.compartment.oc1.network", WorkloadCompartmentID: "ocid1.compartment.oc1.workload",
		VCNID: "ocid1.vcn.oc1.x", SubnetIDs: []string{"ocid1.subnet.oc1.x"}, NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.x"},
		IAMPolicyCompartmentID: "ocid1.compartment.oc1.control", IAMPolicies: []provider.OCIEstatePolicy{{ID: "ocid1.policy.oc1.x", Statements: []string{"Allow dynamic-group terrascale-orchestrator to read compartments in tenancy"}}},
		VaultID: "ocid1.vault.oc1.x", KeyID: "ocid1.key.oc1.x", KeyManagementEndpoint: "https://ocid1.vault.oc1.sa-saopaulo-1.x.management.kms.sa-saopaulo-1.oci.oraclecloud.com",
		ObjectNamespace: "namespace", LedgerBucket: "ledger", BackupBucket: "backups",
	}
}

func signerKeyID(signer *provider.InstancePrincipalSigner) string {
	if signer == nil {
		return ""
	}
	return signer.KeyID
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
		o.GlobalNats = &control.GlobalNatsConfiguration{}
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
		o.GlobalNats = &control.GlobalNatsConfiguration{}
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
