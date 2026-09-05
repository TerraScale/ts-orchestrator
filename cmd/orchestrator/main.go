// Command orchestrator is the thin production host for the TerraScale
// orchestrator control runtimes.  Composition and validation remain owned by
// the control and bootstrap packages; this package only selects a role and
// owns process lifetime.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"terrascale.tech/orchestrator/src/orchestrator/globalclient"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

const (
	natsServerConfigEnvironment        = "TS_ORCH_NATS_SERVER_CONFIG_FILE"
	natsServerReadinessEnvironment     = "TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"
	ociEstateFileEnvironment           = "TS_ORCH_OCI_ESTATE_FILE"
	ociKeyIDEnvironment                = "TS_ORCH_OCI_KEY_ID"
	ociPrivateKeyFileEnvironment       = "TS_ORCH_OCI_PRIVATE_KEY_FILE"
	ociImageIDEnvironment              = "TS_ORCH_OCI_IMAGE_ID"
	ociCertificateAuthorityEnvironment = "TS_ORCH_OCI_CERTIFICATE_AUTHORITY_ID"
	providerEnvironment                = "TS_ORCH_PROVIDER"
	cloudflareTokenEnvironment         = "CLOUDFLARE_API_TOKEN"
	cloudflareZoneIDEnvironment        = "TS_ORCH_CLOUDFLARE_ZONE_ID"
	cloudflareAccountIDEnvironment     = "TS_ORCH_CLOUDFLARE_ACCOUNT_ID"
	cloudflareMembersEnvironment       = "TS_ORCH_CLOUDFLARE_MEMBERS_JSON"
	cloudflareEgressEnvironment        = "TS_ORCH_CLOUDFLARE_TAILSCALE_EGRESS_JSON"
	grafanaMetricsEnvironment          = "TS_ORCH_GRAFANA_METRICS_ENDPOINT"
	grafanaLogsEnvironment             = "TS_ORCH_GRAFANA_LOGS_ENDPOINT"
	grafanaUsernameEnvironment         = "TS_ORCH_GRAFANA_USERNAME"
	grafanaAPIKeyEnvironment           = "TS_ORCH_GRAFANA_API_KEY"

	globalCheckTimeout = 30 * time.Second
)

// component is the common lifecycle contract of all long-running roles.
// Keeping it local makes dispatch tests independent of NATS and permits
// deterministic cleanup assertions.
type component interface {
	Completion() <-chan struct{}
	Close() error
}

type envLookup func(string) (string, bool)

var (
	parseOptions = control.ParseOrchestratorOptions

	startRegionalRuntime = func(ctx context.Context, options *control.OrchestratorOptions) (component, error) {
		return control.NatsRuntimeStartAsync(ctx, options)
	}
	checkRegionalRuntime = control.NatsRuntimeCheck
	startGlobalRuntime   = func(ctx context.Context, configuration *control.GlobalNatsRuntimeConfiguration) (component, error) {
		return control.GlobalNatsRuntimeStartAsync(ctx, configuration)
	}
	startDirectoryRuntime      = defaultDirectoryRuntime
	startDirectoryCheck        = defaultDirectoryCheck
	startDirectoryServiceCheck = defaultDirectoryServiceCheck
	startJournalWriterRuntime  = func(ctx context.Context, options *control.OrchestratorOptions) (component, error) {
		return control.NatsJournalWriterRuntimeStartAsync(ctx, options)
	}
	provisionJournal        = NatsProvision
	makeGlobalConfiguration = defaultGlobalConfiguration
	runEmbeddedNatsServer   = func(ctx context.Context, configuration bootstrap.NatsServerConfig) error {
		return bootstrap.RunNatsServer(ctx, configuration)
	}
	renderCatalog          = writeCatalog
	verifyEstate           = verifyConfiguredOCIEstate
	startProductionRuntime = func(ctx context.Context, options *control.OrchestratorOptions) (*productionRuntime, error) {
		admission, err := admitProductionRuntime(ctx, options)
		if err != nil {
			return nil, err
		}
		return admission.Construct(ctx)
	}
)

// NatsProvision is a variable-friendly spelling for the package singleton's
// production provisioner. Tests replace provisionJournal instead of making a
// network connection.
func NatsProvision(ctx context.Context, options *control.OrchestratorOptions) error {
	return control.NatsOperationJournalProvisioner.ProvisionAsync(ctx, options)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := execute(ctx, os.Args[1:], os.LookupEnv, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

// execute dispatches one process role. It deliberately receives all process
// dependencies so command selection and lifecycle behavior are unit-testable.
func execute(ctx context.Context, args []string, lookup envLookup, output io.Writer) error {
	if ctx == nil {
		return commandFailure("run", errors.New("context is nil"))
	}
	if lookup == nil {
		return commandFailure(commandName(args), errors.New("environment lookup is nil"))
	}

	name, err := requestedCommand(args)
	if err != nil {
		return err
	}
	if name == "run" && len(args) == 3 {
		lookup, err = loadRunConfiguration(args[2])
		if err != nil {
			return commandFailure(name, err)
		}
		args = []string{"run"}
	}
	if name == "initial-gru-r1" {
		return runInitialGRUR1(ctx, args[2])
	}
	if name == "observe-member" {
		return runObserveMember(ctx, args, output)
	}
	if name == "catalog" {
		if err := renderCatalog(output); err != nil {
			return commandFailure(name, err)
		}
		return nil
	}
	if name == "nats-server" {
		configuration, err := natsServerConfiguration(lookup)
		if err != nil {
			return commandFailure(name, err)
		}
		if err := runEmbeddedNatsServer(ctx, configuration); err != nil {
			return commandFailure(name, err)
		}
		return nil
	}
	if name == "reconcile" {
		if err := runReconcileWithLookup(ctx, args, lookup, output); err != nil {
			return commandFailure(name, err)
		}
		return nil
	}
	if name == "bootstrap" {
		// Greenfield OCI bootstrap (D-67): compartment, VCN, NSGs, vault,
		// buckets, and the first two home-Region hosts whose cloud-init
		// installs only ts-node; the hosts then fetch the orchestrator and
		// form the fenced temporary GRU R1. --dry-run prints the runbook.
		if err := runBootstrap(ctx, args, lookup, output); err != nil {
			return commandFailure(name, err)
		}
		return nil
	}
	if name == "add-region" {
		// I-5: one command from an empty OCI region to serving members.
		// --dry-run renders the runbook without touching any provider.
		if err := runAddRegion(ctx, args, lookup, output); err != nil {
			return commandFailure(name, err)
		}
		return nil
	}

	options, err := parseOptions(args, control.EnvironmentLookup(lookup))
	if err != nil {
		return commandFailure(name, err)
	}
	if options == nil {
		return commandFailure(name, errors.New("options are missing"))
	}
	if options.Command == control.OrchestratorCommandRun || options.Command == control.OrchestratorCommandCheck {
		if err := verifyEstate(ctx, options.Cell, lookup); err != nil {
			return commandFailure(name, err)
		}
	}

	switch options.Command {
	case control.OrchestratorCommandRun:
		var serverConfig *bootstrap.NatsServerConfig
		serverConfig, err = selectedNatsConfiguration(lookup)
		if err == nil {
			err = runCommand(ctx, options, serverConfig)
		}
	case control.OrchestratorCommandCheck:
		err = checkCommand(ctx, options)
	case control.OrchestratorCommandProvisionJournal:
		err = provisionJournal(ctx, options)
	case control.OrchestratorCommandJournalWriter:
		err = runJournalWriter(ctx, options)
	default:
		err = errors.New("unsupported command")
	}
	if err != nil {
		return commandFailure(name, err)
	}
	return nil
}

// Local tooling retains its explicit provider selection. Every other cell
// must verify its OCI estate before starting or checking any runtime.
func validateConfiguredProvider(cell string, lookup envLookup) error {
	providerName, present := lookup(providerEnvironment)
	if cell != "local" && (!present || strings.TrimSpace(providerName) != "oci") {
		return errors.New("nonlocal cells require the OCI provider")
	}
	return nil
}

func verifyConfiguredOCIEstate(ctx context.Context, cell string, lookup envLookup) error {
	if err := validateConfiguredProvider(cell, lookup); err != nil {
		return err
	}
	providerName, providerPresent := lookup(providerEnvironment)
	if !providerPresent {
		return errors.New("provider selection is required")
	}
	switch strings.TrimSpace(providerName) {
	case "local":
		return nil
	case "oci":
	default:
		return errors.New("provider selection is invalid")
	}
	estateFile, estatePresent := lookup(ociEstateFileEnvironment)
	keyID, keyPresent := lookup(ociKeyIDEnvironment)
	keyFile, keyFilePresent := lookup(ociPrivateKeyFileEnvironment)
	if !estatePresent || !keyPresent || !keyFilePresent || strings.TrimSpace(estateFile) == "" || strings.TrimSpace(keyID) == "" || strings.TrimSpace(keyFile) == "" {
		return errOCIEstateConfigurationMissing
	}
	spec, err := provider.LoadOCIEstateSpec(estateFile)
	if err != nil {
		return err
	}
	reader, err := provider.NewOCIEstateHTTPReader(spec, keyID, keyFile)
	if err != nil {
		return err
	}
	return provider.VerifyOCIEstate(ctx, spec, reader)
}

func requestedCommand(args []string) (string, error) {
	if len(args) == 0 {
		return "run", nil
	}
	if args[0] == "run" && len(args) == 3 && args[1] == "--config" && args[2] != "" {
		return "run", nil
	}
	if args[0] == "initial-gru-r1" {
		if len(args) == 3 && args[1] == "--config" && args[2] != "" {
			return args[0], nil
		}
		return "unsupported", errors.New("orchestrator: invalid initial configuration arguments")
	}
	if args[0] == "observe-member" {
		return "observe-member", nil
	}
	if args[0] == "reconcile" {
		if len(args) == 1 || len(args) == 2 && args[1] == dryRunFlag {
			return "reconcile", nil
		}
		return "unsupported", errors.New("orchestrator: unsupported command")
	}
	if args[0] == "add-region" {
		if (len(args) == 2 && args[1] != "" && !strings.HasPrefix(args[1], "-")) ||
			(len(args) == 3 && args[1] != "" && !strings.HasPrefix(args[1], "-") && args[2] == dryRunFlag) {
			return "add-region", nil
		}
		return "unsupported", errors.New("orchestrator: unsupported command")
	}
	if args[0] == "bootstrap" {
		if len(args) == 1 || len(args) == 2 && args[1] == dryRunFlag {
			return "bootstrap", nil
		}
		return "unsupported", errors.New("orchestrator: unsupported command")
	}
	if len(args) > 1 {
		return "unsupported", errors.New("orchestrator: command accepts no arguments")
	}
	switch args[0] {
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer", "bootstrap":
		return args[0], nil
	default:
		// Do not echo an arbitrary argument: command lines can contain secrets.
		return "unsupported", errors.New("orchestrator: unsupported command")
	}
}

func commandName(args []string) string {
	if len(args) == 0 {
		return "run"
	}
	switch args[0] {
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer", "reconcile", "bootstrap", "add-region", "observe-member", "initial-gru-r1":
		return args[0]
	default:
		return "unsupported"
	}
}

// commandError keeps errors.Is useful to callers without exposing parser,
// path, credential, or transport details in process output.
type commandError struct {
	command string
	cause   error
}

var errOCIEstateConfigurationMissing = errors.New("orchestrator: OCI estate verification requires TS_ORCH_OCI_ESTATE_FILE, TS_ORCH_OCI_KEY_ID, and TS_ORCH_OCI_PRIVATE_KEY_FILE")

func (e commandError) Error() string {
	if e.command == "unsupported" {
		return "orchestrator: unsupported command"
	}
	if e.command == "run" && errors.Is(e.cause, ErrProductionCompositionMissing) {
		return ErrProductionCompositionMissing.Error()
	}
	if errors.Is(e.cause, errOCIEstateConfigurationMissing) {
		return errOCIEstateConfigurationMissing.Error()
	}
	return "orchestrator " + e.command + " failed"
}

func (e commandError) Unwrap() error { return e.cause }

func commandFailure(command string, cause error) error {
	if command == "" {
		command = "run"
	}
	return commandError{command: command, cause: cause}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 124
	}
	return 1
}

func runCommand(ctx context.Context, options *control.OrchestratorOptions, serverConfig *bootstrap.NatsServerConfig) (result error) {
	if ctx == nil || options == nil {
		return errors.New("run requires context and options")
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	serverCtx, stopServer := context.WithCancel(context.WithoutCancel(ctx))
	defer stopServer()
	var server embeddedNatsRuntime
	monitorDone := make(chan struct{})
	defer close(monitorDone)
	var regional, global component
	var err error
	var production *productionRuntime
	defer func() {
		// A broker fault cancels dependent work internally. Preserve its failure
		// status instead of reporting that cancellation as an operator interrupt.
		if !isNilProductionValue(server) && ctx.Err() == nil && errors.Is(result, context.Canceled) && server.Err() != nil {
			result = server.Err()
		}
		result = combineErrors(result, closeRunRuntime(production, global, regional, server))
	}()

	var admission *admittedProductionRuntime
	var workerConnection *globalclient.Plan
	if options.Cell != "local" {
		admission, err = admitProductionRuntime(ctx, options)
		if err != nil {
			return fmt.Errorf("production runtime admission: %w", err)
		}
		if admission == nil || admission.construct == nil {
			return errors.New("production runtime admission is incomplete")
		}
	}
	if admission != nil && options.GlobalNats != nil {
		workerConnection, err = globalclient.Admit(options.GlobalNats)
		if err != nil {
			return fmt.Errorf("global worker connection admission: %w", err)
		}
	}
	if serverConfig != nil {
		server, err = startSelectedNatsRuntime(ctx, serverCtx, stopServer, *serverConfig)
		if err != nil {
			return err
		}
		go func() {
			select {
			case <-server.Completion():
				cancelRun()
			case <-monitorDone:
			}
		}()
	}
	// Live constructors may now open local durable stores. Global workers are constructed
	// later, only after the GRU election owns a proven lease.
	if admission != nil {
		production, err = admission.Construct(runCtx)
		if err != nil {
			return fmt.Errorf("production runtime composition: %w", err)
		}
		if production == nil {
			return errors.New("production runtime composition returned nil")
		}
		production.connection = workerConnection
		if production.delivery == nil {
			return errors.New("production runtime composition requires signed delivery")
		}
		configuredOptions := *options
		configuredOptions.Delivery = production.delivery
		options = &configuredOptions
	}
	regional, err = startRegionalRuntime(runCtx, options)
	if err != nil {
		return err
	}
	if regional == nil {
		return errors.New("regional runtime starter returned nil")
	}

	if options.GlobalNats != nil {
		configuration, configErr := makeGlobalConfiguration(options, regional)
		if configErr != nil {
			return configErr
		}
		if production != nil {
			if err := production.BindGlobalDelivery(configuration); err != nil {
				return err
			}
		}
		global, err = startGlobalRuntime(runCtx, configuration)
		if err != nil {
			return err
		}
		if global == nil {
			return errors.New("global runtime starter returned nil")
		}
	} else if options.GlobalDirectoryNats != nil {
		if production != nil {
			if err := production.BindGlobalDelivery(nil); err != nil {
				return err
			}
		}
		global, err = startDirectoryRuntime(runCtx, options, regional)
		if err != nil {
			return err
		}
		if global == nil {
			return errors.New("global directory runtime starter returned nil")
		}
	} else if production != nil {
		if err := production.BindGlobalDelivery(nil); err != nil {
			return err
		}
	}
	if production != nil {
		if err := production.StartGlobal(runCtx, global); err != nil {
			return err
		}
	}

	components := []component{}
	if production != nil {
		components = append(components, production)
	}
	if global != nil {
		components = append(components, global)
	}
	if server != nil {
		components = append(components, server)
	}
	return waitForComponents(runCtx, regional, components...)
}

func checkCommand(ctx context.Context, options *control.OrchestratorOptions) (result error) {
	if err := checkRegionalRuntime(ctx, options); err != nil {
		return err
	}
	if options.GlobalNats == nil {
		if options.GlobalDirectoryNats == nil {
			return nil
		}
		checkCtx, cancel := context.WithTimeout(ctx, globalCheckTimeout)
		defer cancel()
		return checkDirectoryDirect(checkCtx, options, nil)
	}
	checkCtx, cancel := context.WithTimeout(ctx, globalCheckTimeout)
	defer cancel()
	configuration, err := makeGlobalConfiguration(options, nil)
	if err != nil {
		return err
	}
	// GlobalNatsRuntime normally owns a supervised directory lifecycle. A
	// dependency check must observe the first direct connection attempt, so
	// leave that optional role out of the temporary global runtime and probe it
	// explicitly below.
	directoryConfigured := configuration.Directory != nil
	directoryServiceConfigured := configuration.DirectoryService != nil
	globalConfiguration := *configuration
	globalConfiguration.Directory = nil
	globalConfiguration.DirectoryService = nil
	globalConfiguration.Membership = nil
	globalConfiguration.DirectoryAuthority = nil
	globalConfiguration.DirectoryPublish = false
	global, err := startGlobalRuntime(checkCtx, &globalConfiguration)
	if err != nil {
		return err
	}
	if global == nil {
		return errors.New("global runtime starter returned nil")
	}
	directoryErr := error(nil)
	if directoryConfigured {
		directoryOptions := *options
		directoryOptions.GlobalDirectoryNats = configuration.Directory
		if directoryServiceConfigured {
			directoryOptions.GlobalDirectoryServiceNats = configuration.DirectoryService
		}
		directoryErr = checkDirectoryDirect(checkCtx, &directoryOptions, nil)
	}
	return combineErrors(directoryErr, global.Close())
}

func runJournalWriter(ctx context.Context, options *control.OrchestratorOptions) error {
	writer, err := startJournalWriterRuntime(ctx, options)
	if err != nil {
		return err
	}
	if writer == nil {
		return errors.New("journal-writer runtime starter returned nil")
	}
	waitErr := waitForComponents(ctx, writer)
	return combineErrors(waitErr, writer.Close())
}

type directoryCheckRuntime interface {
	Snapshot() control.GlobalCellDirectorySnapshot
	Dispose() error
}

type directoryServiceCheckRuntime interface {
	Dispose()
}

func defaultDirectoryCheck(
	ctx context.Context,
	configuration *control.GlobalDirectoryNatsConfiguration,
	membership func() control.RegionalRuntimeMembershipSnapshot,
	authority func() control.RegionalAuthoritySnapshot,
	publishEnabled bool,
) (directoryCheckRuntime, error) {
	return control.GlobalCellDirectoryRuntimeStartAsync(ctx, configuration, membership, authority, publishEnabled)
}

func defaultDirectoryServiceCheck(
	ctx context.Context,
	configuration *control.GlobalDirectoryServiceNatsConfiguration,
	snapshot func() control.GlobalCellDirectorySnapshot,
) (directoryServiceCheckRuntime, error) {
	return control.GlobalCellDirectoryServiceRuntimeStartAsync(ctx, configuration, snapshot)
}

func checkDirectoryDirect(ctx context.Context, options *control.OrchestratorOptions, regional component) error {
	if options == nil || options.GlobalDirectoryNats == nil {
		return errors.New("global directory NATS configuration is missing")
	}
	membership := func() control.RegionalRuntimeMembershipSnapshot {
		if value, ok := regional.(interface {
			MembershipSnapshot() control.RegionalRuntimeMembershipSnapshot
		}); ok {
			return value.MembershipSnapshot()
		}
		return control.RegionalRuntimeMembershipSnapshot{}
	}
	authority := func() control.RegionalAuthoritySnapshot {
		if value, ok := regional.(interface {
			AuthoritySnapshot() control.RegionalAuthoritySnapshot
		}); ok {
			return value.AuthoritySnapshot()
		}
		return control.RegionalAuthoritySnapshot{}
	}
	directory, err := startDirectoryCheck(
		ctx,
		options.GlobalDirectoryNats,
		membership,
		authority,
		false,
	)
	if err != nil {
		return err
	}
	if isNilDirectoryCheckRuntime(directory) {
		return errors.New("global directory runtime starter returned nil")
	}

	var service directoryServiceCheckRuntime
	if options.GlobalDirectoryServiceNats != nil {
		snapshot := directory.Snapshot
		service, err = startDirectoryServiceCheck(ctx, options.GlobalDirectoryServiceNats, snapshot)
		if err != nil {
			_ = directory.Dispose()
			return err
		}
		if isNilDirectoryServiceCheckRuntime(service) {
			_ = directory.Dispose()
			return errors.New("global directory service runtime starter returned nil")
		}
	}
	if service != nil {
		service.Dispose()
	}
	return directory.Dispose()
}

func isNilDirectoryCheckRuntime(runtime directoryCheckRuntime) bool {
	if runtime == nil {
		return true
	}
	value := reflect.ValueOf(runtime)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func isNilDirectoryServiceCheckRuntime(runtime directoryServiceCheckRuntime) bool {
	if runtime == nil {
		return true
	}
	value := reflect.ValueOf(runtime)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func waitForComponents(ctx context.Context, regional component, global ...component) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(completion(regional))},
	}
	for _, value := range global {
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(completion(value))})
	}
	selected, _, _ := reflect.Select(cases)
	if selected == 0 {
		return ctx.Err()
	}
	if selected == 1 {
		return errors.New("regional runtime stopped unexpectedly")
	}
	return errors.New("global runtime stopped unexpectedly")
}

func completion(value component) <-chan struct{} {
	if value == nil {
		return nil
	}
	return value.Completion()
}

func closeReverse(global, regional component) error {
	var result error
	if global != nil {
		result = global.Close()
	}
	if regional != nil {
		result = combineErrors(result, regional.Close())
	}
	return result
}

func closeRuntime(production component, global, regional component) error {
	var result error
	if production != nil {
		result = production.Close()
	}
	if global != nil {
		result = combineErrors(result, global.Close())
	}
	if regional != nil {
		result = combineErrors(result, regional.Close())
	}
	return result
}

func combineErrors(first, second error) error {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return errors.Join(first, second)
}

func defaultGlobalConfiguration(options *control.OrchestratorOptions, regional component) (*control.GlobalNatsRuntimeConfiguration, error) {
	if options == nil || options.GlobalNats == nil {
		return nil, errors.New("global NATS configuration is missing")
	}
	configuration := &control.GlobalNatsRuntimeConfiguration{
		Authority: options.GlobalNats,
		Cell:      options.Cell,
		Instance:  options.Instance,
	}
	if options.GlobalDirectoryNats != nil {
		configuration.Directory = options.GlobalDirectoryNats
		configuration.DirectoryService = options.GlobalDirectoryServiceNats
		configuration.DirectoryPublish = len(options.GlobalDirectoryNats.Endpoints) > 0
		configuration.Membership = func() control.RegionalRuntimeMembershipSnapshot {
			if value, ok := regional.(interface {
				MembershipSnapshot() control.RegionalRuntimeMembershipSnapshot
			}); ok {
				return value.MembershipSnapshot()
			}
			return control.RegionalRuntimeMembershipSnapshot{}
		}
		configuration.DirectoryAuthority = func() control.RegionalAuthoritySnapshot {
			if value, ok := regional.(interface {
				AuthoritySnapshot() control.RegionalAuthoritySnapshot
			}); ok {
				return value.AuthoritySnapshot()
			}
			return control.RegionalAuthoritySnapshot{}
		}
	}
	return configuration, nil
}

type directoryLifecycleComponent struct {
	lifecycle *control.GlobalCellDirectoryLifecycle
}

func (c *directoryLifecycleComponent) Completion() <-chan struct{} {
	if c == nil || c.lifecycle == nil {
		return nil
	}
	return c.lifecycle.Completion()
}

func (c *directoryLifecycleComponent) Close() error {
	if c != nil && c.lifecycle != nil {
		c.lifecycle.Dispose()
	}
	return nil
}

func defaultDirectoryRuntime(ctx context.Context, options *control.OrchestratorOptions, regional component) (component, error) {
	if options == nil || options.GlobalDirectoryNats == nil {
		return nil, errors.New("global directory NATS configuration is missing")
	}
	membership := func() control.RegionalRuntimeMembershipSnapshot {
		if value, ok := regional.(interface {
			MembershipSnapshot() control.RegionalRuntimeMembershipSnapshot
		}); ok {
			return value.MembershipSnapshot()
		}
		return control.RegionalRuntimeMembershipSnapshot{}
	}
	authority := func() control.RegionalAuthoritySnapshot {
		if value, ok := regional.(interface {
			AuthoritySnapshot() control.RegionalAuthoritySnapshot
		}); ok {
			return value.AuthoritySnapshot()
		}
		return control.RegionalAuthoritySnapshot{}
	}
	lifecycle, err := control.GlobalCellDirectoryLifecycleStart(
		options.GlobalDirectoryNats,
		options.GlobalDirectoryServiceNats,
		membership,
		authority,
		len(options.GlobalDirectoryNats.Endpoints) > 0,
		ctx,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return &directoryLifecycleComponent{lifecycle: lifecycle}, nil
}

func natsServerConfiguration(lookup envLookup) (bootstrap.NatsServerConfig, error) {
	if lookup == nil {
		return bootstrap.NatsServerConfig{}, errors.New("nats-server environment lookup is required")
	}
	path, present := lookup(natsServerConfigEnvironment)
	if !present || strings.TrimSpace(path) == "" {
		return bootstrap.NatsServerConfig{}, errors.New("nats-server configuration file is required")
	}
	value, present := lookup(natsServerReadinessEnvironment)
	if !present {
		return bootstrap.NatsServerConfig{ConfigPath: path, ReadinessTimeout: bootstrap.NatsServerDefaultReadiness}, nil
	}
	if strings.TrimSpace(value) == "" {
		return bootstrap.NatsServerConfig{}, errors.New("nats-server readiness timeout is invalid")
	}
	timeout, err := time.ParseDuration(value)
	if err != nil {
		return bootstrap.NatsServerConfig{}, errors.New("nats-server readiness timeout is invalid")
	}
	return bootstrap.NatsServerConfig{ConfigPath: path, ReadinessTimeout: timeout}, nil
}

type catalogDocument struct {
	SchemaVersion int              `json:"schemaVersion"`
	Commands      []catalogCommand `json:"commands"`
	Environment   []string         `json:"environment"`
}

type catalogCommand struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func writeCatalog(output io.Writer) error {
	if output == nil {
		return errors.New("catalog output is nil")
	}
	commands := []catalogCommand{
		{Name: "run", Description: "start the regional runtime and configured global roles; --config FILE uses an explicit production JSON setting source"},
		{Name: "check", Description: "perform bounded regional and configured global dependency checks"},
		{Name: "nats-server", Description: "run the embedded NATS server from an explicit configuration file"},
		{Name: "catalog", Description: "render this deterministic command and configuration catalog"},
		{Name: "provision-journal", Description: "provision the infrastructure-owned operation journal"},
		{Name: "journal-writer", Description: "start the isolated authoritative journal writer"},
		{Name: "reconcile", Description: "drive the observed estate to the declared estate; --dry-run prints the plan"},
		{Name: "add-region", Description: "bring one declared region from empty OCI to serving members; --dry-run prints the runbook"},
		{Name: "bootstrap", Description: "greenfield bootstrap from an empty tenancy to the fenced temporary GRU R1; --dry-run prints the runbook"},
	}
	environment := []string{
		"TS_ORCH_CELL", "TS_ORCH_NATS_URL", "TS_ORCH_REPLICAS", "TS_ORCH_INSTANCE",
		"TS_ORCH_NATS_NKEY_FILE", "TS_ORCH_NATS_TLS_CA_FILE", "TS_ORCH_NATS_TLS_CERT_FILE", "TS_ORCH_NATS_TLS_KEY_FILE",
		"TS_ORCH_GLOBAL_NATS_URL", "TS_ORCH_GLOBAL_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE",
		"TS_ORCH_GLOBAL_DIRECTORY_NATS_URL", "TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS",
		"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE",
		"TS_ORCH_COMMAND_SIGNING_KEY_FILE", "TS_ORCH_COMMAND_TRUST_KEY_FILES", "TS_ORCH_COMMAND_AGGREGATE_ID",
		"TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE", "TS_ORCH_MEMBERSHIP_PINS_FILE",
		"TS_ORCH_INFRA_NATS_NKEY_FILE", "TS_ORCH_INFRA_NATS_TLS_CA_FILE", "TS_ORCH_INFRA_NATS_TLS_CERT_FILE", "TS_ORCH_INFRA_NATS_TLS_KEY_FILE",
		"TS_ORCH_JOURNAL_NATS_NKEY_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CA_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE", "TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE", "TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE", "TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE", "TS_ORCH_JOURNAL_CONTROLLER_NKEYS",
		natsServerConfigEnvironment, natsServerReadinessEnvironment,
		providerEnvironment, ociEstateFileEnvironment, ociKeyIDEnvironment, ociPrivateKeyFileEnvironment,
		reconcileProgressEnvironment,
	}
	sort.Strings(environment)
	document := catalogDocument{SchemaVersion: 1, Commands: commands, Environment: environment}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}
