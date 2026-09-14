// Command orchestrator is the thin production host for the TerraScale
// orchestrator control runtimes.  Composition and validation remain owned by
// the control and bootstrap packages; this package only selects a role and
// owns process lifetime.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

const (
	natsServerConfigEnvironment      = "TS_ORCH_NATS_SERVER_CONFIG_FILE"
	natsServerReadinessEnvironment   = "TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"
	natsServerConfigAliasEnvironment = "TS_ORCH_NATS_SERVER_CONFIG"
	natsConfigAliasEnvironment       = "TS_ORCH_NATS_CONFIG_FILE"
	natsReadinessAliasEnvironment    = "TS_ORCH_NATS_READINESS_TIMEOUT"
	ociEstateFileEnvironment         = "TS_ORCH_OCI_ESTATE_FILE"
	providerEnvironment              = "TS_ORCH_PROVIDER"

	// The documented explicit configuration flags of the autoscaler role.
	// Every value is read through the injected environment lookup, mirroring
	// the nats-server role; nothing is discovered ambiently.
	autoscalerTickIntervalEnvironment            = "TS_ORCH_AUTOSCALER_TICK_INTERVAL"
	autoscalerMinNodesEnvironment                = "TS_ORCH_AUTOSCALER_MIN_NODES"
	autoscalerMaxNodesEnvironment                = "TS_ORCH_AUTOSCALER_MAX_NODES"
	autoscalerScaleUpHeadroomEnvironment         = "TS_ORCH_AUTOSCALER_SCALE_UP_HEADROOM_PERCENT"
	autoscalerScaleDownHeadroomEnvironment       = "TS_ORCH_AUTOSCALER_SCALE_DOWN_HEADROOM_PERCENT"
	autoscalerScaleUpTicksEnvironment            = "TS_ORCH_AUTOSCALER_SCALE_UP_CONFIRM_TICKS"
	autoscalerScaleDownTicksEnvironment          = "TS_ORCH_AUTOSCALER_SCALE_DOWN_CONFIRM_TICKS"
	autoscalerConcurrencyEnvironment             = "TS_ORCH_AUTOSCALER_MAX_CONCURRENT_PROVISIONS"
	autoscalerFlapTicksEnvironment               = "TS_ORCH_AUTOSCALER_FLAP_SUPPRESSION_TICKS"
	autoscalerAgentBinaryEnvironment             = "TS_ORCH_AUTOSCALER_AGENT_BINARY"
	autoscalerRunAsUidEnvironment                = "TS_ORCH_AUTOSCALER_RUN_AS_UID"
	autoscalerDrainLagEnvironment                = "TS_ORCH_AUTOSCALER_DRAIN_MAX_LAG_BYTES"
	autoscalerProviderEnvironment                = "TS_ORCH_AUTOSCALER_PROVIDER"
	autoscalerNodeCredentialDirectoryEnvironment = "TS_ORCH_AUTOSCALER_NODE_NATS_CREDENTIAL_DIRECTORY"

	autoscalerDefaultTickInterval = 10 * time.Second
	autoscalerCordonTimeout       = 2 * time.Second
	// autoscalerDrainStatusTimeout bounds the drain-status request the retire
	// gate sends: the reply observes every allocation the node still serves,
	// so it needs a wider bound than a single cordon acknowledgment.
	autoscalerDrainStatusTimeout  = 10 * time.Second
	autoscalerHeartbeatClockSkew  = 2 * time.Minute
	autoscalerMaximumTrackedNodes = 1024
	// autoscalerHeartbeatStaleTicks bounds how many tick intervals a node's
	// last heartbeat may age before the autoscaler stops counting the node in
	// its snapshots: a silent node is unschedulable evidence, not capacity.
	autoscalerHeartbeatStaleTicks = 3
	// Scheduler demand and placement observations use their own bounded
	// freshness window; stale placement always blocks drains.
	autoscalerObservationStaleTicks = 3
	globalCheckTimeout              = 30 * time.Second
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
	renderCatalog = writeCatalog
	verifyEstate  = verifyConfiguredOCIEstate
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
	if name == "autoscaler" {
		if err := verifyEstate(ctx, lookup); err != nil {
			return commandFailure(name, err)
		}
		configuration, err := autoscalerRoleConfiguration(lookup)
		if err != nil {
			return commandFailure(name, err)
		}
		if err := startAutoscalerRoleWithOutput(ctx, configuration, output); err != nil {
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
		if err := verifyEstate(ctx, lookup); err != nil {
			return commandFailure(name, err)
		}
	}

	switch options.Command {
	case control.OrchestratorCommandRun:
		err = runCommand(ctx, options)
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

func verifyConfiguredOCIEstate(ctx context.Context, lookup envLookup) error {
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
	if !estatePresent || strings.TrimSpace(estateFile) == "" {
		return errors.New("OCI estate verification configuration is required")
	}
	spec, err := provider.LoadOCIEstateSpec(estateFile)
	if err != nil {
		return err
	}
	reader, err := provider.NewOCIEstateHTTPReader(spec)
	if err != nil {
		return err
	}
	return provider.VerifyOCIEstate(ctx, spec, reader)
}

func requestedCommand(args []string) (string, error) {
	if len(args) == 0 {
		return "run", nil
	}
	if len(args) > 1 {
		return "unsupported", errors.New("orchestrator: command accepts no arguments")
	}
	switch args[0] {
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer", "autoscaler":
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
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer", "autoscaler":
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

func (e commandError) Error() string {
	if e.command == "unsupported" {
		return "orchestrator: unsupported command"
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

func runCommand(ctx context.Context, options *control.OrchestratorOptions) (result error) {
	regional, err := startRegionalRuntime(ctx, options)
	if err != nil {
		return err
	}
	if regional == nil {
		return errors.New("regional runtime starter returned nil")
	}

	var global component
	closed := false
	defer func() {
		if !closed {
			result = combineErrors(result, closeReverse(global, regional))
		}
	}()

	if options.GlobalNats != nil {
		configuration, configErr := makeGlobalConfiguration(options, regional)
		if configErr != nil {
			return configErr
		}
		global, err = startGlobalRuntime(ctx, configuration)
		if err != nil {
			return err
		}
		if global == nil {
			return errors.New("global runtime starter returned nil")
		}
	} else if options.GlobalDirectoryNats != nil {
		global, err = startDirectoryRuntime(ctx, options, regional)
		if err != nil {
			return err
		}
		if global == nil {
			return errors.New("global directory runtime starter returned nil")
		}
	}

	result = waitForComponents(ctx, regional, global)
	closed = true
	return combineErrors(result, closeReverse(global, regional))
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-completion(regional):
		return errors.New("regional runtime stopped unexpectedly")
	case <-completion(firstComponent(global)):
		return errors.New("global runtime stopped unexpectedly")
	}
}

func firstComponent(values []component) component {
	if len(values) == 0 {
		return nil
	}
	return values[0]
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
	authority, err := control.GlobalAuthorityNatsConfigurationFrom(options.GlobalNats, options.Cell)
	if err != nil {
		return nil, err
	}
	configuration := &control.GlobalNatsRuntimeConfiguration{
		Authority:            authority,
		Cell:                 options.Cell,
		Instance:             options.Instance,
		CiRunnerNatsIdentity: options.CiRunnerNatsIdentity,
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
	path, present := firstEnvironment(lookup, natsServerConfigEnvironment, natsServerConfigAliasEnvironment, natsConfigAliasEnvironment)
	if !present || strings.TrimSpace(path) == "" {
		return bootstrap.NatsServerConfig{}, errors.New("nats-server configuration file is required")
	}
	value, present := firstEnvironment(lookup, natsServerReadinessEnvironment, natsReadinessAliasEnvironment)
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

func firstEnvironment(lookup envLookup, names ...string) (string, bool) {
	if lookup == nil {
		return "", false
	}
	for _, name := range names {
		if value, present := lookup(name); present {
			return value, true
		}
	}
	return "", false
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
		{Name: "run", Description: "start the regional runtime and configured global roles"},
		{Name: "check", Description: "perform bounded regional and configured global dependency checks"},
		{Name: "nats-server", Description: "run the embedded NATS server from an explicit configuration file"},
		{Name: "catalog", Description: "render this deterministic command and configuration catalog"},
		{Name: "provision-journal", Description: "provision the infrastructure-owned operation journal"},
		{Name: "journal-writer", Description: "start the isolated authoritative journal writer"},
		{Name: "autoscaler", Description: "run the autonomous node autoscaler against the regional NATS"},
	}
	environment := []string{
		"TS_ORCH_CELL", "TS_ORCH_NATS_URL", "TS_ORCH_REPLICAS", "TS_ORCH_INSTANCE",
		"TS_ORCH_NATS_NKEY_FILE", "TS_ORCH_NATS_TLS_CA_FILE", "TS_ORCH_NATS_TLS_CERT_FILE", "TS_ORCH_NATS_TLS_KEY_FILE",
		"TS_ORCH_GLOBAL_NATS_URL", "TS_ORCH_GLOBAL_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE",
		"TS_ORCH_GLOBAL_DIRECTORY_NATS_URL", "TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS",
		"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE", "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE",
		"TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE", "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY",
		"TS_ORCH_COMMAND_SIGNING_KEY_FILE", "TS_ORCH_COMMAND_TRUST_KEY_FILES", "TS_ORCH_COMMAND_AGGREGATE_ID",
		"TS_ORCH_INFRA_NATS_NKEY_FILE", "TS_ORCH_INFRA_NATS_TLS_CA_FILE", "TS_ORCH_INFRA_NATS_TLS_CERT_FILE", "TS_ORCH_INFRA_NATS_TLS_KEY_FILE",
		"TS_ORCH_JOURNAL_NATS_NKEY_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CA_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE", "TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE", "TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE", "TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE", "TS_ORCH_JOURNAL_CONTROLLER_NKEYS",
		natsServerConfigEnvironment, natsServerReadinessEnvironment,
		natsServerConfigAliasEnvironment, natsConfigAliasEnvironment, natsReadinessAliasEnvironment,
		providerEnvironment, ociEstateFileEnvironment,
		autoscalerTickIntervalEnvironment, autoscalerMinNodesEnvironment, autoscalerMaxNodesEnvironment,
		autoscalerScaleUpHeadroomEnvironment, autoscalerScaleDownHeadroomEnvironment,
		autoscalerScaleUpTicksEnvironment, autoscalerScaleDownTicksEnvironment,
		autoscalerConcurrencyEnvironment, autoscalerFlapTicksEnvironment,
		autoscalerAgentBinaryEnvironment, autoscalerRunAsUidEnvironment, autoscalerDrainLagEnvironment,
		autoscalerProviderEnvironment,
		autoscalerNodeCredentialDirectoryEnvironment,
	}
	sort.Strings(environment)
	document := catalogDocument{SchemaVersion: 1, Commands: commands, Environment: environment}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

// autoscalerRoleSettings is the validated explicit configuration of the
// autoscaler role, resolved from the documented environment flags.
type autoscalerRoleSettings struct {
	NatsUrl                     string
	NatsNKeyFile                string
	NatsTls                     *control.NatsTlsFiles
	NodeNatsCredentialDirectory string
	TickInterval                time.Duration
	Policy                      autoscaling.AutoscalerConfig
	AgentBinaryPath             string
	RunAsUid                    uint32
	DrainMaxLagBytes            int64
}

// autoscalerRequiredEnvironment reads one required configuration value.
func autoscalerRequiredEnvironment(lookup envLookup, name string) (string, error) {
	value, present := lookup(name)
	if !present || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("autoscaler: %s is required", name)
	}
	return value, nil
}

// autoscalerRequiredInt reads one required integer configuration value.
func autoscalerRequiredInt(lookup envLookup, name string) (int, error) {
	value, err := autoscalerRequiredEnvironment(lookup, name)
	if err != nil {
		return 0, err
	}
	parsed, parseErr := strconv.Atoi(value)
	if parseErr != nil {
		return 0, fmt.Errorf("autoscaler: %s must be an integer", name)
	}
	return parsed, nil
}

// autoscalerRoleConfiguration resolves and validates every autoscaler flag
// through the injected environment lookup: the regional NATS URL, the tick
// interval (defaulting to the documented cadence), the eight policy knobs of
// the scaling config, the node-agent binary path and unprivileged run uid of
// the local process provisioner, and the drain lag bound of the stateful
// replica evaluator. Nothing is defaulted silently except the tick interval.
func autoscalerRoleConfiguration(lookup envLookup) (autoscalerRoleSettings, error) {
	if lookup == nil {
		return autoscalerRoleSettings{}, errors.New("autoscaler: environment lookup is required")
	}
	natsUrl, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_URL")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	if strings.HasPrefix(natsUrl, "-") || strings.ContainsAny(natsUrl, " \t\n") {
		return autoscalerRoleSettings{}, errors.New("autoscaler: TS_ORCH_NATS_URL must be whitespace-free and flag-safe")
	}
	parsedNatsURL, parseErr := url.Parse(natsUrl)
	if parseErr != nil || !parsedNatsURL.IsAbs() || parsedNatsURL.Scheme != "tls" || parsedNatsURL.Host == "" || parsedNatsURL.User != nil || parsedNatsURL.RawQuery != "" || parsedNatsURL.Fragment != "" {
		return autoscalerRoleSettings{}, errors.New("autoscaler: TS_ORCH_NATS_URL must be an absolute tls:// URL")
	}
	nkeyValue, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_NKEY_FILE")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	nkeyPath, err := control.NatsCredentialFile.Resolve(nkeyValue, "TS_ORCH_NATS_NKEY_FILE")
	if err != nil || nkeyPath == "" {
		return autoscalerRoleSettings{}, errors.New("autoscaler: TS_ORCH_NATS_NKEY_FILE is invalid")
	}
	tlsCA, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_TLS_CA_FILE")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	tlsCert, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_TLS_CERT_FILE")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	tlsKey, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_TLS_KEY_FILE")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	tlsFiles, err := control.NatsTlsFilesResolve(tlsCA, tlsCert, tlsKey, "TS_ORCH_NATS_TLS")
	if err != nil || tlsFiles == nil {
		return autoscalerRoleSettings{}, errors.New("autoscaler: TS_ORCH_NATS_TLS credentials are invalid")
	}
	nodeCredentialDirectory, err := autoscalerRequiredEnvironment(lookup, autoscalerNodeCredentialDirectoryEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	if err := autoscalerValidateCredentialDirectory(nodeCredentialDirectory); err != nil {
		return autoscalerRoleSettings{}, err
	}
	if err := autoscalerRequireLocalDevProvider(lookup); err != nil {
		return autoscalerRoleSettings{}, err
	}
	tickInterval := autoscalerDefaultTickInterval
	if value, present := lookup(autoscalerTickIntervalEnvironment); present {
		parsed, parseErr := time.ParseDuration(value)
		if parseErr != nil || parsed <= 0 {
			return autoscalerRoleSettings{}, fmt.Errorf(
				"autoscaler: %s must be a positive duration", autoscalerTickIntervalEnvironment)
		}
		tickInterval = parsed
	}
	minNodes, err := autoscalerRequiredInt(lookup, autoscalerMinNodesEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	maxNodes, err := autoscalerRequiredInt(lookup, autoscalerMaxNodesEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	scaleUpHeadroom, err := autoscalerRequiredInt(lookup, autoscalerScaleUpHeadroomEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	scaleDownHeadroom, err := autoscalerRequiredInt(lookup, autoscalerScaleDownHeadroomEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	scaleUpTicks, err := autoscalerRequiredInt(lookup, autoscalerScaleUpTicksEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	scaleDownTicks, err := autoscalerRequiredInt(lookup, autoscalerScaleDownTicksEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	concurrency, err := autoscalerRequiredInt(lookup, autoscalerConcurrencyEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	flapTicks, err := autoscalerRequiredInt(lookup, autoscalerFlapTicksEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	policy, err := autoscaling.NewAutoscalerConfig(
		minNodes, maxNodes, scaleUpHeadroom, scaleDownHeadroom,
		scaleUpTicks, scaleDownTicks, concurrency, flapTicks)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	agentBinary, err := autoscalerRequiredEnvironment(lookup, autoscalerAgentBinaryEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	if len(agentBinary) > 4096 || !strings.HasPrefix(agentBinary, "/") || strings.Contains(agentBinary, "/../") {
		return autoscalerRoleSettings{}, fmt.Errorf(
			"autoscaler: %s must be a bounded absolute path", autoscalerAgentBinaryEnvironment)
	}
	runAsUidValue, err := autoscalerRequiredEnvironment(lookup, autoscalerRunAsUidEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	runAsUidParsed, parseErr := strconv.ParseUint(runAsUidValue, 10, 32)
	if parseErr != nil || runAsUidParsed == 0 {
		return autoscalerRoleSettings{}, fmt.Errorf(
			"autoscaler: %s must be a nonzero numeric uid", autoscalerRunAsUidEnvironment)
	}
	drainLagValue, err := autoscalerRequiredEnvironment(lookup, autoscalerDrainLagEnvironment)
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	drainLag, parseErr := strconv.ParseInt(drainLagValue, 10, 64)
	if parseErr != nil || drainLag < 1 {
		return autoscalerRoleSettings{}, fmt.Errorf(
			"autoscaler: %s must be a positive byte count", autoscalerDrainLagEnvironment)
	}
	return autoscalerRoleSettings{
		NatsUrl:                     natsUrl,
		NatsNKeyFile:                nkeyPath,
		NatsTls:                     tlsFiles,
		NodeNatsCredentialDirectory: nodeCredentialDirectory,
		TickInterval:                tickInterval,
		Policy:                      policy,
		AgentBinaryPath:             agentBinary,
		RunAsUid:                    uint32(runAsUidParsed),
		DrainMaxLagBytes:            drainLag,
	}, nil
}

func autoscalerRequireLocalDevProvider(lookup envLookup) error {
	provider, err := autoscalerRequiredEnvironment(lookup, autoscalerProviderEnvironment)
	if err != nil {
		return err
	}
	if provider != "local-dev" {
		return fmt.Errorf("autoscaler: %s must be local-dev; no persistent provider is wired in this stage",
			autoscalerProviderEnvironment)
	}
	return nil
}

func autoscalerValidateCredentialDirectory(value string) error {
	if len(value) < 2 || len(value) > 4096 || !strings.HasPrefix(value, "/") {
		return fmt.Errorf("autoscaler: %s must be a bounded absolute directory", autoscalerNodeCredentialDirectoryEnvironment)
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, " \t\r\n%") {
			return fmt.Errorf("autoscaler: %s contains an invalid path segment", autoscalerNodeCredentialDirectoryEnvironment)
		}
	}
	return nil
}

// autoscalerNodeEntry is the autoscaler's tracked view of one node: its
// lifecycle state, its latest heartbeat metric sample, and when that
// heartbeat arrived.
type autoscalerNodeEntry struct {
	nodeId               string
	state                autoscaling.NodeState
	metrics              hostagent.NodeMetricsSample
	lastHeartbeat        time.Time
	lastHeartbeatUnixSec int64
	replicas             []stateful.ReplicaHealth
}

// autoscalerRole is the control-plane runtime of the autoscaler command: it
// collects node heartbeats from the regional NATS, ticks the deterministic
// autoscaling engine every interval, and executes the emitted actions through
// the local process provisioner and the node subjects. It also implements the
// engine's drain safety seam by adapting the stateful replica evaluator with
// the peer candidates observed on every other node.
type autoscalerRole struct {
	settings           autoscalerRoleSettings
	output             io.Writer
	connection         *nats.Conn
	provisioner        autoscaling.NodeProvisioner
	replicaDrains      *stateful.ReplicaDrainSafetyEvaluator
	replicaHealthReady bool
	// observation is the latest validated scheduler/placement feed. Demand and
	// placement completeness are independent so scale-up may consume current
	// demand while drain safety remains fail-closed until placement is complete.
	observation        autoscaling.AutoscalerObservationFeed
	observationAt      time.Time
	observationUnixSec int64
	engine             *autoscaling.Autoscaler
	mutex              sync.Mutex
	nodes              map[string]*autoscalerNodeEntry
}

// EvaluateDrainSafety adapts the engine's drain seam onto the stateful
// replica evaluator: the candidate node is evaluated against the replicas
// tracked on every other non-retired node.
func (r *autoscalerRole) EvaluateDrainSafety(
	ctx context.Context,
	candidate stateful.NodeDrainCandidate,
) (stateful.DrainDecision, error) {
	if ctx == nil {
		return stateful.DrainDecision{}, errors.New("autoscaler: the drain safety context must not be nil")
	}
	if r == nil || r.replicaDrains == nil {
		return stateful.DrainDecision{}, errors.New("autoscaler: the replica drain evaluator is unavailable")
	}
	r.mutex.Lock()
	placementReady := r.replicaHealthReady
	r.mutex.Unlock()
	if !placementReady {
		return stateful.NewDrainDecision(false,
			"Replica placement health is unavailable; node drain is deferred.", nil)
	}
	return r.replicaDrains.EvaluateDrainSafety(candidate, r.peerCandidates(candidate.NodeId))
}

// peerCandidates returns the drain candidates of every other tracked node,
// including the latest complete placement feed's replica observations.
func (r *autoscalerRole) peerCandidates(excluded string) []stateful.NodeDrainCandidate {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	peers := make([]stateful.NodeDrainCandidate, 0, len(r.nodes))
	for nodeId, entry := range r.nodes {
		if nodeId == excluded || entry.state == autoscaling.NodeStateRetired {
			continue
		}
		peer, err := stateful.NewNodeDrainCandidate(nodeId, entry.replicas)
		if err != nil {
			// Unreachable for a heartbeat-validated node token; skip.
			continue
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(left, right int) bool {
		return peers[left].NodeId < peers[right].NodeId
	})
	return peers
}

// handleHeartbeat folds one published node heartbeat into the node table. A
// malformed heartbeat is dropped rather than trusted, and a retired node
// stays retired.
func (r *autoscalerRole) handleHeartbeat(message *nats.Msg) {
	if r == nil || message == nil {
		return
	}
	parts := strings.Split(message.Subject, ".")
	if len(parts) != 5 || parts[0] != "terrascale" || parts[1] != "node" ||
		parts[2] != "v1" || parts[4] != hostagent.NatsSubjectLeafHeartbeat {
		return
	}
	subjectNode, err := hostagent.NewNodeId(parts[3])
	if err != nil {
		return
	}
	var heartbeat hostagent.NodeHeartbeat
	if err := json.Unmarshal(message.Data, &heartbeat); err != nil {
		return
	}
	if heartbeat.NodeId != subjectNode {
		// The wildcard subscription is not an identity proof. Bind the
		// payload to the node token in the subject before trusting metrics.
		return
	}
	now := time.Now()
	if heartbeat.UnixSeconds < now.Add(-autoscalerHeartbeatClockSkew).Unix() ||
		heartbeat.UnixSeconds > now.Add(autoscalerHeartbeatClockSkew).Unix() {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.nodes == nil {
		r.nodes = make(map[string]*autoscalerNodeEntry)
	}
	entry, present := r.nodes[heartbeat.NodeId.Value]
	if present && entry.state == autoscaling.NodeStateRetired {
		return
	}
	if !present {
		if len(r.nodes) >= autoscalerMaximumTrackedNodes {
			return
		}
		entry = &autoscalerNodeEntry{
			nodeId: heartbeat.NodeId.Value,
			state:  autoscaling.NodeStateReady,
		}
		r.nodes[heartbeat.NodeId.Value] = entry
	}
	if present && heartbeat.UnixSeconds <= entry.lastHeartbeatUnixSec {
		return
	}
	entry.metrics = heartbeat.Metrics
	entry.lastHeartbeat = now
	entry.lastHeartbeatUnixSec = heartbeat.UnixSeconds
}

// handleObservationFeed folds one scheduler/placement publication into the
// role. Malformed, future, stale-by-arrival, or replayed publications are not
// trusted. Freshness is checked again when a tick builds its snapshot.
func (r *autoscalerRole) handleObservationFeed(message *nats.Msg) {
	if r == nil || message == nil || message.Subject != autoscaling.AutoscalerObservationSubject {
		return
	}
	var feed autoscaling.AutoscalerObservationFeed
	if err := json.Unmarshal(message.Data, &feed); err != nil {
		return
	}
	now := time.Now()
	if feed.UnixSeconds < now.Add(-autoscalerHeartbeatClockSkew).Unix() ||
		feed.UnixSeconds > now.Add(autoscalerHeartbeatClockSkew).Unix() {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if feed.UnixSeconds <= r.observationUnixSec {
		return
	}
	r.observation = feed
	r.observationAt = now
	r.observationUnixSec = feed.UnixSeconds
	// snapshot computes coverage against the currently fresh heartbeat set.
	r.replicaHealthReady = false
}

// setState records one lifecycle transition of a tracked node, creating the
// entry when the node has not heartbeated yet.
func (r *autoscalerRole) setState(nodeId string, state autoscaling.NodeState) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.nodes == nil {
		r.nodes = make(map[string]*autoscalerNodeEntry)
	}
	entry, present := r.nodes[nodeId]
	if !present {
		r.nodes[nodeId] = &autoscalerNodeEntry{nodeId: nodeId, state: state, lastHeartbeat: time.Now()}
		return
	}
	entry.state = state
}

// snapshot derives the validated cluster observation of one tick from fresh
// host heartbeats and the latest scheduler/placement feed. Demand is included
// only when its feed is fresh and complete. Replica health is included only
// when a fresh complete placement view covers every node in this snapshot;
// otherwise the role marks placement unavailable and drains fail closed.
func (r *autoscalerRole) snapshot(now time.Time) autoscaling.AutoscalerSnapshot {
	staleness := autoscalerHeartbeatStaleTicks * r.settings.TickInterval
	if staleness <= 0 {
		staleness = autoscalerHeartbeatStaleTicks * autoscalerDefaultTickInterval
	}
	feedStaleness := autoscalerObservationStaleTicks * r.settings.TickInterval
	if feedStaleness <= 0 {
		feedStaleness = autoscalerObservationStaleTicks * autoscalerDefaultTickInterval
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	nodes := make([]autoscaling.NodeObservation, 0, len(r.nodes))
	freshNodes := make(map[string]struct{}, len(r.nodes))
	for _, entry := range r.nodes {
		// Arrival freshness alone is insufficient: a delayed heartbeat with an
		// old event timestamp could otherwise keep a dead node schedulable.
		// Require both transport arrival and the producer's event timestamp to
		// be inside the bounded window. The timestamp is second precision, so
		// this deliberately fails closed for sub-second windows.
		eventAge := now.Sub(time.Unix(entry.lastHeartbeatUnixSec, 0))
		if entry.lastHeartbeatUnixSec <= 0 || now.Sub(entry.lastHeartbeat) > staleness ||
			now.Sub(entry.lastHeartbeat) < -autoscalerHeartbeatClockSkew ||
			eventAge > staleness || eventAge < -autoscalerHeartbeatClockSkew {
			continue
		}
		_, capacityErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryTotalBytes, entry.metrics.CpuQuotaPercent, entry.metrics.TasksMax)
		_, usageErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryUsedBytes, entry.metrics.CpuUsedPercent, entry.metrics.TasksRunning)
		if capacityErr != nil || usageErr != nil {
			// Unreachable for a heartbeat-validated metric sample; skip.
			continue
		}
		freshNodes[entry.nodeId] = struct{}{}
	}
	feedAge := now.Sub(time.Unix(r.observationUnixSec, 0))
	feedFresh := r.observationUnixSec > 0 && !r.observationAt.IsZero() &&
		now.Sub(r.observationAt) <= feedStaleness &&
		now.Sub(r.observationAt) >= -autoscalerHeartbeatClockSkew &&
		feedAge >= 0 && feedAge <= feedStaleness
	placements := make(map[string][]stateful.ReplicaHealth, len(r.observation.Placements))
	placementComplete := feedFresh && r.observation.PlacementComplete
	if placementComplete {
		for nodeId, entry := range r.nodes {
			if entry.state == autoscaling.NodeStateRetired {
				continue
			}
			if _, fresh := freshNodes[nodeId]; !fresh {
				// A tracked node with no current heartbeat/metrics is an
				// unknown placement surface. Do not treat it as empty.
				placementComplete = false
				break
			}
		}
	}
	if placementComplete {
		for _, placement := range r.observation.Placements {
			if _, known := freshNodes[placement.NodeId]; !known {
				placementComplete = false
				break
			}
			placements[placement.NodeId] = append([]stateful.ReplicaHealth(nil), placement.Replicas...)
		}
		if placementComplete && len(placements) != len(freshNodes) {
			placementComplete = false
		}
	}
	demand := []autoscaling.AllocationDemand(nil)
	if feedFresh && r.observation.DemandComplete {
		demand = append(demand, r.observation.Demand...)
	}
	for _, entry := range r.nodes {
		if _, fresh := freshNodes[entry.nodeId]; !fresh {
			entry.replicas = nil
			continue
		}
		capacity, capacityErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryTotalBytes, entry.metrics.CpuQuotaPercent, entry.metrics.TasksMax)
		usage, usageErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryUsedBytes, entry.metrics.CpuUsedPercent, entry.metrics.TasksRunning)
		if capacityErr != nil || usageErr != nil {
			entry.replicas = nil
			continue
		}
		replicas := []stateful.ReplicaHealth(nil)
		if placementComplete {
			replicas = placements[entry.nodeId]
		}
		entry.replicas = append([]stateful.ReplicaHealth(nil), replicas...)
		observation, err := autoscaling.NewNodeObservation(
			entry.nodeId, entry.state, capacity, usage,
			entry.metrics.PendingAllocations, replicas)
		if err != nil {
			continue
		}
		nodes = append(nodes, observation)
	}
	r.replicaHealthReady = placementComplete
	return autoscaling.AutoscalerSnapshot{Nodes: nodes, Demand: demand}
}

// apply executes one autoscaler action. Every application is fail-closed: a
// failed provision, cordon, or retire surfaces to the run loop and stops the
// role instead of being retried blind.
func (r *autoscalerRole) apply(ctx context.Context, action autoscaling.AutoscalerAction) error {
	if r == nil {
		return errors.New("autoscaler: the role is unavailable")
	}
	switch action.Kind() {
	case autoscaling.AutoscalerActionProvisionNode:
		if r.provisioner == nil {
			return errors.New("autoscaler: the node provisioner is unavailable")
		}
		if err := r.provisioner.Provision(ctx, action.ProvisionRequest()); err != nil {
			// The provisioner explicitly reported the failure: release the
			// engine's remembered reservation so it stops counting against the
			// provisioning capacity, then surface the failure fail-closed.
			if r.engine != nil {
				_ = r.engine.RefuteProvision(action.ProvisionRequest().NodeId)
			}
			return err
		}
		return nil
	case autoscaling.AutoscalerActionCordonNode:
		if r.connection == nil {
			return errors.New("autoscaler: the NATS connection is unavailable")
		}
		if err := r.cordonNode(action.NodeId()); err != nil {
			return err
		}
		r.setState(action.NodeId(), autoscaling.NodeStateCordoned)
		return nil
	case autoscaling.AutoscalerActionDrainNode:
		// The drain sequence parks the node in Draining: its allocations stop
		// through the scheduler's relocation and the retire gate observes the
		// quiet node on later ticks.
		r.setState(action.NodeId(), autoscaling.NodeStateDraining)
		return nil
	case autoscaling.AutoscalerActionRetireNode:
		if r.provisioner == nil {
			return errors.New("autoscaler: the node provisioner is unavailable")
		}
		if err := r.requireDrained(action.NodeId()); err != nil {
			return err
		}
		if r.output != nil {
			if _, err := fmt.Fprintf(r.output, "autoscaler action=RetireNode node=%s\n", action.NodeId()); err != nil {
				return err
			}
		}
		if err := r.provisioner.Retire(ctx, action.NodeId()); err != nil {
			return err
		}
		r.setState(action.NodeId(), autoscaling.NodeStateRetired)
		return nil
	default:
		return fmt.Errorf("autoscaler: the action kind %s is not executed by this role", action.Kind())
	}
}

// autoscalerCommandId derives the bounded command token of one autoscaler
// message from its prefix and target node: the node id is folded into a
// sixteen-character digest, so even a node id at the 63-character token bound
// cannot push the command id past the length bound NewCordonCommand and
// NewNodeStatusRequest enforce.
func autoscalerCommandId(prefix string, nodeId string) string {
	digest := sha256.Sum256([]byte(nodeId))
	return prefix + hex.EncodeToString(digest[:8])
}

// requireDrained proves through the node's own drain-status subject that the
// node is cordoned and fully drained before it may be retired. The heartbeat
// gauge alone is node-local evidence; the drain-status report is the
// node-scoped observation of every allocation the agent still tracks, so
// retiring a node whose containers still run - which would strand them on a
// retired node - is not expressible. An unreachable or malformed answer fails
// closed.
func (r *autoscalerRole) requireDrained(nodeId string) error {
	if r == nil || r.connection == nil {
		return errors.New("autoscaler: the NATS connection is unavailable")
	}
	request, err := hostagent.NewNodeStatusRequest(autoscalerCommandId("autoscaler-drain-status-", nodeId))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	identity, err := hostagent.NewNodeId(nodeId)
	if err != nil {
		return err
	}
	subject, err := hostagent.NodeDrainStatusSubject(identity)
	if err != nil {
		return err
	}
	reply, err := r.connection.Request(subject, payload, autoscalerDrainStatusTimeout)
	if err != nil {
		return fmt.Errorf("autoscaler: the drain status of node %s could not be observed: %s",
			nodeId, err.Error())
	}
	var report hostagent.DrainStatusReport
	if err := json.Unmarshal(reply.Data, &report); err != nil {
		return fmt.Errorf("autoscaler: node %s returned a malformed drain-status report", nodeId)
	}
	if report.CommandId != request.CommandId || report.NodeId != nodeId || !report.Cordoned || !report.Drained {
		return fmt.Errorf("autoscaler: node %s is not drained and must not be retired", nodeId)
	}
	return nil
}

// cordonNode delivers one cordon command to the node agent over the regional
// NATS and requires the agent's acknowledgment before the state transition.
func (r *autoscalerRole) cordonNode(nodeId string) error {
	if r == nil || r.connection == nil {
		return errors.New("autoscaler: the NATS connection is unavailable")
	}
	command, err := hostagent.NewCordonCommand(autoscalerCommandId("autoscaler-cordon-", nodeId), true)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return err
	}
	identity, err := hostagent.NewNodeId(nodeId)
	if err != nil {
		return err
	}
	subject, err := hostagent.NodeCordonSubject(identity)
	if err != nil {
		return err
	}
	reply, err := r.connection.Request(subject, payload, autoscalerCordonTimeout)
	if err != nil {
		return fmt.Errorf("autoscaler: the cordon of node %s failed: %s", nodeId, err.Error())
	}
	var acknowledgment hostagent.CordonAcknowledgment
	if err := json.Unmarshal(reply.Data, &acknowledgment); err != nil {
		return fmt.Errorf("autoscaler: the cordon of node %s returned a malformed acknowledgment", nodeId)
	}
	if acknowledgment.CommandId != command.CommandId || !acknowledgment.Cordoned || acknowledgment.NodeId != nodeId {
		return fmt.Errorf("autoscaler: node %s did not acknowledge its cordon", nodeId)
	}
	return nil
}

// reassertCordons re-delivers the cordon command to every node the control
// plane believes is Cordoned or Draining. The agent keeps its cordon flag in
// memory only, so an agent restart would otherwise silently un-cordon a
// draining node and let it accept new Converge work; cordon is idempotent and
// acknowledged, so asserting it on every tick is safe.
func (r *autoscalerRole) reassertCordons() error {
	if r == nil {
		return errors.New("autoscaler: the role is unavailable")
	}
	r.mutex.Lock()
	targets := make([]string, 0, len(r.nodes))
	for nodeId, entry := range r.nodes {
		if entry.state == autoscaling.NodeStateCordoned || entry.state == autoscaling.NodeStateDraining {
			targets = append(targets, nodeId)
		}
	}
	r.mutex.Unlock()
	if len(targets) == 0 {
		return nil
	}
	if r.connection == nil {
		return errors.New("autoscaler: the NATS connection is unavailable")
	}
	sort.Strings(targets)
	for _, nodeId := range targets {
		if err := r.cordonNode(nodeId); err != nil {
			return err
		}
	}
	return nil
}

// tick runs one autoscaler tick over the current snapshot and applies every
// emitted action in the tick's canonical order. Cordoned and draining nodes
// have their cordon re-asserted first, so a restarted agent cannot silently
// slip back into accepting work.
func (r *autoscalerRole) tick(ctx context.Context, now time.Time) error {
	if r == nil || r.engine == nil {
		return errors.New("autoscaler: the engine is unavailable")
	}
	if ctx == nil {
		return errors.New("autoscaler: the tick context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.reassertCordons(); err != nil {
		return err
	}
	actions, err := r.engine.Tick(ctx, r.snapshot(now))
	if err != nil {
		return err
	}
	for _, action := range actions {
		if err := r.apply(ctx, action); err != nil {
			return err
		}
	}
	return nil
}

// autoscalerNodeAgentArgumentsForNode resolves a distinct credential set for
// one node. Files are named <node>.seed, <node>.ca.pem, <node>.pem, and
// <node>.key in the configured private directory.
func autoscalerNodeAgentArgumentsForNode(settings autoscalerRoleSettings, nodeId string) ([]string, error) {
	if _, err := hostagent.NewNodeId(nodeId); err != nil {
		return nil, fmt.Errorf("autoscaler: node id is invalid: %w", err)
	}
	if settings.NatsNKeyFile == "" || settings.NatsTls == nil {
		return nil, errors.New("autoscaler: controller NATS credentials are unavailable")
	}
	if err := autoscalerValidateCredentialDirectory(settings.NodeNatsCredentialDirectory); err != nil {
		return nil, err
	}
	directory := settings.NodeNatsCredentialDirectory
	nodeNkey, err := control.NatsCredentialFile.Resolve(filepath.Join(directory, nodeId+".seed"), directory)
	if err != nil {
		return nil, fmt.Errorf("autoscaler: node %s NKey credentials are invalid", nodeId)
	}
	nodeTLS, err := control.NatsTlsFilesResolve(
		filepath.Join(directory, nodeId+".ca.pem"),
		filepath.Join(directory, nodeId+".pem"),
		filepath.Join(directory, nodeId+".key"),
		"TS_ORCH_AUTOSCALER_NODE_NATS_TLS")
	if err != nil || nodeTLS == nil {
		return nil, fmt.Errorf("autoscaler: node %s TLS credentials are invalid", nodeId)
	}
	sameNkey, err := control.NatsCredentialFile.SameIdentity(settings.NatsNKeyFile, nodeNkey)
	if err != nil || sameNkey || settings.NatsTls.SameIdentity(nodeTLS) {
		return nil, fmt.Errorf("autoscaler: node %s credentials must be distinct from the autoscaler", nodeId)
	}
	return []string{
		"--nats-nkey-file", nodeNkey,
		"--nats-tls-ca-file", nodeTLS.CaFile,
		"--nats-tls-cert-file", nodeTLS.CertificateFile,
		"--nats-tls-key-file", nodeTLS.KeyFile,
	}, nil
}

type autoscalerNodeAgentIdentity struct {
	publicKey string
	tls       *control.NatsTlsFiles
}

// autoscalerNodeAgentArgumentsState tracks identities that belong to live
// children. Resolve only validates and checks the current committed set; it
// deliberately does not reserve an identity because the child may never
// start. Commit is called by the process provisioner after Spawn succeeds.
type autoscalerNodeAgentArgumentsState struct {
	settings  autoscalerRoleSettings
	mutex     sync.Mutex
	usedNKeys map[string]struct{}
	usedTLS   []*control.NatsTlsFiles
	usedNodes map[string]autoscalerNodeAgentIdentity
}

func newAutoscalerNodeAgentArgumentsState(settings autoscalerRoleSettings) *autoscalerNodeAgentArgumentsState {
	return &autoscalerNodeAgentArgumentsState{
		settings:  settings,
		usedNKeys: make(map[string]struct{}),
		usedTLS:   make([]*control.NatsTlsFiles, 0),
		usedNodes: make(map[string]autoscalerNodeAgentIdentity),
	}
}

func autoscalerNodeAgentIdentityForArguments(nodeId string, arguments []string) (autoscalerNodeAgentIdentity, error) {
	if len(arguments) < 8 {
		return autoscalerNodeAgentIdentity{}, fmt.Errorf("autoscaler: node %s credentials are incomplete", nodeId)
	}
	publicKey, err := control.NatsCredentialFile.PublicKey(arguments[1])
	if err != nil {
		return autoscalerNodeAgentIdentity{}, fmt.Errorf("autoscaler: node %s NKey credentials are invalid", nodeId)
	}
	nodeTLS, err := control.NatsTlsFilesResolve(arguments[3], arguments[5], arguments[7], "TS_ORCH_AUTOSCALER_NODE_NATS_TLS")
	if err != nil || nodeTLS == nil {
		return autoscalerNodeAgentIdentity{}, fmt.Errorf("autoscaler: node %s TLS credentials are invalid", nodeId)
	}
	return autoscalerNodeAgentIdentity{publicKey: publicKey, tls: nodeTLS}, nil
}

func (s *autoscalerNodeAgentArgumentsState) resolve(nodeId string) ([]string, error) {
	if s == nil {
		return nil, errors.New("autoscaler: node credential state is unavailable")
	}
	arguments, err := autoscalerNodeAgentArgumentsForNode(s.settings, nodeId)
	if err != nil {
		return nil, err
	}
	identity, err := autoscalerNodeAgentIdentityForArguments(nodeId, arguments)
	if err != nil {
		return nil, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, used := s.usedNKeys[identity.publicKey]; used {
		return nil, fmt.Errorf("autoscaler: node %s reuses another node's NKey identity", nodeId)
	}
	for _, usedTLSFiles := range s.usedTLS {
		if usedTLSFiles.SameIdentity(identity.tls) {
			return nil, fmt.Errorf("autoscaler: node %s reuses another node's TLS identity", nodeId)
		}
	}
	return arguments, nil
}

// commit marks an identity only after the process spawner has returned a
// positive pid. Rechecking under the state lock preserves uniqueness even if
// a caller invokes the state callbacks concurrently.
func (s *autoscalerNodeAgentArgumentsState) commit(nodeId string, arguments []string) error {
	if s == nil {
		return errors.New("autoscaler: node credential state is unavailable")
	}
	identity, err := autoscalerNodeAgentIdentityForArguments(nodeId, arguments)
	if err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, used := s.usedNodes[nodeId]; used {
		return fmt.Errorf("autoscaler: node %s already owns a node identity", nodeId)
	}
	if _, used := s.usedNKeys[identity.publicKey]; used {
		return fmt.Errorf("autoscaler: node %s reuses another node's NKey identity", nodeId)
	}
	for _, usedTLSFiles := range s.usedTLS {
		if usedTLSFiles.SameIdentity(identity.tls) {
			return fmt.Errorf("autoscaler: node %s reuses another node's TLS identity", nodeId)
		}
	}
	s.usedNKeys[identity.publicKey] = struct{}{}
	s.usedTLS = append(s.usedTLS, identity.tls)
	s.usedNodes[nodeId] = identity
	return nil
}

// release returns an identity to the available set after its child has
// terminated. A termination failure never calls this method, so a still-live
// child cannot race a reprovision into reusing its credentials.
func (s *autoscalerNodeAgentArgumentsState) release(nodeId string) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	identity, found := s.usedNodes[nodeId]
	if !found {
		return
	}
	delete(s.usedNodes, nodeId)
	delete(s.usedNKeys, identity.publicKey)
	for index, usedTLSFiles := range s.usedTLS {
		if usedTLSFiles == identity.tls || usedTLSFiles.SameIdentity(identity.tls) {
			s.usedTLS = append(s.usedTLS[:index], s.usedTLS[index+1:]...)
			break
		}
	}
}

// rollback is intentionally a no-op for committed identity state: resolve
// never reserves identities. It remains a callback so the provisioner can
// uniformly release tentative state if the resolver grows such state later.
func (s *autoscalerNodeAgentArgumentsState) rollback(string, []string) {}

func autoscalerNodeAgentArgumentsResolver(settings autoscalerRoleSettings) func(string) ([]string, error) {
	return newAutoscalerNodeAgentArgumentsState(settings).resolve
}

// startAutoscalerRole composes and runs the autoscaler against the regional
// NATS until the context is cancelled: it subscribes to every node heartbeat,
// builds the deterministic engine with the stateful drain gate and the local
// process provisioner, and executes one tick per interval. A tick or action
// failure stops the role fail-closed.
func startAutoscalerRole(ctx context.Context, settings autoscalerRoleSettings) error {
	return startAutoscalerRoleWithOutput(ctx, settings, os.Stdout)
}

func startAutoscalerRoleWithOutput(ctx context.Context, settings autoscalerRoleSettings, output io.Writer) (result error) {
	if ctx == nil {
		return errors.New("autoscaler: the role context must not be nil")
	}
	authentication, err := control.NatsAuthenticationFilesFromNKeyFile(settings.NatsNKeyFile)
	if err != nil {
		return errors.New("autoscaler: NATS authentication is unavailable")
	}
	connection, err := control.NatsConnect(ctx, control.NatsConnectionConfiguration{
		URL: settings.NatsUrl, Authentication: authentication, TLS: settings.NatsTls,
		Timeout: 5 * time.Second, MaxReconnects: -1,
	})
	if err != nil {
		return err
	}
	defer func() {
		// Drain subscriptions before closing so a cancellation cannot leave
		// heartbeat or scheduler-feed callbacks active against torn-down role
		// state. Close remains the final fallback if draining fails.
		_ = connection.Drain()
		connection.Close()
	}()
	role := &autoscalerRole{
		settings:   settings,
		output:     output,
		connection: connection,
		nodes:      make(map[string]*autoscalerNodeEntry),
	}
	drainPolicy, err := stateful.NewDrainPolicy(settings.DrainMaxLagBytes)
	if err != nil {
		return err
	}
	role.replicaDrains, err = stateful.NewReplicaDrainSafetyEvaluator(drainPolicy)
	if err != nil {
		return err
	}
	spawner, err := autoscaling.NewCommandProcessSpawner(10 * time.Second)
	if err != nil {
		return err
	}
	provisionerConfig, err := autoscaling.NewLocalProcessProvisionerConfig(
		settings.AgentBinaryPath, settings.NatsUrl, []string{"--heartbeat-interval", "1s"}, settings.RunAsUid)
	if err != nil {
		return err
	}
	nodeArguments := newAutoscalerNodeAgentArgumentsState(settings)
	provisionerConfig.AgentArgumentsForNode = nodeArguments.resolve
	provisionerConfig.AgentArgumentsForNodeCommit = nodeArguments.commit
	provisionerConfig.AgentArgumentsForNodeRollback = nodeArguments.rollback
	provisionerConfig.AgentArgumentsForNodeRelease = nodeArguments.release
	role.provisioner, err = autoscaling.NewLocalProcessNodeProvisioner(provisionerConfig, spawner)
	if err != nil {
		return err
	}
	defer func() {
		if shutdowner, ok := role.provisioner.(autoscaling.NodeProvisionerShutdown); ok {
			result = combineErrors(result, shutdowner.Shutdown(context.Background()))
		}
	}()
	role.engine, err = autoscaling.NewAutoscaler(settings.Policy, role)
	if err != nil {
		return err
	}
	subscription, err := connection.Subscribe(
		hostagent.NatsSubjectNodePrefix+".*."+hostagent.NatsSubjectLeafHeartbeat,
		role.handleHeartbeat)
	if err != nil {
		return err
	}
	defer func() { _ = subscription.Unsubscribe() }()
	observationSubscription, err := connection.Subscribe(
		autoscaling.AutoscalerObservationSubject, role.handleObservationFeed)
	if err != nil {
		return err
	}
	defer func() { _ = observationSubscription.Unsubscribe() }()
	if err := connection.Flush(); err != nil {
		return err
	}
	ticker := time.NewTicker(settings.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if err := role.tick(ctx, now); err != nil {
				return err
			}
		}
	}
}
