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
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

const (
	natsServerConfigEnvironment      = "TS_ORCH_NATS_SERVER_CONFIG_FILE"
	natsServerReadinessEnvironment   = "TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"
	natsServerConfigAliasEnvironment = "TS_ORCH_NATS_SERVER_CONFIG"
	natsConfigAliasEnvironment       = "TS_ORCH_NATS_CONFIG_FILE"
	natsReadinessAliasEnvironment    = "TS_ORCH_NATS_READINESS_TIMEOUT"

	// The documented explicit configuration flags of the autoscaler role.
	// Every value is read through the injected environment lookup, mirroring
	// the nats-server role; nothing is discovered ambiently.
	autoscalerTickIntervalEnvironment      = "TS_ORCH_AUTOSCALER_TICK_INTERVAL"
	autoscalerMinNodesEnvironment          = "TS_ORCH_AUTOSCALER_MIN_NODES"
	autoscalerMaxNodesEnvironment          = "TS_ORCH_AUTOSCALER_MAX_NODES"
	autoscalerScaleUpHeadroomEnvironment   = "TS_ORCH_AUTOSCALER_SCALE_UP_HEADROOM_PERCENT"
	autoscalerScaleDownHeadroomEnvironment = "TS_ORCH_AUTOSCALER_SCALE_DOWN_HEADROOM_PERCENT"
	autoscalerScaleUpTicksEnvironment      = "TS_ORCH_AUTOSCALER_SCALE_UP_CONFIRM_TICKS"
	autoscalerScaleDownTicksEnvironment    = "TS_ORCH_AUTOSCALER_SCALE_DOWN_CONFIRM_TICKS"
	autoscalerConcurrencyEnvironment       = "TS_ORCH_AUTOSCALER_MAX_CONCURRENT_PROVISIONS"
	autoscalerFlapTicksEnvironment         = "TS_ORCH_AUTOSCALER_FLAP_SUPPRESSION_TICKS"
	autoscalerAgentBinaryEnvironment       = "TS_ORCH_AUTOSCALER_AGENT_BINARY"
	autoscalerRunAsUidEnvironment          = "TS_ORCH_AUTOSCALER_RUN_AS_UID"
	autoscalerDrainLagEnvironment          = "TS_ORCH_AUTOSCALER_DRAIN_MAX_LAG_BYTES"

	autoscalerDefaultTickInterval = 10 * time.Second
	autoscalerCordonTimeout       = 2 * time.Second
	// autoscalerHeartbeatStaleTicks bounds how many tick intervals a node's
	// last heartbeat may age before the autoscaler stops counting the node in
	// its snapshots: a silent node is unschedulable evidence, not capacity.
	autoscalerHeartbeatStaleTicks = 3
	globalCheckTimeout            = 30 * time.Second
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
		configuration, err := autoscalerRoleConfiguration(lookup)
		if err != nil {
			return commandFailure(name, err)
		}
		if err := startAutoscalerRole(ctx, configuration); err != nil {
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
		"TS_ORCH_INFRA_NATS_NKEY_FILE", "TS_ORCH_INFRA_NATS_TLS_CA_FILE", "TS_ORCH_INFRA_NATS_TLS_CERT_FILE", "TS_ORCH_INFRA_NATS_TLS_KEY_FILE",
		"TS_ORCH_JOURNAL_NATS_NKEY_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CA_FILE", "TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE", "TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE", "TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE", "TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE", "TS_ORCH_JOURNAL_CONTROLLER_NKEYS",
		natsServerConfigEnvironment, natsServerReadinessEnvironment,
		natsServerConfigAliasEnvironment, natsConfigAliasEnvironment, natsReadinessAliasEnvironment,
		autoscalerTickIntervalEnvironment, autoscalerMinNodesEnvironment, autoscalerMaxNodesEnvironment,
		autoscalerScaleUpHeadroomEnvironment, autoscalerScaleDownHeadroomEnvironment,
		autoscalerScaleUpTicksEnvironment, autoscalerScaleDownTicksEnvironment,
		autoscalerConcurrencyEnvironment, autoscalerFlapTicksEnvironment,
		autoscalerAgentBinaryEnvironment, autoscalerRunAsUidEnvironment, autoscalerDrainLagEnvironment,
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
	NatsUrl          string
	TickInterval     time.Duration
	Policy           autoscaling.AutoscalerConfig
	AgentBinaryPath  string
	RunAsUid         uint32
	DrainMaxLagBytes int64
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
	natsUrl, err := autoscalerRequiredEnvironment(lookup, "TS_ORCH_NATS_URL")
	if err != nil {
		return autoscalerRoleSettings{}, err
	}
	if strings.HasPrefix(natsUrl, "-") || strings.ContainsAny(natsUrl, " \t\n") {
		return autoscalerRoleSettings{}, errors.New("autoscaler: TS_ORCH_NATS_URL must be whitespace-free and flag-safe")
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
		NatsUrl:          natsUrl,
		TickInterval:     tickInterval,
		Policy:           policy,
		AgentBinaryPath:  agentBinary,
		RunAsUid:         uint32(runAsUidParsed),
		DrainMaxLagBytes: drainLag,
	}, nil
}

// autoscalerNodeEntry is the autoscaler's tracked view of one node: its
// lifecycle state, its latest heartbeat metric sample, and when that
// heartbeat arrived.
type autoscalerNodeEntry struct {
	nodeId        string
	state         autoscaling.NodeState
	metrics       hostagent.NodeMetricsSample
	lastHeartbeat time.Time
}

// autoscalerRole is the control-plane runtime of the autoscaler command: it
// collects node heartbeats from the regional NATS, ticks the deterministic
// autoscaling engine every interval, and executes the emitted actions through
// the local process provisioner and the node subjects. It also implements the
// engine's drain safety seam by adapting the stateful replica evaluator with
// the peer candidates observed on every other node.
type autoscalerRole struct {
	settings      autoscalerRoleSettings
	connection    *nats.Conn
	provisioner   autoscaling.NodeProvisioner
	replicaDrains *stateful.ReplicaDrainSafetyEvaluator
	engine        *autoscaling.Autoscaler
	mutex         sync.Mutex
	nodes         map[string]*autoscalerNodeEntry
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
	return r.replicaDrains.EvaluateDrainSafety(candidate, r.peerCandidates(candidate.NodeId))
}

// peerCandidates returns the drain candidates of every other tracked node.
// Heartbeat metric samples name no replicas, so the peer candidates carry
// empty replica lists: a node observed to host replicas through a future
// replica-health source blocks its own drain fail-closed, never silently.
func (r *autoscalerRole) peerCandidates(excluded string) []stateful.NodeDrainCandidate {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	peers := make([]stateful.NodeDrainCandidate, 0, len(r.nodes))
	for nodeId, entry := range r.nodes {
		if nodeId == excluded || entry.state == autoscaling.NodeStateRetired {
			continue
		}
		peer, err := stateful.NewNodeDrainCandidate(nodeId, nil)
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
	var heartbeat hostagent.NodeHeartbeat
	if err := json.Unmarshal(message.Data, &heartbeat); err != nil {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	entry, present := r.nodes[heartbeat.NodeId.Value]
	if present && entry.state == autoscaling.NodeStateRetired {
		return
	}
	if !present {
		entry = &autoscalerNodeEntry{
			nodeId: heartbeat.NodeId.Value,
			state:  autoscaling.NodeStateReady,
		}
		r.nodes[heartbeat.NodeId.Value] = entry
	}
	entry.metrics = heartbeat.Metrics
	entry.lastHeartbeat = time.Now()
}

// setState records one lifecycle transition of a tracked node, creating the
// entry when the node has not heartbeated yet.
func (r *autoscalerRole) setState(nodeId string, state autoscaling.NodeState) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	entry, present := r.nodes[nodeId]
	if !present {
		r.nodes[nodeId] = &autoscalerNodeEntry{nodeId: nodeId, state: state, lastHeartbeat: time.Now()}
		return
	}
	entry.state = state
}

// snapshot derives the validated cluster observation of one tick from the
// node table: a node counts while its last heartbeat is fresh inside the
// staleness window. Heartbeats carry no replica health and no unsatisfied
// demand, so StatefulReplicas is empty and the demand set is empty; the
// scheduler integration that feeds both is the follow-up lane.
func (r *autoscalerRole) snapshot(now time.Time) autoscaling.AutoscalerSnapshot {
	staleness := autoscalerHeartbeatStaleTicks * r.settings.TickInterval
	r.mutex.Lock()
	defer r.mutex.Unlock()
	nodes := make([]autoscaling.NodeObservation, 0, len(r.nodes))
	for _, entry := range r.nodes {
		if now.Sub(entry.lastHeartbeat) > staleness {
			continue
		}
		capacity, capacityErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryTotalBytes, entry.metrics.CpuQuotaPercent, entry.metrics.TasksMax)
		usage, usageErr := autoscaling.NewNodeResources(
			entry.metrics.MemoryUsedBytes, entry.metrics.CpuUsedPercent, entry.metrics.TasksRunning)
		if capacityErr != nil || usageErr != nil {
			// Unreachable for a heartbeat-validated metric sample; skip.
			continue
		}
		observation, err := autoscaling.NewNodeObservation(
			entry.nodeId, entry.state, capacity, usage,
			entry.metrics.PendingAllocations, nil)
		if err != nil {
			continue
		}
		nodes = append(nodes, observation)
	}
	return autoscaling.AutoscalerSnapshot{Nodes: nodes}
}

// apply executes one autoscaler action. Every application is fail-closed: a
// failed provision, cordon, or retire surfaces to the run loop and stops the
// role instead of being retried blind.
func (r *autoscalerRole) apply(ctx context.Context, action autoscaling.AutoscalerAction) error {
	switch action.Kind() {
	case autoscaling.AutoscalerActionProvisionNode:
		return r.provisioner.Provision(ctx, action.ProvisionRequest())
	case autoscaling.AutoscalerActionCordonNode:
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
		if err := r.provisioner.Retire(ctx, action.NodeId()); err != nil {
			return err
		}
		r.setState(action.NodeId(), autoscaling.NodeStateRetired)
		return nil
	default:
		return fmt.Errorf("autoscaler: the action kind %s is not executed by this role", action.Kind())
	}
}

// cordonNode delivers one cordon command to the node agent over the regional
// NATS and requires the agent's acknowledgment before the state transition.
func (r *autoscalerRole) cordonNode(nodeId string) error {
	command, err := hostagent.NewCordonCommand("autoscaler-cordon-"+nodeId, true)
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
	if !acknowledgment.Cordoned || acknowledgment.NodeId != nodeId {
		return fmt.Errorf("autoscaler: node %s did not acknowledge its cordon", nodeId)
	}
	return nil
}

// tick runs one autoscaler tick over the current snapshot and applies every
// emitted action in the tick's canonical order.
func (r *autoscalerRole) tick(ctx context.Context, now time.Time) error {
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

// startAutoscalerRole composes and runs the autoscaler against the regional
// NATS until the context is cancelled: it subscribes to every node heartbeat,
// builds the deterministic engine with the stateful drain gate and the local
// process provisioner, and executes one tick per interval. A tick or action
// failure stops the role fail-closed.
func startAutoscalerRole(ctx context.Context, settings autoscalerRoleSettings) error {
	if ctx == nil {
		return errors.New("autoscaler: the role context must not be nil")
	}
	connection, err := nats.Connect(settings.NatsUrl,
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1))
	if err != nil {
		return err
	}
	defer connection.Close()
	role := &autoscalerRole{
		settings:   settings,
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
		settings.AgentBinaryPath, settings.NatsUrl, nil, settings.RunAsUid)
	if err != nil {
		return err
	}
	role.provisioner, err = autoscaling.NewLocalProcessNodeProvisioner(provisionerConfig, spawner)
	if err != nil {
		return err
	}
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
