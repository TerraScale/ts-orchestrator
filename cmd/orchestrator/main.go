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
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control"
)

const (
	natsServerConfigEnvironment      = "TS_ORCH_NATS_SERVER_CONFIG_FILE"
	natsServerReadinessEnvironment   = "TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"
	natsServerConfigAliasEnvironment = "TS_ORCH_NATS_SERVER_CONFIG"
	natsConfigAliasEnvironment       = "TS_ORCH_NATS_CONFIG_FILE"
	natsReadinessAliasEnvironment    = "TS_ORCH_NATS_READINESS_TIMEOUT"
	globalCheckTimeout               = 30 * time.Second
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
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer":
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
	case "run", "check", "nats-server", "catalog", "provision-journal", "journal-writer":
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
	}
	sort.Strings(environment)
	document := catalogDocument{SchemaVersion: 1, Commands: commands, Environment: environment}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}
