package control

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// OrchestratorCommand is the closed command vocabulary accepted by the
// orchestrator entry point.
type OrchestratorCommand int

const (
	OrchestratorCommandRun OrchestratorCommand = iota
	OrchestratorCommandCheck
	OrchestratorCommandCatalog
	OrchestratorCommandProvisionJournal
	OrchestratorCommandJournalWriter
)

func (c OrchestratorCommand) String() string {
	switch c {
	case OrchestratorCommandRun:
		return "run"
	case OrchestratorCommandCheck:
		return "check"
	case OrchestratorCommandCatalog:
		return "catalog"
	case OrchestratorCommandProvisionJournal:
		return "provision-journal"
	case OrchestratorCommandJournalWriter:
		return "journal-writer"
	default:
		return strconv.Itoa(int(c))
	}
}

// OrchestratorOptions contains the resolved settings for one orchestrator
// role. File fields are absolute paths validated by the owning resolver; no
// secret material is retained in this value.
type OrchestratorOptions struct {
	Command                    OrchestratorCommand
	Cell                       string
	NatsURL                    string
	Replicas                   int
	Instance                   string
	NatsNKeyFile               *string
	NatsTls                    *NatsTlsFiles
	GlobalNats                 *GlobalNatsConfiguration
	GlobalDirectoryNats        *GlobalDirectoryNatsConfiguration
	GlobalDirectoryServiceNats *GlobalDirectoryServiceNatsConfiguration
	InfrastructureNatsNKeyFile *string
	InfrastructureNatsTls      *NatsTlsFiles
	AuthoritativeJournal       *NatsAuthoritativeJournalConfiguration
}

// EnvironmentLookup is deliberately injected so parsing never reads process
// globals behind the caller's back. A false result means the variable is not
// present; an empty present value remains an explicit (and usually invalid)
// setting, matching the C# parser's null semantics.
type EnvironmentLookup func(string) (string, bool)

// NewOrchestratorOptions parses args and resolves the role-specific
// environment settings. An omitted command means run, as in the C# CLI.
func NewOrchestratorOptions(args []string, environment EnvironmentLookup) (*OrchestratorOptions, error) {
	if environment == nil {
		return nil, errors.New("an environment lookup function is required")
	}

	command, err := parseOrchestratorCommand(args)
	if err != nil {
		return nil, err
	}
	if len(args) > 1 {
		return nil, fmt.Errorf("The %s command does not accept arguments.", args[0])
	}

	lookup := func(name string) string {
		value, present := environment(name)
		if !present {
			return ""
		}
		return value
	}
	defaultValue := func(name, fallback string) string {
		value, present := environment(name)
		if !present {
			return fallback
		}
		return value
	}

	cell := defaultValue("TS_ORCH_CELL", "local")
	urlValue := defaultValue("TS_ORCH_NATS_URL", "nats://127.0.0.1:4222")
	replicasText := defaultValue("TS_ORCH_REPLICAS", "1")
	instance := defaultValue("TS_ORCH_INSTANCE", "local")

	controllerNKey := lookup("TS_ORCH_NATS_NKEY_FILE")
	controllerCA := lookup("TS_ORCH_NATS_TLS_CA_FILE")
	controllerCert := lookup("TS_ORCH_NATS_TLS_CERT_FILE")
	controllerKey := lookup("TS_ORCH_NATS_TLS_KEY_FILE")

	globalURL := lookup("TS_ORCH_GLOBAL_NATS_URL")
	globalNKey := lookup("TS_ORCH_GLOBAL_NATS_NKEY_FILE")
	globalCredentials := lookup("TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE")
	globalCA := lookup("TS_ORCH_GLOBAL_NATS_TLS_CA_FILE")
	globalCert := lookup("TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE")
	globalKey := lookup("TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE")

	directoryURL := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL")
	directoryNKey := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE")
	directoryCredentials := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE")
	directoryCA := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE")
	directoryCert := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE")
	directoryKey := lookup("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE")
	directoryEndpoints := lookup("TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS")

	serviceURL := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL")
	serviceNKey := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE")
	serviceCredentials := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE")
	serviceCA := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE")
	serviceCert := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE")
	serviceKey := lookup("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE")

	infrastructureNKey := lookup("TS_ORCH_INFRA_NATS_NKEY_FILE")
	infrastructureCA := lookup("TS_ORCH_INFRA_NATS_TLS_CA_FILE")
	infrastructureCert := lookup("TS_ORCH_INFRA_NATS_TLS_CERT_FILE")
	infrastructureKey := lookup("TS_ORCH_INFRA_NATS_TLS_KEY_FILE")

	journalNKey := lookup("TS_ORCH_JOURNAL_NATS_NKEY_FILE")
	journalCA := lookup("TS_ORCH_JOURNAL_NATS_TLS_CA_FILE")
	journalCert := lookup("TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE")
	journalKey := lookup("TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE")
	journalAuthority := lookup("TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE")
	journalReply := lookup("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE")
	journalControllers := lookup("TS_ORCH_JOURNAL_CONTROLLER_NKEYS")

	if err := rejectUnownedCredentials(command, orchestratorCredentialFamilies{
		controller: []string{
			controllerNKey, controllerCA, controllerCert, controllerKey,
			globalURL, globalNKey, globalCredentials, globalCA, globalCert, globalKey,
			directoryURL, directoryNKey, directoryCredentials, directoryCA, directoryCert, directoryKey,
			serviceURL, serviceNKey, serviceCredentials, serviceCA, serviceCert, serviceKey,
		},
		infrastructure: []string{infrastructureNKey, infrastructureCA, infrastructureCert, infrastructureKey},
		journal:        []string{journalNKey, journalCA, journalCert, journalKey, journalAuthority, journalReply, journalControllers},
	}); err != nil {
		return nil, err
	}

	if !isOrchestratorSubjectToken(cell) {
		return nil, errors.New("TS_ORCH_CELL must contain only lowercase letters, digits, or hyphens.")
	}
	parsedURL, err := url.Parse(urlValue)
	if err != nil || !parsedURL.IsAbs() || (parsedURL.Scheme != "nats" && parsedURL.Scheme != "tls") {
		return nil, errors.New("TS_ORCH_NATS_URL must be an absolute nats:// or tls:// URL.")
	}
	replicas, err := strconv.Atoi(replicasText)
	if err != nil || replicas < 1 || replicas > 5 || replicas%2 == 0 {
		return nil, errors.New("TS_ORCH_REPLICAS must be 1, 3, or 5.")
	}
	if !isOrchestratorSubjectToken(instance) {
		return nil, errors.New("TS_ORCH_INSTANCE must contain only lowercase letters, digits, or hyphens.")
	}

	var controllerNKeyPath *string
	var controllerTLS *NatsTlsFiles
	if command == OrchestratorCommandRun || command == OrchestratorCommandCheck {
		path, resolveErr := NatsCredentialFile.Resolve(controllerNKey, "TS_ORCH_NATS_NKEY_FILE")
		if resolveErr != nil {
			return nil, resolveErr
		}
		if path != "" {
			controllerNKeyPath = &path
		}
		controllerTLS, err = NatsTlsFilesResolve(controllerCA, controllerCert, controllerKey, "TS_ORCH_NATS_TLS")
		if err != nil {
			return nil, err
		}
	}
	if command == OrchestratorCommandRun &&
		(parsedURL.Scheme != "tls" || controllerNKeyPath == nil || controllerTLS == nil) {
		return nil, errors.New("The run command requires a tls:// regional control NATS URL, a private NKey seed, and complete mTLS credentials.")
	}

	var infrastructureNKeyPath *string
	var infrastructureTLS *NatsTlsFiles
	if command == OrchestratorCommandProvisionJournal {
		path, resolveErr := NatsCredentialFile.Resolve(infrastructureNKey, "TS_ORCH_INFRA_NATS_NKEY_FILE")
		if resolveErr != nil {
			return nil, resolveErr
		}
		if path != "" {
			infrastructureNKeyPath = &path
		}
		infrastructureTLS, err = NatsTlsFilesResolve(infrastructureCA, infrastructureCert, infrastructureKey, "TS_ORCH_INFRA_NATS_TLS")
		if err != nil {
			return nil, err
		}
	}
	if command == OrchestratorCommandProvisionJournal &&
		(parsedURL.Scheme != "tls" || infrastructureNKeyPath == nil || infrastructureTLS == nil) {
		return nil, errors.New("The provision-journal command requires a tls:// regional control NATS URL and complete TS_ORCH_INFRA_NATS NKey and mTLS credentials.")
	}
	if infrastructureNKeyPath != nil && controllerNKeyPath != nil {
		same, identityErr := NatsCredentialFile.SameIdentity(*infrastructureNKeyPath, *controllerNKeyPath)
		if identityErr != nil || same {
			return nil, errors.New("Infrastructure and controller NATS identities must be distinct.")
		}
	}
	if infrastructureTLS != nil && controllerTLS != nil && infrastructureTLS.SameIdentity(controllerTLS) {
		return nil, errors.New("Infrastructure and controller NATS mTLS identities must be distinct.")
	}

	var global *GlobalNatsConfiguration
	var directory *GlobalDirectoryNatsConfiguration
	var service *GlobalDirectoryServiceNatsConfiguration
	if command == OrchestratorCommandRun || command == OrchestratorCommandCheck {
		global, err = GlobalNatsConfigurationResolveWithCredentials(globalURL, globalNKey, globalCredentials, globalCA, globalCert, globalKey, replicas, cell)
		if err != nil {
			return nil, err
		}
		directory, err = GlobalDirectoryNatsConfigurationResolveWithCredentials(directoryURL, directoryNKey, directoryCredentials, directoryCA, directoryCert, directoryKey, replicas, cell, directoryEndpoints)
		if err != nil {
			return nil, err
		}
		service, err = GlobalDirectoryServiceNatsConfigurationResolveWithCredentials(serviceURL, serviceNKey, serviceCredentials, serviceCA, serviceCert, serviceKey, replicas, cell)
		if err != nil {
			return nil, err
		}
	}
	if service != nil && directory == nil {
		return nil, errors.New("The global directory service requires complete global directory publisher/watch credentials.")
	}
	if (global != nil || directory != nil) && (controllerNKeyPath == nil || controllerTLS == nil) {
		return nil, errors.New("Global authority and directory roles require complete regional control credentials.")
	}
	if err := validateDistinctNatsIdentities(controllerNKeyPath, controllerTLS, global, directory, service); err != nil {
		return nil, err
	}

	var journal *NatsAuthoritativeJournalConfiguration
	if command == OrchestratorCommandJournalWriter {
		journal, err = NatsAuthoritativeJournalConfigurationResolve(journalNKey, journalCA, journalCert, journalKey, journalAuthority, journalReply, journalControllers)
		if err != nil {
			return nil, err
		}
	}
	if command == OrchestratorCommandJournalWriter &&
		(parsedURL.Scheme != "tls" || replicas < 3 || journal == nil) {
		return nil, errors.New("The journal-writer command requires R3/R5 tls:// control NATS and complete TS_ORCH_JOURNAL writer credentials.")
	}
	return &OrchestratorOptions{
		Command:                    command,
		Cell:                       cell,
		NatsURL:                    parsedURL.String(),
		Replicas:                   replicas,
		Instance:                   instance,
		NatsNKeyFile:               controllerNKeyPath,
		NatsTls:                    controllerTLS,
		GlobalNats:                 global,
		GlobalDirectoryNats:        directory,
		GlobalDirectoryServiceNats: service,
		InfrastructureNatsNKeyFile: infrastructureNKeyPath,
		InfrastructureNatsTls:      infrastructureTLS,
		AuthoritativeJournal:       journal,
	}, nil
}

// ParseOrchestratorOptions is the function-style parser alias used by CLI
// callers that do not need to retain a parser value.
func ParseOrchestratorOptions(args []string, environment EnvironmentLookup) (*OrchestratorOptions, error) {
	return NewOrchestratorOptions(args, environment)
}

// OrchestratorOptionsParse is retained as a migration-friendly symbol name.
func OrchestratorOptionsParse(args []string, environment EnvironmentLookup) (*OrchestratorOptions, error) {
	return NewOrchestratorOptions(args, environment)
}

func parseOrchestratorCommand(args []string) (OrchestratorCommand, error) {
	if len(args) == 0 {
		return OrchestratorCommandRun, nil
	}
	switch args[0] {
	case "run":
		return OrchestratorCommandRun, nil
	case "check":
		return OrchestratorCommandCheck, nil
	case "catalog":
		return OrchestratorCommandCatalog, nil
	case "provision-journal":
		return OrchestratorCommandProvisionJournal, nil
	case "journal-writer":
		return OrchestratorCommandJournalWriter, nil
	default:
		return 0, fmt.Errorf("Unknown command '%s'. Use 'run', 'check', 'catalog', 'provision-journal', or 'journal-writer'.", args[0])
	}
}

func isOrchestratorSubjectToken(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

type orchestratorCredentialFamilies struct {
	controller     []string
	infrastructure []string
	journal        []string
}

func rejectUnownedCredentials(command OrchestratorCommand, families orchestratorCredentialFamilies) error {
	if anyOptionSupplied(families.controller) && command != OrchestratorCommandRun && command != OrchestratorCommandCheck {
		return fmt.Errorf("The %s role must not receive controller NATS credentials.", command.String())
	}
	if anyOptionSupplied(families.infrastructure) && command != OrchestratorCommandProvisionJournal {
		return fmt.Errorf("The %s role must not receive infrastructure NATS credentials.", command.String())
	}
	if anyOptionSupplied(families.journal) && command != OrchestratorCommandJournalWriter {
		return fmt.Errorf("The %s role must not receive journal-writer credentials.", command.String())
	}
	return nil
}

func anyOptionSupplied(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func validateDistinctNatsIdentities(regionalNKey *string, regionalTLS *NatsTlsFiles, authority *GlobalNatsConfiguration, directory *GlobalDirectoryNatsConfiguration, service *GlobalDirectoryServiceNatsConfiguration) error {
	type identity struct {
		name   string
		public string
		tls    *NatsTlsFiles
	}
	identities := make([]identity, 0, 4)
	if regionalNKey != nil && regionalTLS != nil {
		public, err := NatsCredentialFile.PublicKey(*regionalNKey)
		if err != nil {
			return errors.New("NATS identities could not be validated as distinct.")
		}
		identities = append(identities, identity{"regional control", public, regionalTLS})
	}
	if authority != nil {
		identities = append(identities, identity{"global authority", authority.Authentication.PublicKey, authority.Tls})
	}
	if directory != nil {
		identities = append(identities, identity{"global directory", directory.Authentication.PublicKey, directory.Tls})
	}
	if service != nil {
		identities = append(identities, identity{"global directory service", service.Authentication.PublicKey, service.Tls})
	}
	for first := 0; first < len(identities); first++ {
		for second := first + 1; second < len(identities); second++ {
			left, right := identities[first], identities[second]
			if left.public == right.public || left.tls.SameIdentity(right.tls) {
				return fmt.Errorf("%s and %s NATS identities must be distinct.", left.name, right.name)
			}
		}
	}
	return nil
}
