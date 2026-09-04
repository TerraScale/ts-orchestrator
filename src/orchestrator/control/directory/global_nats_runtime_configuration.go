package directory

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

// globalNatsConfigurationIsLegacyAuthorityAliasAllowed: the legacy
// TS_ORCH_GLOBAL_NATS_* settings identify GRU global authority.
func globalNatsConfigurationIsLegacyAuthorityAliasAllowed(cell string) bool {
	return cell == "gru" && messaging.GlobalNatsTopologyIsCellToken(cell)
}

func globalNatsConfigurationValidateLegacyAuthorityAlias(cell string) error {
	if !globalNatsConfigurationIsLegacyAuthorityAliasAllowed(cell) {
		return errors.New(
			"TS_ORCH_GLOBAL_NATS_* is a GRU-only global-authority alias. (Parameter 'cell')")
	}

	return nil
}

// GlobalDirectoryNatsConfiguration holds connection and access settings for a
// regional directory publisher with one durable capability, the GLOBAL_CELLS
// projection.
type GlobalDirectoryNatsConfiguration struct {
	Url            string
	Authentication *messaging.NatsAuthenticationFiles
	Tls            *messaging.NatsTlsFiles
	Replicas       int
	Cell           string

	// Endpoints are the cell's advertised control-plane endpoints. Publishing
	// an advertisement requires at least one; a watch-only composition may
	// leave them empty.
	Endpoints []string
}

// NewGlobalDirectoryNatsConfigurationFromNKey builds an R3 configuration from
// an nkey file and TLS files.
func NewGlobalDirectoryNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *messaging.NatsTlsFiles,
	cell string,
) (*GlobalDirectoryNatsConfiguration, error) {
	return NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey(
		rawUrl, nkeyFile, tls, 3, cell)
}

// NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey builds the
// configuration from an nkey file, TLS files, and a replica count.
func NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryNatsConfiguration, error) {
	authentication, err := messaging.NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalDirectoryNatsConfiguration(rawUrl, authentication, tls, replicas, cell, nil)
}

// NewGlobalDirectoryNatsConfiguration validates the settings and normalizes
// replicas to 3.
func NewGlobalDirectoryNatsConfiguration(
	rawUrl string,
	authentication *messaging.NatsAuthenticationFiles,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
	endpoints []string,
) (*GlobalDirectoryNatsConfiguration, error) {
	if replicas != 3 {
		replicas = 3
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" {
		return nil, errors.New("The global directory NATS URL must be an absolute tls:// URL. (Parameter 'url')")
	}

	if authentication == nil {
		return nil, errors.New("(Parameter 'authentication')")
	}

	if tls == nil {
		return nil, errors.New("(Parameter 'tls')")
	}

	if !shared.MessagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory cell is invalid. (Parameter 'cell')")
	}

	if len(endpoints) > 8 {
		return nil, errors.New(
			"The advertised cell endpoints must be valid control endpoints (at most eight). (Parameter 'endpoints')")
	}

	for _, endpoint := range endpoints {
		if !GlobalCellAdvertisementIsControlEndpoint(endpoint) {
			return nil, errors.New(
				"The advertised cell endpoints must be valid control endpoints (at most eight). (Parameter 'endpoints')")
		}
	}

	ordered := append([]string(nil), endpoints...)
	sort.Strings(ordered)

	return &GlobalDirectoryNatsConfiguration{
		Url:            parsed.String(),
		Authentication: authentication,
		Tls:            tls,
		Replicas:       replicas,
		Cell:           cell,
		Endpoints:      ordered,
	}, nil
}

// AccessPlan returns the publisher access plan for this configuration.
func (c *GlobalDirectoryNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityCellDirectoryPublisher)
}

// GlobalDirectoryNatsConfigurationResolve resolves the
// TS_ORCH_GLOBAL_DIRECTORY_NATS settings without a credentials file.
func GlobalDirectoryNatsConfigurationResolve(
	rawUrl string,
	nkeyFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalDirectoryNatsConfiguration, error) {
	return GlobalDirectoryNatsConfigurationResolveWithCredentials(
		rawUrl, nkeyFile, "", caFile, certificateFile, keyFile, replicas, cell, "")
}

// GlobalDirectoryNatsConfigurationResolveWithCredentials resolves the full
// TS_ORCH_GLOBAL_DIRECTORY_NATS settings; a nil result means no setting was
// supplied.
func GlobalDirectoryNatsConfigurationResolveWithCredentials(
	rawUrl string,
	nkeyFile string,
	credentialsFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
	endpoints string,
) (*GlobalDirectoryNatsConfiguration, error) {
	values := []string{rawUrl, nkeyFile, credentialsFile, caFile, certificateFile, keyFile}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	// Validate the endpoints value even when no other setting is supplied, so a
	// stray TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS cannot survive unnoticed.
	advertisedEndpoints, err := GlobalDirectoryNatsConfigurationParseEndpoints(endpoints)
	if err != nil {
		return nil, err
	}

	if supplied == 0 {
		return nil, nil
	}

	if !shared.MessagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory cell is invalid. (Parameter 'cell')")
	}

	authentication, err := messaging.NatsAuthenticationFilesResolve(
		nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_DIRECTORY_NATS")
	if err != nil {
		return nil, err
	}

	if rawUrl == "" || authentication == nil || caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, errors.New(
			"Global directory NATS requires URL, authentication, CA, certificate, and key together.")
	}

	if replicas != 3 {
		return nil, errors.New("Global directory NATS requires exactly three replicas.")
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" {
		return nil, errors.New("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL must be an absolute tls:// URL.")
	}

	tls, err := messaging.NatsTlsFilesResolve(caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS credentials are missing.")
	}

	return NewGlobalDirectoryNatsConfiguration(
		parsed.String(), authentication, tls, replicas, cell, advertisedEndpoints)
}

// GlobalDirectoryNatsConfigurationParseEndpoints parses a comma- or
// semicolon-separated list of one to eight absolute control endpoints; nil
// means absent (a legal watch-only composition).
func GlobalDirectoryNatsConfigurationParseEndpoints(endpoints string) ([]string, error) {
	if strings.TrimSpace(endpoints) == "" {
		return nil, nil
	}

	parsed := []string{}
	for _, part := range strings.FieldsFunc(endpoints, func(r rune) bool { return r == ',' || r == ';' }) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parsed = append(parsed, trimmed)
		}
	}

	if len(parsed) == 0 || len(parsed) > 8 {
		return nil, fmt.Errorf(
			"TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS must be a comma- or semicolon-separated list of one to eight " +
				"absolute control endpoints (scheme, lowercase host, explicit port, no path, query, fragment, or " +
				"user information). (Parameter 'endpoints')")
	}

	for _, endpoint := range parsed {
		if !GlobalCellAdvertisementIsControlEndpoint(endpoint) {
			return nil, fmt.Errorf(
				"TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS must be a comma- or semicolon-separated list of one to eight " +
					"absolute control endpoints (scheme, lowercase host, explicit port, no path, query, fragment, or " +
					"user information). (Parameter 'endpoints')")
		}
	}

	sort.Strings(parsed)
	return parsed, nil
}

// GlobalDirectoryServiceNatsConfiguration holds the GRU-only identity for the
// read-only global cell query service.
type GlobalDirectoryServiceNatsConfiguration struct {
	Url            string
	Authentication *messaging.NatsAuthenticationFiles
	Tls            *messaging.NatsTlsFiles
	Replicas       int
	Cell           string
}

// NewGlobalDirectoryServiceNatsConfigurationFromNKey builds the configuration
// from an nkey file.
func NewGlobalDirectoryServiceNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	authentication, err := messaging.NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalDirectoryServiceNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// NewGlobalDirectoryServiceNatsConfiguration validates the settings and
// builds the configuration.
func NewGlobalDirectoryServiceNatsConfiguration(
	rawUrl string,
	authentication *messaging.NatsAuthenticationFiles,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	if !shared.MessagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory service cell is invalid. (Parameter 'cell')")
	}

	if cell != "gru" {
		return nil, errors.New("The global directory service identity is GRU-only. (Parameter 'cell')")
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" {
		return nil, errors.New(
			"The global directory service NATS URL must be an absolute tls:// URL. (Parameter 'url')")
	}

	if authentication == nil {
		return nil, errors.New("(Parameter 'authentication')")
	}

	if tls == nil {
		return nil, errors.New("(Parameter 'tls')")
	}

	if replicas != 3 {
		return nil, errors.New("The global directory service requires exactly three replicas. (Parameter 'replicas')")
	}

	return &GlobalDirectoryServiceNatsConfiguration{
		Url:            parsed.String(),
		Authentication: authentication,
		Tls:            tls,
		Replicas:       replicas,
		Cell:           cell,
	}, nil
}

// AccessPlan returns the service access plan for this configuration.
func (c *GlobalDirectoryServiceNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityCellDirectoryService)
}

// GlobalDirectoryServiceNatsConfigurationResolve resolves the
// TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS settings without a credentials file.
func GlobalDirectoryServiceNatsConfigurationResolve(
	rawUrl string,
	nkeyFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	return GlobalDirectoryServiceNatsConfigurationResolveWithCredentials(
		rawUrl, nkeyFile, "", caFile, certificateFile, keyFile, replicas, cell)
}

// GlobalDirectoryServiceNatsConfigurationResolveWithCredentials resolves the
// full TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS settings; a nil result means no
// setting was supplied.
func GlobalDirectoryServiceNatsConfigurationResolveWithCredentials(
	rawUrl string,
	nkeyFile string,
	credentialsFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	values := []string{rawUrl, nkeyFile, credentialsFile, caFile, certificateFile, keyFile}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	if supplied == 0 {
		return nil, nil
	}

	if !shared.MessagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory service cell is invalid. (Parameter 'cell')")
	}

	if cell != "gru" {
		return nil, errors.New("The global directory service identity is GRU-only. (Parameter 'cell')")
	}

	authentication, err := messaging.NatsAuthenticationFilesResolve(
		nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS")
	if err != nil {
		return nil, err
	}

	if rawUrl == "" || authentication == nil || caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, errors.New(
			"Global directory service NATS requires URL, authentication, CA, certificate, and key together.")
	}

	tls, err := messaging.NatsTlsFilesResolve(
		caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS credentials are missing.")
	}

	return NewGlobalDirectoryServiceNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// GlobalAuthorityNatsConfiguration holds GRU-only connection and access
// settings for the global authority.
type GlobalAuthorityNatsConfiguration struct {
	Url            string
	Authentication *messaging.NatsAuthenticationFiles
	Tls            *messaging.NatsTlsFiles
	Replicas       int
	Cell           string
}

// NewGlobalAuthorityNatsConfigurationFromNKey builds the configuration from
// an nkey file.
func NewGlobalAuthorityNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	authentication, err := messaging.NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalAuthorityNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// NewGlobalAuthorityNatsConfiguration validates the settings and builds the
// configuration.
func NewGlobalAuthorityNatsConfiguration(
	rawUrl string,
	authentication *messaging.NatsAuthenticationFiles,
	tls *messaging.NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	if err := globalNatsConfigurationValidateLegacyAuthorityAlias(cell); err != nil {
		return nil, err
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" {
		return nil, errors.New("The global authority NATS URL must be an absolute tls:// URL. (Parameter 'url')")
	}

	if authentication == nil {
		return nil, errors.New("(Parameter 'authentication')")
	}

	if tls == nil {
		return nil, errors.New("(Parameter 'tls')")
	}

	if replicas != 3 {
		return nil, errors.New("The global authority requires exactly three replicas. (Parameter 'replicas')")
	}

	return &GlobalAuthorityNatsConfiguration{
		Url:            parsed.String(),
		Authentication: authentication,
		Tls:            tls,
		Replicas:       replicas,
		Cell:           cell,
	}, nil
}

// AccessPlan returns the global-authority access plan for this configuration.
func (c *GlobalAuthorityNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityGlobalAuthority)
}

// GlobalAuthorityNatsConfigurationResolveWithCredentials resolves the
// TS_ORCH_GLOBAL_NATS_* settings; nil means no setting was supplied.
func GlobalAuthorityNatsConfigurationResolveWithCredentials(
	rawUrl string,
	nkeyFile string,
	credentialsFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	values := []string{rawUrl, nkeyFile, credentialsFile, caFile, certificateFile, keyFile}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	if supplied == 0 {
		return nil, nil
	}

	authentication, err := messaging.NatsAuthenticationFilesResolve(nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_NATS")
	if err != nil {
		return nil, err
	}

	if rawUrl == "" || authentication == nil || caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, errors.New(
			"Global control NATS requires URL, authentication, CA, certificate, and key together.")
	}

	tls, err := messaging.NatsTlsFilesResolve(caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_NATS_TLS credentials are missing.")
	}

	return NewGlobalAuthorityNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}
