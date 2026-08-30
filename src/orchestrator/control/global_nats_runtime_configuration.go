// Port of src/TerraScale.Orchestrator/Messaging/GlobalNatsRuntimeConfiguration.cs.
package control

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// GlobalDirectoryNatsConfiguration mirrors the C# sealed class: connection and
// access settings for a regional directory publisher with one durable
// capability, the GLOBAL_CELLS projection.
type GlobalDirectoryNatsConfiguration struct {
	Url            string
	Authentication *NatsAuthenticationFiles
	Tls            *NatsTlsFiles
	Replicas       int
	Cell           string

	// Endpoints are the cell's advertised control-plane endpoints. Publishing
	// an advertisement requires at least one; a watch-only composition may
	// leave them empty.
	Endpoints []string
}

// NewGlobalDirectoryNatsConfigurationFromNKey mirrors the nkey+tls C#
// constructor with R3 fixed.
func NewGlobalDirectoryNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *NatsTlsFiles,
	cell string,
) (*GlobalDirectoryNatsConfiguration, error) {
	return NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey(
		rawUrl, nkeyFile, tls, 3, cell)
}

// NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey mirrors the
// nkey+tls+replicas C# constructor.
func NewGlobalDirectoryNatsConfigurationWithReplicasFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryNatsConfiguration, error) {
	authentication, err := NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalDirectoryNatsConfiguration(rawUrl, authentication, tls, replicas, cell, nil)
}

// NewGlobalDirectoryNatsConfiguration mirrors the main C# constructor
// (replicas fixed at 3).
func NewGlobalDirectoryNatsConfiguration(
	rawUrl string,
	authentication *NatsAuthenticationFiles,
	tls *NatsTlsFiles,
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

	if !messagingCellTokenIsValid(cell) {
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

// AccessPlan mirrors the C# AccessPlan property.
func (c *GlobalDirectoryNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityCellDirectoryPublisher)
}

// GlobalDirectoryNatsConfigurationResolve mirrors the C# Resolve overload
// without a credentials file.
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

// GlobalDirectoryNatsConfigurationResolveWithCredentials mirrors the full C#
// Resolve.
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

	if !messagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory cell is invalid. (Parameter 'cell')")
	}

	authentication, err := NatsAuthenticationFilesResolve(
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

	tls, err := NatsTlsFilesResolve(caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS credentials are missing.")
	}

	return NewGlobalDirectoryNatsConfiguration(
		parsed.String(), authentication, tls, replicas, cell, advertisedEndpoints)
}

// GlobalDirectoryNatsConfigurationParseEndpoints mirrors the C# ParseEndpoints:
// a comma- or semicolon-separated list of one to eight absolute control
// endpoints; nil means absent (a legal watch-only composition).
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

// GlobalDirectoryServiceNatsConfiguration mirrors the C# sealed class: the
// GRU-only identity for the read-only global cell query service.
type GlobalDirectoryServiceNatsConfiguration struct {
	Url            string
	Authentication *NatsAuthenticationFiles
	Tls            *NatsTlsFiles
	Replicas       int
	Cell           string
}

// NewGlobalDirectoryServiceNatsConfigurationFromNKey mirrors the nkey C#
// constructor.
func NewGlobalDirectoryServiceNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	authentication, err := NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalDirectoryServiceNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// NewGlobalDirectoryServiceNatsConfiguration mirrors the main C# constructor.
func NewGlobalDirectoryServiceNatsConfiguration(
	rawUrl string,
	authentication *NatsAuthenticationFiles,
	tls *NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalDirectoryServiceNatsConfiguration, error) {
	if !messagingCellTokenIsValid(cell) {
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

// AccessPlan mirrors the C# AccessPlan property.
func (c *GlobalDirectoryServiceNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityCellDirectoryService)
}

// GlobalDirectoryServiceNatsConfigurationResolve mirrors the C# Resolve
// overload without a credentials file.
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

// GlobalDirectoryServiceNatsConfigurationResolveWithCredentials mirrors the
// full C# Resolve.
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

	if !messagingCellTokenIsValid(cell) {
		return nil, errors.New("The global directory service cell is invalid. (Parameter 'cell')")
	}

	if cell != "gru" {
		return nil, errors.New("The global directory service identity is GRU-only. (Parameter 'cell')")
	}

	authentication, err := NatsAuthenticationFilesResolve(
		nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS")
	if err != nil {
		return nil, err
	}

	if rawUrl == "" || authentication == nil || caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, errors.New(
			"Global directory service NATS requires URL, authentication, CA, certificate, and key together.")
	}

	tls, err := NatsTlsFilesResolve(
		caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS credentials are missing.")
	}

	return NewGlobalDirectoryServiceNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// GlobalAuthorityNatsConfiguration mirrors the C# internal sealed class:
// GRU-only connection and access settings for the global authority.
type GlobalAuthorityNatsConfiguration struct {
	Url            string
	Authentication *NatsAuthenticationFiles
	Tls            *NatsTlsFiles
	Replicas       int
	Cell           string
}

// NewGlobalAuthorityNatsConfigurationFromNKey mirrors the nkey C#
// constructor.
func NewGlobalAuthorityNatsConfigurationFromNKey(
	rawUrl string,
	nkeyFile string,
	tls *NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	authentication, err := NatsAuthenticationFilesFromNKeyFile(nkeyFile)
	if err != nil {
		return nil, err
	}

	return NewGlobalAuthorityNatsConfiguration(rawUrl, authentication, tls, replicas, cell)
}

// NewGlobalAuthorityNatsConfiguration mirrors the main C# constructor.
func NewGlobalAuthorityNatsConfiguration(
	rawUrl string,
	authentication *NatsAuthenticationFiles,
	tls *NatsTlsFiles,
	replicas int,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	if err := GlobalNatsConfigurationValidateLegacyAuthorityAlias(cell); err != nil {
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

// AccessPlan mirrors the C# AccessPlan property.
func (c *GlobalAuthorityNatsConfiguration) AccessPlan() (*GlobalNatsAccessPlan, error) {
	return GlobalNatsAccessContract.Create(c.Cell, GlobalNatsCapabilityGlobalAuthority)
}

// GlobalAuthorityNatsConfigurationFrom mirrors the C# From factory.
func GlobalAuthorityNatsConfigurationFrom(
	configuration *GlobalNatsConfiguration,
	cell string,
) (*GlobalAuthorityNatsConfiguration, error) {
	if configuration == nil {
		return nil, errors.New("(Parameter 'configuration')")
	}

	return NewGlobalAuthorityNatsConfiguration(
		configuration.Url, configuration.Authentication, configuration.Tls, 3, cell)
}
