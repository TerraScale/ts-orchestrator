package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	goruntime "runtime"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// infisicalMarshalJSON encodes a wire body without HTML escaping (the migration
// contract maps System.Text.Json to encoding/json with SetEscapeHTML(false)).
func infisicalMarshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	// json.Encoder appends a trailing newline; drop it to match Marshal output.
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

const infisicalMaximumResponseBytes = 8 * 1024 * 1024

// InfisicalConfiguration is the resolved, validated Universal Auth identity.
type InfisicalConfiguration struct {
	Server           string
	VaultProject     string
	Environment      string
	SecretPath       string
	ClientIdFile     string
	ClientSecretFile string
	OrganizationSlug *string
}

const infisicalForbiddenCredentialMode = 0o077

// InfisicalConfigurationRequiresRuntimeSecretEnvironment reports whether a
// command must fetch and materialize the generic TS_ORCH_* secret environment.
// Infrastructure-only journal provisioning must not fetch or materialize the
// generic runtime secret environment, which can contain controller and
// journal-writer private credential files.
func InfisicalConfigurationRequiresRuntimeSecretEnvironment(command string) bool {
	switch command {
	case "", "run", "check", "runner":
		return true
	default:
		return false
	}
}

// InfisicalConfigurationResolveEnv resolves the configuration from an
// environment lookup function; it returns nil when nothing is supplied.
func InfisicalConfigurationResolveEnv(environment func(string) (string, bool)) (*InfisicalConfiguration, error) {
	if environment == nil {
		return nil, &errs.Argument{Param: "environment"}
	}
	lookup := func(key string) string {
		if value, present := environment(key); present {
			return value
		}
		return ""
	}
	return InfisicalConfigurationResolve(
		lookup("TS_ORCH_INFISICAL_URL"),
		lookup("TS_ORCH_INFISICAL_PROJECT_ID"),
		lookup("TS_ORCH_INFISICAL_ENVIRONMENT"),
		lookup("TS_ORCH_INFISICAL_SECRET_PATH"),
		lookup("TS_ORCH_INFISICAL_CLIENT_ID_FILE"),
		lookup("TS_ORCH_INFISICAL_CLIENT_SECRET_FILE"),
		lookup("TS_ORCH_INFISICAL_ORGANIZATION_SLUG"))
}

// InfisicalConfigurationResolve validates and resolves every Infisical setting;
// empty strings mean "not supplied" and a completely empty input resolves to a
// nil configuration.
func InfisicalConfigurationResolve(
	server string,
	projectId string,
	environment string,
	secretPath string,
	clientIdFile string,
	clientSecretFile string,
	organizationSlug string,
) (*InfisicalConfiguration, error) {
	supplied := anySupplied(server, projectId, environment, secretPath, clientIdFile, clientSecretFile, organizationSlug)
	if !supplied {
		return nil, nil
	}
	if isBlank(projectId) || isBlank(environment) || isBlank(clientIdFile) || isBlank(clientSecretFile) {
		return nil, &errs.Argument{
			Message: "Infisical requires project, environment, client ID file, and client secret file together.",
		}
	}

	serverValue := "https://app.infisical.com"
	if !isBlank(server) {
		serverValue = server
	}
	serverUri, err := parseInfisicalServerUri(serverValue)
	if err != nil {
		return nil, err
	}

	resolvedPath := "/"
	if !isBlank(secretPath) {
		resolvedPath = secretPath
	}
	resolvedProject, err := infisicalRequireText(projectId, 128, "Infisical project", false)
	if err != nil {
		return nil, err
	}
	resolvedEnvironment, err := infisicalRequireText(environment, 64, "Infisical environment", false)
	if err != nil {
		return nil, err
	}
	if _, err := infisicalRequireText(resolvedPath, 512, "Infisical secret path", true); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(resolvedPath, "/") || strings.Contains(resolvedPath, "?") || strings.Contains(resolvedPath, "#") {
		return nil, &errs.Argument{Message: "The Infisical secret path must be an absolute vault path."}
	}

	var resolvedOrganization *string
	if !isBlank(organizationSlug) {
		validated, textErr := infisicalRequireText(organizationSlug, 64, "Infisical organization slug", false)
		if textErr != nil {
			return nil, textErr
		}
		resolvedOrganization = &validated
	}

	resolvedClientId, err := infisicalResolveCredentialFile(clientIdFile, "Infisical client ID")
	if err != nil {
		return nil, err
	}
	resolvedClientSecret, err := infisicalResolveCredentialFile(clientSecretFile, "Infisical client secret")
	if err != nil {
		return nil, err
	}

	return &InfisicalConfiguration{
		Server:           serverUri,
		VaultProject:     resolvedProject,
		Environment:      resolvedEnvironment,
		SecretPath:       resolvedPath,
		ClientIdFile:     resolvedClientId,
		ClientSecretFile: resolvedClientSecret,
		OrganizationSlug: resolvedOrganization,
	}, nil
}

func parseInfisicalServerUri(serverValue string) (string, error) {
	parsed, err := url.Parse(serverValue)
	if err != nil {
		return "", &errs.Argument{Message: "The Infisical server URL is invalid or insecure."}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.Host == "" || (scheme != "http" && scheme != "https") {
		return "", &errs.Argument{Message: "The Infisical server URL is invalid or insecure."}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", &errs.Argument{Message: "The Infisical server URL is invalid or insecure."}
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", &errs.Argument{Message: "The Infisical server URL is invalid or insecure."}
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	if port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		port = "" // Uri canonicalizes default ports away (GetLeftPart(Port omitted)).
	}
	if scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return "", &errs.Argument{Message: "The Infisical server URL is invalid or insecure."}
	}

	authority := strings.ToLower(parsed.Hostname())
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	return scheme + "://" + authority + "/", nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func infisicalRequireText(value string, maximum int, name string, allowSlash bool) (string, error) {
	if isBlank(value) || len(value) > maximum {
		return "", &errs.Argument{Message: fmt.Sprintf("The %s is invalid.", name)}
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", &errs.Argument{Message: fmt.Sprintf("The %s is invalid.", name)}
		}
		if !allowSlash && character == '/' {
			return "", &errs.Argument{Message: fmt.Sprintf("The %s is invalid.", name)}
		}
	}
	return value, nil
}

func infisicalResolveCredentialFile(value string, name string) (string, error) {
	if goruntime.GOOS != "linux" {
		return "", &PlatformNotSupportedError{
			Message: "Infisical credential files require Linux file permissions.",
		}
	}
	if isBlank(value) {
		return "", &errs.Argument{Message: fmt.Sprintf("The %s file is required.", name)}
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return "", &errs.Argument{Message: fmt.Sprintf("The %s file must be bounded, regular, and owner-private.", name)}
	}
	info, statErr := os.Stat(path)
	linkInfo, linkErr := os.Lstat(path)
	if statErr != nil || linkErr != nil || linkInfo.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > 4096 {
		return "", &errs.Argument{Message: fmt.Sprintf("The %s file must be bounded, regular, and owner-private.", name)}
	}
	if unixMode(linkInfo)&infisicalForbiddenCredentialMode != 0 {
		return "", &errs.Argument{Message: fmt.Sprintf("The %s file must be bounded, regular, and owner-private.", name)}
	}
	return path, nil
}

// ReadClientId reads and validates the client ID credential file.
func (c *InfisicalConfiguration) ReadClientId() (string, error) {
	return c.readCredential(c.ClientIdFile, "Infisical client ID")
}

// ReadClientSecret reads and validates the client secret credential file.
func (c *InfisicalConfiguration) ReadClientSecret() (string, error) {
	return c.readCredential(c.ClientSecretFile, "Infisical client secret")
}

func (c *InfisicalConfiguration) readCredential(path string, name string) (string, error) {
	resolvedPath, err := infisicalResolveCredentialFile(path, name)
	if err != nil {
		return "", err
	}
	raw, readErr := os.ReadFile(resolvedPath)
	if readErr != nil {
		return "", &InvalidDataError{Message: fmt.Sprintf("The %s file is invalid.", name)}
	}
	defer clearBytes(raw)
	if !utf8.Valid(raw) {
		return "", &InvalidDataError{Message: fmt.Sprintf("The %s file is invalid.", name)}
	}
	value := string(raw)
	if len(value) < 1 || len(value) > 4096 {
		return "", &InvalidDataError{Message: fmt.Sprintf("The %s file is invalid.", name)}
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", &InvalidDataError{Message: fmt.Sprintf("The %s file is invalid.", name)}
		}
	}
	return value, nil
}

func isBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func anySupplied(values ...string) bool {
	for _, value := range values {
		if !isBlank(value) {
			return true
		}
	}
	return false
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// InfisicalSecret is one fetched secret (name, value, version, path).
type InfisicalSecret struct {
	Name    string
	Value   string
	Version int
	Path    string
}

func (s InfisicalSecret) String() string {
	return fmt.Sprintf("%s:%s@%d", s.Path, s.Name, s.Version)
}

// InfisicalSecretMetadata is one secret's redacted metadata.
type InfisicalSecretMetadata struct {
	Name    string
	Version int
	Path    string
}

// InfisicalSecretStore is the direct Universal Auth and v4 Secrets API adapter.
// Secret values never appear in its errors.
type InfisicalSecretStore struct {
	mu             sync.Mutex
	configuration  *InfisicalConfiguration
	client         *http.Client
	authentication chan struct{}
	closed         chan struct{}
	accessToken    []byte
	inFlight       int
	disposed       bool
}

// InfisicalSecretStoreCreate builds the production store.
func InfisicalSecretStoreCreate(configuration *InfisicalConfiguration) *InfisicalSecretStore {
	transport := &http.Transport{
		DisableCompression: true,
	}
	return InfisicalSecretStoreCreateWithTransport(configuration, transport)
}

// InfisicalSecretStoreCreateWithTransport is the injectable seam used by tests.
func InfisicalSecretStoreCreateWithTransport(configuration *InfisicalConfiguration, transport http.RoundTripper) *InfisicalSecretStore {
	configuration = cloneInfisicalConfiguration(configuration)
	return &InfisicalSecretStore{
		configuration:  configuration,
		client:         &http.Client{Timeout: 15 * time.Second, Transport: transport},
		authentication: make(chan struct{}, 1),
		closed:         make(chan struct{}),
	}
}

// List returns the redacted metadata of every secret in scope.
func (s *InfisicalSecretStore) List(ctx context.Context) ([]InfisicalSecretMetadata, error) {
	documents, err := s.listDocuments(ctx, false)
	if err != nil {
		return nil, err
	}
	metadata := make([]InfisicalSecretMetadata, 0, len(documents))
	for _, document := range documents {
		path, pathErr := s.pathOf(&document)
		if pathErr != nil {
			return nil, pathErr
		}
		metadata = append(metadata, InfisicalSecretMetadata{
			Name:    document.SecretKey,
			Version: document.Version,
			Path:    path,
		})
	}
	return metadata, nil
}

// Get fetches one secret with its value.
func (s *InfisicalSecretStore) Get(ctx context.Context, name string) (InfisicalSecret, error) {
	if err := infisicalRequireSecretName(name); err != nil {
		return InfisicalSecret{}, err
	}
	var response secretResponse
	if err := s.send(ctx, http.MethodGet,
		fmt.Sprintf("api/v4/secrets/%s?%s&viewSecretValue=true&expandSecretReferences=true",
			infisicalEscapeDataString(name), s.scopeQuery()),
		nil, &response); err != nil {
		return InfisicalSecret{}, err
	}
	document, err := s.requireDocument(response.Secret)
	if err != nil {
		return InfisicalSecret{}, err
	}
	if document.SecretValue == nil {
		return InfisicalSecret{}, &InvalidDataError{Message: "Infisical did not return the requested secret value."}
	}
	path, pathErr := s.pathOf(document)
	if pathErr != nil {
		return InfisicalSecret{}, pathErr
	}
	return InfisicalSecret{
		Name:    document.SecretKey,
		Value:   *document.SecretValue,
		Version: document.Version,
		Path:    path,
	}, nil
}

// Create writes a new secret.
func (s *InfisicalSecretStore) Create(ctx context.Context, name string, value string) (InfisicalSecretMetadata, error) {
	return s.write(ctx, http.MethodPost, name, value)
}

// Update overwrites an existing secret.
func (s *InfisicalSecretStore) Update(ctx context.Context, name string, value string) (InfisicalSecretMetadata, error) {
	return s.write(ctx, http.MethodPatch, name, value)
}

func (s *InfisicalSecretStore) write(ctx context.Context, method string, name string, value string) (InfisicalSecretMetadata, error) {
	if err := infisicalRequireSecretName(name); err != nil {
		return InfisicalSecretMetadata{}, err
	}
	if err := infisicalRequireSecretValue(value); err != nil {
		return InfisicalSecretMetadata{}, err
	}
	configuration, err := s.configurationSnapshot()
	if err != nil {
		return InfisicalSecretMetadata{}, err
	}
	body := secretWriteRequest{
		ProjectId:   configuration.VaultProject,
		Environment: configuration.Environment,
		SecretValue: value,
		SecretPath:  configuration.SecretPath,
		Type:        "shared",
	}
	var response secretResponse
	if err := s.send(ctx, method,
		fmt.Sprintf("api/v4/secrets/%s", infisicalEscapeDataString(name)),
		body, &response); err != nil {
		return InfisicalSecretMetadata{}, err
	}
	return s.metadataOf(response.Secret)
}

// Delete removes one secret.
func (s *InfisicalSecretStore) Delete(ctx context.Context, name string) (InfisicalSecretMetadata, error) {
	if err := infisicalRequireSecretName(name); err != nil {
		return InfisicalSecretMetadata{}, err
	}
	configuration, err := s.configurationSnapshot()
	if err != nil {
		return InfisicalSecretMetadata{}, err
	}
	body := secretDeleteRequest{
		ProjectId:   configuration.VaultProject,
		Environment: configuration.Environment,
		SecretPath:  configuration.SecretPath,
		Type:        "shared",
	}
	var response secretResponse
	if err := s.send(ctx, http.MethodDelete,
		fmt.Sprintf("api/v4/secrets/%s", infisicalEscapeDataString(name)),
		body, &response); err != nil {
		return InfisicalSecretMetadata{}, err
	}
	return s.metadataOf(response.Secret)
}

// LoadEnvironment fetches every secret value keyed by secret name.
func (s *InfisicalSecretStore) LoadEnvironment(ctx context.Context) (map[string]string, error) {
	documents, err := s.listDocuments(ctx, true)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(documents))
	for _, document := range documents {
		if document.SecretValue == nil {
			return nil, &InvalidDataError{Message: "Infisical returned missing or duplicate secret values."}
		}
		if _, duplicate := values[document.SecretKey]; duplicate {
			return nil, &InvalidDataError{Message: "Infisical returned missing or duplicate secret values."}
		}
		values[document.SecretKey] = *document.SecretValue
	}
	return values, nil
}

func (s *InfisicalSecretStore) listDocuments(ctx context.Context, viewValues bool) ([]secretDocument, error) {
	viewText := "false"
	if viewValues {
		viewText = "true"
	}
	var response secretListResponse
	if err := s.send(ctx, http.MethodGet,
		fmt.Sprintf("api/v4/secrets?%s&viewSecretValue=%s&expandSecretReferences=true&recursive=false",
			s.scopeQuery(), viewText),
		nil, &response); err != nil {
		return nil, err
	}
	if response.Secrets == nil {
		return nil, &InvalidDataError{Message: "Infisical returned an invalid secret list."}
	}
	values := make(map[string]secretDocument, len(response.Secrets))
	var order []string
	for index := range response.Secrets {
		valid, err := s.requireDocument(&response.Secrets[index])
		if err != nil {
			return nil, err
		}
		if _, seen := values[valid.SecretKey]; !seen {
			order = append(order, valid.SecretKey)
		}
		values[valid.SecretKey] = *valid
	}
	for _, imported := range response.Imports {
		for index := range imported.Secrets {
			valid, err := s.requireDocument(&imported.Secrets[index])
			if err != nil {
				return nil, err
			}
			if valid.SecretPath == nil || isBlank(*valid.SecretPath) {
				path := imported.SecretPath
				valid.SecretPath = &path
			}
			if _, seen := values[valid.SecretKey]; !seen {
				order = append(order, valid.SecretKey)
			}
			values[valid.SecretKey] = *valid
		}
	}
	documents := make([]secretDocument, 0, len(order))
	for _, key := range order {
		documents = append(documents, values[key])
	}
	return documents, nil
}

func (s *InfisicalSecretStore) send(ctx context.Context, method string, relativeUri string, body any, result any) error {
	if s == nil {
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The Infisical context must not be nil."}
	}
	s.mu.Lock()
	disposed := s.disposed
	configured := s.configuration != nil
	s.mu.Unlock()
	if disposed || !configured {
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	if err := s.ensureAuthenticated(ctx); err != nil {
		return err
	}
	lease, err := s.acquireRequestLease(true)
	if err != nil {
		return err
	}
	defer lease.release()
	var payload io.Reader
	if body != nil {
		encoded, err := infisicalMarshalJSON(body)
		if err != nil {
			return &InvalidDataError{Message: "Infisical returned an invalid secret response."}
		}
		defer clearBytes(encoded)
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, lease.server+relativeUri, payload)
	if err != nil {
		return &InvalidDataError{Message: "Infisical returned an invalid secret response."}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(lease.token))
	if body != nil {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	return s.sendRequest(ctx, request, "secret", result)
}

func (s *InfisicalSecretStore) ensureAuthenticated(ctx context.Context) error {
	if s == nil {
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The Infisical context must not be nil."}
	}
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	if len(s.accessToken) > 0 {
		s.mu.Unlock()
		return nil
	}
	configuration := cloneInfisicalConfiguration(s.configuration)
	closed := s.closed
	s.mu.Unlock()
	if configuration == nil {
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	select {
	case s.authentication <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	defer func() { <-s.authentication }()
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	if len(s.accessToken) > 0 {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	clientId, err := configuration.ReadClientId()
	if err != nil {
		return err
	}
	clientSecret, err := configuration.ReadClientSecret()
	if err != nil {
		return err
	}
	body := loginRequest{
		ClientId:         clientId,
		ClientSecret:     clientSecret,
		OrganizationSlug: configuration.OrganizationSlug,
	}
	encoded, err := infisicalMarshalJSON(body)
	if err != nil {
		return &InvalidDataError{Message: "Infisical returned an invalid authentication response."}
	}
	defer clearBytes(encoded)
	request, requestErr := http.NewRequestWithContext(
		ctx, http.MethodPost, configuration.Server+"api/v1/auth/universal-auth/login",
		bytes.NewReader(encoded))
	if requestErr != nil {
		return &InvalidDataError{Message: "Infisical returned an invalid authentication response."}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	var response loginResponse
	lease, leaseErr := s.acquireRequestLease(false)
	if leaseErr != nil {
		return leaseErr
	}
	defer lease.release()
	if err := s.sendRequest(ctx, request, "authentication", &response); err != nil {
		return err
	}
	if response.ExpiresIn <= 0 || isBlank(response.AccessToken) || containsWhitespaceOrControl(response.AccessToken) {
		return &InvalidDataError{Message: "Infisical returned an invalid authentication response."}
	}
	accessToken := []byte(response.AccessToken)
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		clearBytes(accessToken)
		return &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	s.accessToken = accessToken
	s.mu.Unlock()
	return nil
}

type infisicalRequestLease struct {
	store  *InfisicalSecretStore
	server string
	token  []byte
}

func (s *InfisicalSecretStore) acquireRequestLease(requireToken bool) (*infisicalRequestLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disposed || s.configuration == nil || (requireToken && len(s.accessToken) == 0) {
		return nil, &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	s.inFlight++
	return &infisicalRequestLease{
		store:  s,
		server: s.configuration.Server,
		token:  s.accessToken,
	}, nil
}

func (l *infisicalRequestLease) release() {
	if l == nil || l.store == nil {
		return
	}
	store := l.store
	store.mu.Lock()
	store.inFlight--
	if store.disposed && store.inFlight == 0 {
		clearBytes(store.accessToken)
		store.accessToken = nil
	}
	store.mu.Unlock()
	l.store = nil
	l.server = ""
	l.token = nil
}

func (s *InfisicalSecretStore) sendRequest(ctx context.Context, request *http.Request, operation string, result any) error {
	response, err := s.client.Do(request)
	if err != nil {
		// Transport failures surface like the C# HttpRequestException path.
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Infisical %s failed with HTTP %d.", operation, response.StatusCode),
		}
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, infisicalMaximumResponseBytes+1))
	if readErr != nil {
		return &InvalidDataError{Message: fmt.Sprintf("Infisical returned an invalid %s response.", operation)}
	}
	if len(body) > infisicalMaximumResponseBytes {
		return &InvalidDataError{Message: fmt.Sprintf("Infisical returned an invalid %s response.", operation)}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return &InvalidDataError{Message: fmt.Sprintf("Infisical returned an invalid %s response.", operation)}
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return &InvalidDataError{Message: fmt.Sprintf("Infisical returned an empty %s response.", operation)}
	}
	if err := json.Unmarshal(trimmed, result); err != nil {
		return &InvalidDataError{Message: fmt.Sprintf("Infisical returned an invalid %s response.", operation)}
	}
	return nil
}

func (s *InfisicalSecretStore) scopeQuery() string {
	configuration, err := s.configurationSnapshot()
	if err != nil {
		return ""
	}
	return strings.Join([]string{
		infisicalPair("projectId", configuration.VaultProject),
		infisicalPair("environment", configuration.Environment),
		infisicalPair("secretPath", configuration.SecretPath),
	}, "&")
}

func (s *InfisicalSecretStore) configurationSnapshot() (*InfisicalConfiguration, error) {
	if s == nil {
		return nil, &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disposed || s.configuration == nil {
		return nil, &InvalidOperationError{Message: "Cannot access a disposed object."}
	}
	return cloneInfisicalConfiguration(s.configuration), nil
}

func cloneInfisicalConfiguration(configuration *InfisicalConfiguration) *InfisicalConfiguration {
	if configuration == nil {
		return nil
	}
	clone := *configuration
	if configuration.OrganizationSlug != nil {
		organization := *configuration.OrganizationSlug
		clone.OrganizationSlug = &organization
	}
	return &clone
}

func infisicalPair(key string, value string) string {
	return infisicalEscapeDataString(key) + "=" + infisicalEscapeDataString(value)
}

// infisicalEscapeDataString mirrors System.Uri.EscapeDataString: every byte
// outside the unreserved set is percent-encoded.
func infisicalEscapeDataString(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' || character == '.' ||
			character == '_' || character == '~' {
			builder.WriteByte(character)
		} else {
			fmt.Fprintf(&builder, "%%%02X", character)
		}
	}
	return builder.String()
}

func (s *InfisicalSecretStore) metadataOf(document *secretDocument) (InfisicalSecretMetadata, error) {
	valid, err := s.requireDocument(document)
	if err != nil {
		return InfisicalSecretMetadata{}, err
	}
	path, pathErr := s.pathOf(valid)
	if pathErr != nil {
		return InfisicalSecretMetadata{}, pathErr
	}
	return InfisicalSecretMetadata{
		Name:    valid.SecretKey,
		Version: valid.Version,
		Path:    path,
	}, nil
}

func (s *InfisicalSecretStore) pathOf(document *secretDocument) (string, error) {
	path := s.configuration.SecretPath
	if document.SecretPath != nil && !isBlank(*document.SecretPath) {
		path = *document.SecretPath
	}
	if len(path) > 512 || !strings.HasPrefix(path, "/") || strings.ContainsFunc(path, unicode.IsControl) {
		return "", &InvalidDataError{Message: "Infisical returned invalid secret metadata."}
	}
	return path, nil
}

func (s *InfisicalSecretStore) requireDocument(document *secretDocument) (*secretDocument, error) {
	if document == nil || document.Version < 1 {
		return nil, &InvalidDataError{Message: "Infisical returned invalid secret metadata."}
	}
	if err := infisicalRequireSecretName(document.SecretKey); err != nil {
		return nil, err
	}
	return document, nil
}

func infisicalRequireSecretName(name string) error {
	if isBlank(name) || len(name) > 256 || strings.ContainsFunc(name, unicode.IsControl) {
		return &errs.Argument{Param: "name", Message: "The Infisical secret name is invalid."}
	}
	return nil
}

func infisicalRequireSecretValue(value string) error {
	if len(value) > 1024*1024 {
		return &errs.Argument{Param: "value", Message: "The Infisical secret value exceeds the supported bound."}
	}
	return nil
}

func containsWhitespaceOrControl(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

// Close disposes the store (IAsyncDisposable in the C# source).
func (s *InfisicalSecretStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.disposed {
		s.mu.Unlock()
		return
	}
	s.disposed = true
	if s.closed != nil {
		close(s.closed)
	}
	if s.inFlight == 0 {
		clearBytes(s.accessToken)
		s.accessToken = nil
	}
	client := s.client
	s.mu.Unlock()
	if client != nil {
		client.CloseIdleConnections()
	}
}

type loginRequest struct {
	ClientId         string  `json:"clientId"`
	ClientSecret     string  `json:"clientSecret"`
	OrganizationSlug *string `json:"organizationSlug,omitempty"`
}

type loginResponse struct {
	AccessToken       string `json:"accessToken"`
	ExpiresIn         int    `json:"expiresIn"`
	AccessTokenMaxTtl int    `json:"accessTokenMaxTtl"`
}

type secretWriteRequest struct {
	ProjectId   string `json:"projectId"`
	Environment string `json:"environment"`
	SecretValue string `json:"secretValue"`
	SecretPath  string `json:"secretPath"`
	Type        string `json:"type"`
}

type secretDeleteRequest struct {
	ProjectId   string `json:"projectId"`
	Environment string `json:"environment"`
	SecretPath  string `json:"secretPath"`
	Type        string `json:"type"`
}

type secretResponse struct {
	Secret *secretDocument `json:"secret"`
}

type secretListResponse struct {
	Secrets []secretDocument `json:"secrets"`
	Imports []secretImport   `json:"imports"`
}

type secretImport struct {
	SecretPath string           `json:"secretPath"`
	Secrets    []secretDocument `json:"secrets"`
}

type secretDocument struct {
	SecretKey   string  `json:"secretKey"`
	SecretValue *string `json:"secretValue"`
	Version     int     `json:"version"`
	SecretPath  *string `json:"secretPath"`
}

const infisicalSecretDirectoryMode = 0o700
const infisicalSecretFileMode = 0o600

// InfisicalSecretEnvironment materializes fetched secrets, writing every
// *_FILE setting to an owner-private temporary file and substituting its path.
type InfisicalSecretEnvironment struct {
	mu        sync.RWMutex
	values    map[string]string
	directory *string
	closed    bool
}

// InfisicalSecretEnvironmentLoad loads the environment through a fresh store.
func InfisicalSecretEnvironmentLoad(ctx context.Context, configuration *InfisicalConfiguration) (*InfisicalSecretEnvironment, error) {
	store := InfisicalSecretStoreCreate(configuration)
	defer store.Close()
	return InfisicalSecretEnvironmentLoadFromStore(ctx, store)
}

// InfisicalSecretEnvironmentLoadFromStore loads the environment through an
// existing store.
func InfisicalSecretEnvironmentLoadFromStore(ctx context.Context, store *InfisicalSecretStore) (*InfisicalSecretEnvironment, error) {
	if store == nil {
		return nil, &errs.Argument{Param: "store"}
	}
	if goruntime.GOOS != "linux" {
		return nil, &PlatformNotSupportedError{
			Message: "Infisical secret files require Linux file permissions.",
		}
	}
	secrets, err := store.LoadEnvironment(ctx)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(secrets))
	for key, value := range secrets {
		values[key] = value
	}
	var directory *string
	fail := func(loadErr error) (*InfisicalSecretEnvironment, error) {
		if directory != nil {
			os.RemoveAll(*directory)
		}
		return nil, loadErr
	}
	for key, value := range secrets {
		if !infisicalIsFileSetting(key) {
			continue
		}
		if directory == nil {
			created, dirErr := infisicalCreateDirectory()
			if dirErr != nil {
				return fail(dirErr)
			}
			directory = &created
		}
		path := filepath.Join(*directory, strings.ToLower(key))
		raw := []byte(value)
		if err := infisicalWritePrivateFile(path, raw); err != nil {
			clearBytes(raw)
			return fail(err)
		}
		clearBytes(raw)
		values[key] = path
	}
	return &InfisicalSecretEnvironment{values: values, directory: directory}, nil
}

// GetValue returns the materialized environment value for a key.
func (e *InfisicalSecretEnvironment) GetValue(key string) (string, bool) {
	if e == nil {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	value, present := e.values[key]
	return value, present
}

// Dispose clears the in-memory values and removes the secret directory.
func (e *InfisicalSecretEnvironment) Dispose() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.values = nil
	directory := e.directory
	e.directory = nil
	e.mu.Unlock()
	if directory != nil {
		os.RemoveAll(*directory)
	}
}

func infisicalIsFileSetting(key string) bool {
	if !strings.HasPrefix(key, "TS_ORCH_") || !strings.HasSuffix(key, "_FILE") {
		return false
	}
	for _, character := range key {
		if !(character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func infisicalCreateDirectory() (string, error) {
	if goruntime.GOOS != "linux" {
		return "", &PlatformNotSupportedError{
			Message: "Infisical secret files require Linux file permissions.",
		}
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	path := filepath.Join(os.TempDir(),
		fmt.Sprintf("terrascale-infisical-%d-%s", os.Getpid(), hex.EncodeToString(random)))
	if err := os.Mkdir(path, infisicalSecretDirectoryMode); err != nil {
		return "", err
	}
	if err := os.Chmod(path, infisicalSecretDirectoryMode); err != nil {
		os.RemoveAll(path)
		return "", err
	}
	return path, nil
}

func infisicalWritePrivateFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, infisicalSecretFileMode)
	if err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
