// This file ports tests/TerraScale.Orchestrator.Tests/
// InfisicalSecretStoreTests.cs. It runs only on Linux (the C# suite is
// [SupportedOSPlatform("linux")] and skips its body elsewhere).
package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	goruntime "runtime"
)

func skipUnlessLinux(t *testing.T) {
	t.Helper()
	if goruntime.GOOS != "linux" {
		t.Skip("Infisical credential and secret files require Linux file permissions.")
	}
}

type infisicalFixture struct {
	root         string
	clientId     string
	clientSecret string
}

func newInfisicalFixture(t *testing.T) *infisicalFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "infisical-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	fixture := &infisicalFixture{
		root:         root,
		clientId:     filepath.Join(root, "client-id"),
		clientSecret: filepath.Join(root, "client-secret"),
	}
	writeFile := func(path string) {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("chmod: %v", err)
		}
	}
	writeFile(fixture.clientId)
	writeFile(fixture.clientSecret)
	t.Cleanup(func() { os.RemoveAll(root) })
	return fixture
}

func (f *infisicalFixture) configuration(t *testing.T) *InfisicalConfiguration {
	t.Helper()
	configuration, err := InfisicalConfigurationResolve(
		"http://127.0.0.1:8080", "project-1", "prod", "/orchestrator",
		f.clientId, f.clientSecret, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return configuration
}

func TestConfigurationRequiresACompleteSecureUniversalAuthIdentity(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)

	configuration := fixture.configuration(t)
	if configuration.Server != "http://127.0.0.1:8080/" {
		t.Fatalf("unexpected server %q", configuration.Server)
	}
	if configuration.VaultProject != "project-1" || configuration.Environment != "prod" || configuration.SecretPath != "/orchestrator" {
		t.Fatalf("unexpected configuration %+v", configuration)
	}
	blankOrganization, err := InfisicalConfigurationResolve(
		"", "project-1", "prod", "", fixture.clientId, fixture.clientSecret, " ")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Resolve treats empty strings as absent; OrganizationSlug " " is blank → nil.
	if blankOrganization == nil || blankOrganization.OrganizationSlug != nil {
		t.Fatal("a blank organization slug must resolve to nil")
	}
	if _, err := InfisicalConfigurationResolve(
		"", "project-1", "", "", fixture.clientId, fixture.clientSecret, ""); err == nil {
		t.Fatal("an incomplete identity must be rejected")
	}
	if _, err := InfisicalConfigurationResolve(
		"http://infisical.example", "project-1", "prod", "/", fixture.clientId, fixture.clientSecret, ""); err == nil {
		t.Fatal("a non-loopback plain-HTTP server must be rejected")
	}

	if err := os.Chmod(fixture.clientSecret, 0o604); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := InfisicalConfigurationResolve(
		"http://127.0.0.1:8080", "project-1", "prod", "/orchestrator",
		fixture.clientId, fixture.clientSecret, ""); err == nil {
		t.Fatal("a non-private credential file must be rejected")
	}
}

func TestInfisicalStoreSnapshotsConfigurationOwnership(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)
	organization := "original-org"
	configuration := fixture.configuration(t)
	configuration.OrganizationSlug = &organization
	store := InfisicalSecretStoreCreateWithTransport(configuration, infisicalHandlerTransport{
		handle: func(*http.Request) *http.Response { return infisicalJsonResponse(http.StatusInternalServerError, `{}`) },
	})
	t.Cleanup(store.Close)

	configuration.Server = "https://mutated.example/"
	configuration.VaultProject = "mutated-project"
	organization = "mutated-org"

	snapshot, err := store.configurationSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Server != "http://127.0.0.1:8080/" || snapshot.VaultProject != "project-1" ||
		snapshot.OrganizationSlug == nil || *snapshot.OrganizationSlug != "original-org" {
		t.Fatalf("store did not retain an owned configuration snapshot: %+v", snapshot)
	}
}

func TestProvisionJournalDoesNotLoadTheGenericRuntimeSecretEnvironment(t *testing.T) {
	if InfisicalConfigurationRequiresRuntimeSecretEnvironment("provision-journal") {
		t.Fatal("provision-journal must not load the runtime secret environment")
	}
	if InfisicalConfigurationRequiresRuntimeSecretEnvironment("journal-writer") {
		t.Fatal("journal-writer must not load the runtime secret environment")
	}
	if !InfisicalConfigurationRequiresRuntimeSecretEnvironment("run") ||
		!InfisicalConfigurationRequiresRuntimeSecretEnvironment("check") ||
		!InfisicalConfigurationRequiresRuntimeSecretEnvironment("runner") {
		t.Fatal("runtime commands must load the runtime secret environment")
	}
}

type capturedInfisicalRequest struct {
	Method        string
	Path          string
	Query         string
	Authorization string
}

type infisicalHandlerTransport struct {
	handle func(request *http.Request) *http.Response
}

func (t infisicalHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response := t.handle(request)
	if response == nil {
		return nil, fmt.Errorf("Unexpected Infisical request.")
	}
	return response, nil
}

func infisicalJsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestV4ClientAuthenticatesAndSupportsSecretCrudWithoutLeakingValues(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)
	var requests []capturedInfisicalRequest
	transport := infisicalHandlerTransport{handle: func(request *http.Request) *http.Response {
		var body string
		if request.Body != nil {
			raw, _ := io.ReadAll(request.Body)
			body = string(raw)
		}
		requests = append(requests, capturedInfisicalRequest{
			Method:        request.Method,
			Path:          request.URL.Path,
			Query:         request.URL.RawQuery,
			Authorization: request.Header.Get("Authorization"),
		})
		if request.URL.Path == "/api/v1/auth/universal-auth/login" {
			if !strings.Contains(body, "client-id") || !strings.Contains(body, "client-secret") {
				t.Fatal("the login body must carry the universal auth identity")
			}
			return infisicalJsonResponse(200,
				`{"accessToken":"access-token","expiresIn":3600,"accessTokenMaxTTL":7200}`)
		}
		if request.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("unexpected authorization %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == "GET" && request.URL.Path == "/api/v4/secrets":
			return infisicalJsonResponse(200, `{"secrets":[{"secretKey":"LOCAL","version":2,"secretPath":"/orchestrator"}],
                     "imports":[{"secretPath":"/imported","secrets":[
                       {"secretKey":"LOCAL","version":1},
                       {"secretKey":"IMPORTED","version":3}]}]}`)
		case request.Method == "GET" && request.URL.Path == "/api/v4/secrets/API_KEY":
			return infisicalJsonResponse(200,
				`{"secret":{"secretKey":"API_KEY","secretValue":"sentinel-secret-value","version":4,"secretPath":"/orchestrator"}}`)
		case request.Method == "POST" && request.URL.Path == "/api/v4/secrets/NEW":
			return infisicalJsonResponse(200, `{"secret":{"secretKey":"NEW","version":1,"secretPath":"/orchestrator"}}`)
		case request.Method == "PATCH" && request.URL.Path == "/api/v4/secrets/NEW":
			return infisicalJsonResponse(200, `{"secret":{"secretKey":"NEW","version":2,"secretPath":"/orchestrator"}}`)
		case request.Method == "DELETE" && request.URL.Path == "/api/v4/secrets/NEW":
			return infisicalJsonResponse(200, `{"secret":{"secretKey":"NEW","version":2,"secretPath":"/orchestrator"}}`)
		case request.Method == "GET" && request.URL.Path == "/api/v4/secrets/DENIED":
			return infisicalJsonResponse(403, `{"message":"sentinel-secret-value"}`)
		case request.Method == "GET" && request.URL.Path == "/api/v4/secrets/BAD_PATH":
			return infisicalJsonResponse(200,
				`{"secret":{"secretKey":"BAD_PATH","secretValue":"sentinel-secret-value","version":1,"secretPath":"/bad\npath"}}`)
		default:
			return nil
		}
	}}
	store := InfisicalSecretStoreCreateWithTransport(fixture.configuration(t), transport)
	defer store.Close()
	ctx := context.Background()

	listed, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	fetched, err := store.Get(ctx, "API_KEY")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	created, err := store.Create(ctx, "NEW", "created-value")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := store.Update(ctx, "NEW", "updated-value")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	deleted, err := store.Delete(ctx, "NEW")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, deniedErr := store.Get(ctx, "DENIED")
	var operationError *InvalidOperationError
	if !errors.As(deniedErr, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", deniedErr)
	}
	_, badPathErr := store.Get(ctx, "BAD_PATH")
	var dataError *InvalidDataError
	if !errors.As(badPathErr, &dataError) {
		t.Fatalf("expected InvalidDataError, got %v", badPathErr)
	}

	var listedNames []string
	importedPath := ""
	for _, metadata := range listed {
		listedNames = append(listedNames, metadata.Name)
		if metadata.Name == "IMPORTED" {
			importedPath = metadata.Path
		}
	}
	if len(listedNames) != 2 {
		t.Fatalf("expected LOCAL and IMPORTED, got %v", listedNames)
	}
	if importedPath != "/imported" {
		t.Fatalf("unexpected imported path %q", importedPath)
	}
	if fetched.Value != "sentinel-secret-value" {
		t.Fatalf("unexpected fetched value %q", fetched.Value)
	}
	if strings.Contains(fetched.String(), "sentinel-secret-value") {
		t.Fatal("the secret string form must not leak the value")
	}
	if created.Version != 1 || updated.Version != 2 || deleted.Version != 2 {
		t.Fatalf("unexpected versions %d %d %d", created.Version, updated.Version, deleted.Version)
	}
	if strings.Contains(fmt.Sprint(deniedErr), "sentinel-secret-value") {
		t.Fatal("errors must not leak secret values")
	}
	if strings.Contains(fmt.Sprint(badPathErr), "sentinel-secret-value") {
		t.Fatal("errors must not leak secret values")
	}
	loginCount := 0
	for _, request := range requests {
		if request.Path == "/api/v1/auth/universal-auth/login" {
			loginCount++
		}
	}
	if loginCount != 1 {
		t.Fatalf("expected exactly one login, got %d", loginCount)
	}
	for _, request := range requests {
		if request.Path == "/api/v4/secrets" && !strings.Contains(request.Query, "viewSecretValue=false") {
			t.Fatalf("listing must not request secret values: %q", request.Query)
		}
	}
}

func TestCloseDefersTokenClearUntilInFlightSendReleases(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)
	secretStarted := make(chan struct{})
	releaseSecret := make(chan struct{})
	var startedOnce sync.Once
	transport := infisicalHandlerTransport{handle: func(request *http.Request) *http.Response {
		switch request.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			return infisicalJsonResponse(200,
				`{"accessToken":"access-token","expiresIn":3600,"accessTokenMaxTTL":7200}`)
		case "/api/v4/secrets/API_KEY":
			startedOnce.Do(func() { close(secretStarted) })
			<-releaseSecret
			return infisicalJsonResponse(200,
				`{"secret":{"secretKey":"API_KEY","secretValue":"sentinel-secret-value","version":1,"secretPath":"/orchestrator"}}`)
		default:
			return nil
		}
	}}
	store := InfisicalSecretStoreCreateWithTransport(fixture.configuration(t), transport)

	result := make(chan error, 1)
	go func() {
		_, err := store.Get(context.Background(), "API_KEY")
		result <- err
	}()
	<-secretStarted

	closed := make(chan struct{})
	go func() {
		store.Close()
		store.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close must not wait for an in-flight network request")
	}

	store.mu.Lock()
	tokenRetained := len(store.accessToken) > 0
	store.mu.Unlock()
	if !tokenRetained {
		t.Fatal("an in-flight request must retain token ownership")
	}

	close(releaseSecret)
	if err := <-result; err != nil {
		t.Fatalf("an in-flight request should complete: %v", err)
	}
	store.mu.Lock()
	tokenCleared := len(store.accessToken) == 0 && store.inFlight == 0
	store.mu.Unlock()
	if !tokenCleared {
		t.Fatal("the token must be cleared when the last request releases it")
	}
}

func TestCloseRejectsAuthenticationThatFinishesAfterDisposal(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)
	authStarted := make(chan struct{})
	releaseAuth := make(chan struct{})
	var startedOnce sync.Once
	transport := infisicalHandlerTransport{handle: func(request *http.Request) *http.Response {
		if request.URL.Path != "/api/v1/auth/universal-auth/login" {
			return nil
		}
		startedOnce.Do(func() { close(authStarted) })
		<-releaseAuth
		return infisicalJsonResponse(200,
			`{"accessToken":"access-token","expiresIn":3600,"accessTokenMaxTTL":7200}`)
	}}
	store := InfisicalSecretStoreCreateWithTransport(fixture.configuration(t), transport)

	result := make(chan error, 1)
	go func() {
		_, err := store.Get(context.Background(), "API_KEY")
		result <- err
	}()
	<-authStarted
	closed := make(chan struct{})
	go func() {
		store.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close must not wait for authentication network I/O")
	}
	close(releaseAuth)
	if err := <-result; err == nil {
		t.Fatal("a request finishing after Close must fail")
	}
	store.mu.Lock()
	tokenCleared := len(store.accessToken) == 0 && store.inFlight == 0
	store.mu.Unlock()
	if !tokenCleared {
		t.Fatal("authentication must not install a token after Close")
	}
}

func TestStartupSecretsMaterializeExistingFileSettingsOwnerPrivately(t *testing.T) {
	skipUnlessLinux(t)
	fixture := newInfisicalFixture(t)
	transport := infisicalHandlerTransport{handle: func(request *http.Request) *http.Response {
		switch request.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			return infisicalJsonResponse(200,
				`{"accessToken":"access-token","expiresIn":3600,"accessTokenMaxTTL":7200}`)
		case "/api/v4/secrets":
			return infisicalJsonResponse(200, `{"secrets":[
                  {"secretKey":"TS_ORCH_CELL","secretValue":"fra","version":1,"secretPath":"/orchestrator"},
                  {"secretKey":"TS_ORCH_FORGEJO_API_TOKEN_FILE","secretValue":"private-token-value","version":1,"secretPath":"/orchestrator"}
                ],"imports":[]}`)
		default:
			return nil
		}
	}}
	store := InfisicalSecretStoreCreateWithTransport(fixture.configuration(t), transport)
	defer store.Close()

	environment, err := InfisicalSecretEnvironmentLoadFromStore(context.Background(), store)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cell, _ := environment.GetValue("TS_ORCH_CELL")
	tokenFile, _ := environment.GetValue("TS_ORCH_FORGEJO_API_TOKEN_FILE")

	if cell != "fra" {
		t.Fatalf("unexpected cell %q", cell)
	}
	if tokenFile == "private-token-value" {
		t.Fatal("file settings must be replaced with the materialized path")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(tokenBytes) != "private-token-value" {
		t.Fatalf("unexpected token bytes %q", string(tokenBytes))
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Mode&0o777 != 0o600 {
		t.Fatalf("token file must be owner-private: %o", info.Mode().Perm())
	}

	environment.Dispose()
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatal("dispose must remove the secret directory")
	}
}

func TestCliRequiresExplicitFilesAndExactDeleteConfirmation(t *testing.T) {
	if command, err := InfisicalCli.Parse([]string{"list"}); err != nil || command.Action != InfisicalCliActionList {
		t.Fatalf("unexpected list parse: %+v %v", command, err)
	}
	if command, err := InfisicalCli.Parse([]string{"get", "API_KEY", "--output", "/tmp/key"}); err != nil || command.Action != InfisicalCliActionGet {
		t.Fatalf("unexpected get parse: %+v %v", command, err)
	}
	if _, err := InfisicalCli.Parse([]string{"delete", "API_KEY", "--confirm", "OTHER"}); err == nil {
		t.Fatal("a mismatched delete confirmation must be rejected")
	}
	if _, err := InfisicalCli.Parse([]string{"create", "API_KEY", "literal-value"}); err == nil {
		t.Fatal("literal secret values must be rejected")
	}
}
