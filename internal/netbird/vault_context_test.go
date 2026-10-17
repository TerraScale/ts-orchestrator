package netbird

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

func TestVaultIntegrationProviderInitializationCancelsHTTP(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { <-started; cancel() }()
	dispatcher := instancePrincipalContextDispatcher{ctx: ctx, dispatcher: server.Client()}
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeSecretsClient(ctx, func() (secrets.SecretsClient, error) {
		_, err := dispatcher.Do(request)
		return secrets.SecretsClient{}, err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("initialization escaped cancellation: %v", err)
	}
}

func TestVaultIntegrationInitializationReleasesCallerDuringHTTPBackoff(t *testing.T) {
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release); <-finished })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { <-started; cancel() }()
	startedAt := time.Now()
	if _, err := initializeSecretsClient(ctx, func() (secrets.SecretsClient, error) {
		defer close(finished)
		response, err := server.Client().Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		return secrets.SecretsClient{}, err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("initialization held caller: %v", err)
	}
	if time.Since(startedAt) > time.Second {
		t.Fatal("initialization cancellation exceeded one second")
	}
}
