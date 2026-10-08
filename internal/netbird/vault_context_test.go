package netbird

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type contextProviderDispatcher func(*http.Request) (*http.Response, error)

func (d contextProviderDispatcher) Do(request *http.Request) (*http.Response, error) {
	return d(request)
}

func TestInstancePrincipalInitializationRespectsEnrollmentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dispatcher := instancePrincipalContextDispatcher{ctx: ctx, dispatcher: contextProviderDispatcher(func(request *http.Request) (*http.Response, error) {
		got, ok := request.Context().Deadline()
		if !ok || !got.Equal(deadline) {
			return nil, errors.New("provider initialization did not inherit enrollment deadline")
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	// The OCI provider creates initialization requests without our context.
	request, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/opc/v2/identity/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dispatcher.Do(request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("provider initialization escaped the enrollment deadline: %v", err)
	}
}

func TestSecretsInitializationReleasesCallerDuringSDKBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release); <-finished })
	go func() { <-started; cancel() }()
	if _, err := initializeSecretsClient(ctx, func() (secrets.SecretsClient, error) {
		defer close(finished)
		close(started)
		// The SDK's retry sleep does not observe the request context.
		<-release
		return secrets.SecretsClient{}, errors.New("credential initialization ended")
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SDK credential backoff held the caller past its deadline: %v", err)
	}
	select {
	case <-finished:
		t.Fatal("test initializer unexpectedly ended before its simulated SDK backoff")
	default:
	}
}
