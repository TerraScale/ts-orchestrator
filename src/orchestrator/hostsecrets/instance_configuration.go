package hostsecrets

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// NewInstanceConfiguration creates the official instance-principal provider;
// local OCI profile credentials are never read. The context must live as long
// as its client because every later metadata/federation request is bound to it.
// Signing can refresh credentials using SDK-internal sleeps: callers must run
// signing inside the shared ociworker.Gate with a bounded caller context, as the
// Vault and Secrets adapters do, and sanitize SDK errors before returning them.
func NewInstanceConfiguration(ctx context.Context, region string) (common.ConfigurationProvider, error) {
	if ctx == nil || !provider.ValidOCIRegion(region) {
		return nil, ErrIdentity
	}
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrIdentity
	}
	type result struct {
		configuration common.ConfigurationProvider
		err           error
	}
	completed := make(chan result, 1)
	go func() {
		defer func() { <-identityWorker }()
		configuration, err := instanceConfiguration(ctx, region, credentialTransport())
		completed <- result{configuration, err}
	}()
	select {
	case outcome := <-completed:
		return outcome.configuration, outcome.err
	case <-ctx.Done():
		return nil, ErrIdentity
	}
}
