package ociclient

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type credentialSourceGuardKey struct{}

// WithCredentialSourceGuard revalidates a local accepted snapshot before credential waits and signing.
// The guard must use local state only: OCI reads here would recurse into the credential refresh lock.
func WithCredentialSourceGuard(ctx context.Context, guard func(context.Context) error) context.Context {
	return context.WithValue(ctx, credentialSourceGuardKey{}, guard)
}

type credentialScopeKey struct{}

// credentialContext restores the original request budget for credential acquisition and signing.

func credentialContext(ctx context.Context) (context.Context, func(), error) {
	release := func() {}
	if original := originalReadContext(ctx); original != nil && original.Done() != nil && original.Done() != ctx.Done() && ctx.Value(credentialScopeKey{}) != original.Done() {
		// Preserve values and any shorter outer deadline while restoring original cancellation.
		joined, cancel := context.WithCancel(ctx)
		var cancelDeadline context.CancelFunc = func() {}
		deadline, hasDeadline := original.Deadline()
		if hasDeadline {
			joined, cancelDeadline = context.WithDeadline(joined, deadline)
		}
		propagateCancellation := func() {
			// Let the child deadline report DeadlineExceeded rather than racing it with Canceled.
			if !hasDeadline || original.Err() != context.DeadlineExceeded {
				cancel()
			}
		}
		stop := context.AfterFunc(original, propagateCancellation)
		if original.Err() != nil {
			propagateCancellation()
		}
		ctx = context.WithValue(joined, credentialScopeKey{}, original.Done())
		release = func() { stop(); cancelDeadline(); cancel() }
	}
	return ctx, release, checkCredentialSource(ctx)
}

func checkCredentialSource(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if guard, ok := ctx.Value(credentialSourceGuardKey{}).(func(context.Context) error); ok {
		if guard == nil {
			return errors.New("OCI credential source is unavailable")
		}
		if err := guard(context.WithValue(ctx, credentialSourceGuardKey{}, struct{}{})); err != nil {
			return fmt.Errorf("OCI credential source guard: %w", err)
		}
	}
	return ctx.Err()
}

type credentialDispatcher struct{ next common.HTTPRequestDispatcher }

func (d credentialDispatcher) Do(request *http.Request) (*http.Response, error) {
	if err := checkCredentialSource(request.Context()); err != nil {
		return nil, err
	}
	return d.next.Do(request)
}

// contextualPrincipal retains credentials only; every key lookup supplies its own operation context.
type contextualPrincipal struct{ common.ConfigurationProvider }

func (p contextualPrincipal) Refreshable() bool {
	provider, ok := p.ConfigurationProvider.(common.RefreshableConfigurationProvider)
	return ok && provider.Refreshable()
}

func (p contextualPrincipal) KeyIDContext(ctx context.Context) (string, error) {
	ctx, release, err := credentialContext(ctx)
	defer release()
	if err != nil {
		return "", err
	}
	provider, ok := p.ConfigurationProvider.(common.ContextKeyProvider)
	if !ok {
		return "", errors.New("OCI instance principal provider lacks context support")
	}
	return provider.KeyIDContext(ctx)
}
func (p contextualPrincipal) PrivateRSAKeyContext(ctx context.Context) (*rsa.PrivateKey, error) {
	ctx, release, err := credentialContext(ctx)
	defer release()
	if err != nil {
		return nil, err
	}
	provider, ok := p.ConfigurationProvider.(common.ContextKeyProvider)
	if !ok {
		return nil, errors.New("OCI instance principal provider lacks context support")
	}
	return provider.PrivateRSAKeyContext(ctx)
}

// constructionProvider is private until the generated constructor returns and ctx is cleared.
type constructionProvider struct {
	common.ConfigurationProvider
	ctx context.Context
}

func (p *constructionProvider) Refreshable() bool {
	return (contextualPrincipal{p.ConfigurationProvider}).Refreshable()
}

func (p *constructionProvider) KeyID() (string, error) {
	if p.ctx != nil {
		return p.KeyIDContext(p.ctx)
	}
	return p.ConfigurationProvider.KeyID()
}
func (p *constructionProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	if p.ctx != nil {
		return p.PrivateRSAKeyContext(p.ctx)
	}
	return p.ConfigurationProvider.PrivateRSAKey()
}
func (p *constructionProvider) KeyIDContext(ctx context.Context) (string, error) {
	return (contextualPrincipal{p.ConfigurationProvider}).KeyIDContext(ctx)
}
func (p *constructionProvider) PrivateRSAKeyContext(ctx context.Context) (*rsa.PrivateKey, error) {
	return (contextualPrincipal{p.ConfigurationProvider}).PrivateRSAKeyContext(ctx)
}

// SecretsContext includes both eager SDK validation passes in the caller's operation budget.
func (f *Factory) SecretsContext(ctx context.Context) (secrets.SecretsClient, error) {
	ctx, release, err := credentialContext(ctx)
	defer release()
	if err != nil {
		return secrets.SecretsClient{}, err
	}
	provider := &constructionProvider{ConfigurationProvider: f.provider, ctx: ctx}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	provider.ctx = nil
	if err != nil {
		return client, fmt.Errorf("create OCI Secrets client: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return secrets.SecretsClient{}, err
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceVault)
	return client, nil
}
