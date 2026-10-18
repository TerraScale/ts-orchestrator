package foundation

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// EnsureOriginalNetBirdPullCredentials runs only in the original user provision
// continuation. Instance admission cannot create this operator session.
func EnsureOriginalNetBirdPullCredentials(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, bundle region.RetainedFoundation) error {
	session, err := region.NewOriginalNetBirdOCIRSession(ctx, factory, roots, bundle)
	if err != nil {
		return err
	}
	scopes := session.Scopes()
	for _, scope := range scopes {
		if err := session.Guard(ctx, scope); err != nil {
			return err
		}
	}
	for _, scope := range scopes {
		guard := func(wire context.Context) error { return session.Guard(wire, scope) }
		bounded, cancel := context.WithDeadline(ctx, scope.ExpiresAt())
		defer cancel()
		guarded := ociclient.WithRequestGuard(bounded, guard)
		journal, err := session.Journal(guarded, scope)
		if err != nil {
			return err
		}
		intent := scope.Intent()
		regional, err := factory.ForRegion(intent.OCIRegion)
		if err != nil {
			return err
		}
		issuer, err := registry.NewIssuer(guarded, regional, journal, scope, guard, session.HomeWrite)
		if err != nil {
			return err
		}
		owned, err := issuer.Ensure(guarded)
		if err != nil {
			return err
		}
		expected := registry.PullSecret{RegistryHost: intent.RegistryHost, Repository: intent.RegistryNamespace + "/" + intent.RepositoryName,
			Ref: vaultsecret.Ref{Vault: intent.VaultTarget.VaultID, Name: intent.SecretName}}
		if owned != expected {
			return errors.New("original NetBird issuer returned a different credential binding")
		}
		if err := session.Guard(ctx, scope); err != nil {
			return err
		}
	}
	return nil
}
