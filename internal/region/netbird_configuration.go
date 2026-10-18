package region

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

var errNetBirdConfiguration = errors.New("original NetBird configuration is absent, changed or expired")

// ReadNetBirdConfiguration returns relay, session and datastore values in that
// fixed order. The caller clears these memory-only slices after synchronous use.
func ReadNetBirdConfiguration(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager) (values [3][]byte, err error) {
	defer func() {
		if err != nil {
			for i := range values {
				clear(values[i])
				values[i] = nil
			}
		}
	}()
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if ctx == nil || factory == nil || !ok || reader == nil || reader.factory != factory || factory.Region() != foundationHomeRegion || reader.scope.Cell != "GRU" || reader.scope.Environment != "production" {
		return values, errNetBirdConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := manager.Check(ctx); err != nil {
		return values, errors.Join(errNetBirdConfiguration, err)
	}
	original, err := reader.originalNetBirdState(ctx, resolver)
	if err != nil || original.record.NetBirdMaterial == nil {
		return values, errors.Join(errNetBirdConfiguration, err)
	}
	journal := *original.record.NetBirdMaterial
	ctx, cancelDeadline := context.WithDeadline(ctx, original.intent.expires)
	defer cancelDeadline()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reader.factory != factory || resolver.Footprint != reader {
			return errNetBirdConfiguration
		}
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil || tenancy != reader.tenancy || tenancy != journal.Authority.Context.TenancyID {
			return errors.Join(errNetBirdConfiguration, err)
		}
		if err := manager.Check(ctx); err != nil {
			return errors.Join(errNetBirdConfiguration, err)
		}
		current, err := reader.originalNetBirdState(ctx, resolver)
		if err != nil || current.record.NetBirdMaterial == nil || *current.record.NetBirdMaterial != journal || current.intent.grantDigest != original.intent.grantDigest ||
			current.target() != manager.CredentialTarget() || manager.StoreGeneration() != journal.Authority.Context.StoreGeneration {
			return errors.Join(errNetBirdConfiguration, err)
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return values, err
	}
	// Revalidation uses the captured base context, never its own wire guard.
	guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return guard() })
	management, err := vault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return values, errNetBirdConfiguration
	}
	management.SetRegion(foundationHomeRegion)
	factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	bundles, err := factory.SecretsContext(guarded)
	if err != nil {
		return values, errNetBirdConfiguration
	}
	values, err = readNetBirdConfigurationValues(guarded, &management, &bundles, journal)
	if err != nil {
		return values, err
	}
	return values, guard()
}

func readNetBirdConfigurationValues(ctx context.Context, management *vault.VaultsClient, bundles *secrets.SecretsClient, journal NetBirdMaterialJournal) (values [3][]byte, err error) {
	defer func() {
		if err != nil {
			for i := range values {
				clear(values[i])
				values[i] = nil
			}
		}
	}()
	if ctx == nil || management == nil || bundles == nil || !journal.Complete || journal.Authority.validate() != nil {
		return values, errNetBirdConfiguration
	}
	for i := range values {
		index := i + 1
		create := journal.Creates[index]
		if create.Name != journal.Authority.Names[index] || create.Version != 1 || !validFoundationDigest(create.ContentSHA256) {
			return values, errNetBirdConfiguration
		}
		values[i], err = readNetBirdMaterialSecret(ctx, management, bundles, journal.Authority, index, create)
		if err != nil || netBirdMaterialSHA(values[i]) != create.ContentSHA256 {
			return values, errNetBirdConfiguration
		}
		for _, octet := range values[i] {
			if octet < '!' || octet > '~' {
				return values, errNetBirdConfiguration
			}
		}
	}
	return values, nil
}
