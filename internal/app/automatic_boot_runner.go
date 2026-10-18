package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// RunAutomaticBootstrap discovers a signed controller role before configuration
// exists. Managed workers continue through their separate host setup unit.
func RunAutomaticBootstrap(ctx context.Context, args []string) error {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("managed-host-start requires root and accepts no arguments")
	}
	if accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity(); err == nil {
		return bootstrapstart.CheckIdentityRekeyPrestart(accepted)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect automatic controller install: %w", err)
	}
	if present, err := bootstrapstart.IdentityRekeyJournalPresent(); err != nil {
		return err
	} else if present {
		return bootstrapstart.ErrIdentityRekeyLocalPending
	}
	if err := controllerClockCheck(controllerBrokerClockProbe())(); err != nil {
		return fmt.Errorf("automatic controller startup NTP clock health: %w", err)
	}
	if err := region.DeliverOriginalFoundationPublic(ctx); err != nil {
		if _, pending := errors.AsType[*region.OriginalFoundationAdmissionPendingError](err); pending {
			if archiveErr := rootfoundation.EnsureOriginalSourceArchive(ctx); archiveErr != nil {
				return fmt.Errorf("archive original foundation source: %w", archiveErr)
			}
		}
		return fmt.Errorf("deliver original public foundation bundle: %w", err)
	}
	if err := bootstrapstart.InstallLaunchMaterial(ctx, bootstrapstart.NewIMDSClient(), time.Now().UTC()); errors.Is(err, bootstrapstart.ErrNotController) {
		return setupRuntimeWorker(ctx, os.Stdout)
	} else if err != nil {
		return fmt.Errorf("install automatic bootstrap launch material: %w", err)
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return err
	}
	grant, err := local.foundations.BootstrapMaterial(ctx, local.cell)
	if err != nil {
		return err
	}
	template, err := bootstrap.VerifyBoundStartupTemplate(ctx, local.factory, grant.FoundationGrantWire(), local.baked.Roots, local.anchor, time.Now().UTC())
	if err != nil {
		return err
	}
	slot, err := automaticControllerSlot(ctx, &local, grant, template)
	if err != nil {
		return err
	}
	home, err := local.anchor.FoundationScope()
	if err != nil {
		return err
	}
	homeFactory, err := local.factory.ForRegion(home.OCIRegion)
	if err != nil {
		return err
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return err
	}
	var authority bootstrap.DerivedStartupAuthority
	if slot == template.Template().SeedSlot {
		authority, err = automaticSeedAuthority(ctx, &local, grant, template)
	} else {
		authority, err = bootstrap.LoadDerivedStartupAuthority(ctx, template, &objects, slot, time.Now().UTC())
		if err == nil {
			authority, err = automaticPeerAuthority(ctx, &local, grant, template, authority)
		}
	}
	if err != nil {
		return err
	}
	if err := installAutomaticControllerFiles(ctx, authority); err != nil {
		return err
	}
	config, err := LoadConfig(filepath.Join(controllerConfigDirectory, controllerConfigFilename))
	if err != nil {
		return err
	}
	return bootstrapController(ctx, config)
}

func automaticSeedAuthority(ctx context.Context, local *automaticFoundation, grant region.VerifiedBootstrapMaterial,
	template bootstrap.VerifiedStartupTemplate,
) (bootstrap.DerivedStartupAuthority, error) {
	backend, err := rootfoundation.NewFounder(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	material, link, _, err := backend.InitialMaterial(ctx, call)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	install, err := newVerifiedAutomaticInstall(ctx, local, template, material, link)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	authority, err := install.bindAuthority(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	call, err = rootoci.RootCall(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := backend.PrepareSeedLedger(ctx, call, authority); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return authority, nil
}

func automaticVaultClients(factory *ociclient.Factory) (*ocivault.VaultsClient, *ocisecrets.SecretsClient, error) {
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, nil, err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, nil, err
	}
	return &management, &bundles, nil
}
