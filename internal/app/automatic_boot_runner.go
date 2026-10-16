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
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const automaticSourceDirectory = "/var/lib/terrascale-orchestrator-bootstrap/automatic"

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
	founder, err := bootstrapstart.VerifySourceFounder(ctx, local.factory, template)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	homeAuthority, err := region.NewHomeIAMAuthority(ctx, founder, local.foundations)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	actor, err := region.NewSourceFounder(ctx, local.foundations, homeAuthority)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	factory, guarded, err := founder.GuardedFactory(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	home, err := local.anchor.FoundationScope()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	homeFactory, err := factory.ForRegion(home.OCIRegion)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	escrowManagement, escrowBundles, err := automaticVaultClients(homeFactory)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	management, bundles, err := automaticVaultClients(factory)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := os.MkdirAll(automaticSourceDirectory, 0o700); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	source, err := materialsource.ResolveColdStartMaterial(guarded, grant, actor, &objects, escrowManagement, escrowBundles,
		filepath.Join(automaticSourceDirectory, "regional"), time.Now().UTC())
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	target, err := automaticVaultTarget(guarded, *local, grant)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if _, err := source.Provision(guarded, target, management, bundles, time.Now().UTC()); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	material, err := source.InstallMaterial(guarded)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	var linkProof bootstrap.VerifiedStartupLink
	linkDirectory := filepath.Join(automaticSourceDirectory, "link")
	if grant.Config().Cell == natscell.LinkHome {
		link, err := materialsource.ResolveLinkSource(guarded, source, source, nil, &objects, escrowManagement, escrowBundles,
			linkDirectory, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		target, err := automaticVaultTarget(guarded, *local, grant)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		if _, err := link.Provision(guarded, target, management, bundles, time.Now().UTC()); err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		linkProof, err = link.StartupLink(guarded, template, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
	} else {
		regional, err := bootstrap.LoadRegionalSource(guarded, template, &objects, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		homeTemplate, err := template.ForCell(guarded, oci.RegionGRU, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		homeInventory, err := bootstrap.LoadRegionalSource(guarded, homeTemplate, &objects, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		recipient, err := bootstrap.VerifyLinkRecipient(guarded, regional, homeInventory, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		link, err := materialsource.ResolveRegionalLink(guarded, material, recipient, &objects, bundles, linkDirectory, time.Now().UTC())
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		linkProof = link.Proof()
	}
	install, err := newVerifiedAutomaticInstall(guarded, local, template, material, linkProof)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	authority, err := install.bindAuthority(guarded)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if _, err := source.PrepareSeedLedger(guarded, local.baked.Roots, local.anchor, authority, actor.Founder()); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if _, err := source.InstallMaterial(guarded); err != nil {
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
