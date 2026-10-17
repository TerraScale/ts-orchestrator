package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func netBirdManagerAPI(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager) (*manager.API, error) {
	if err := admission.Check(ctx); err != nil {
		return nil, err
	}
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return nil, err
	}
	token, err := vaultsecret.Read(ctx, bundles, admission.VaultTarget().VaultID, foundation.ManagementSecretName)
	if err != nil {
		return nil, err
	}
	return manager.NewFencedAPI("http://127.0.0.1:18081", token, func() error { return admission.Check(ctx) })
}

func bootstrapNetBirdManagerAccount(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager, quiesce func(context.Context) error) error {
	ctx, cancel := context.WithDeadline(ctx, admission.ExpiresAt())
	defer cancel()
	api, err := netBirdManagerAPI(ctx, local, admission)
	if err != nil {
		return err
	}
	defer api.Close()
	if err := manager.RestrictBaseline(ctx, api); err != nil {
		return err
	}
	if err := manager.BootstrapManagerAccount(ctx, api); err != nil {
		return err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(local.factory.Provider())
	if err != nil {
		return err
	}
	management.SetRegion(local.factory.Region())
	local.factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return err
	}
	_, err = manager.ReconcileManagerEnrollment(ctx, api, foundation.DataDirectory+"/data/terrascale-enrollment/manager", manager.EnrollmentVault{
		Target: admission.VaultTarget(), Management: &management, Bundles: bundles, Name: manager.ManagerSetupKeySecret,
	}, manager.EnrollmentAuthority{Check: func() error { return admission.Check(ctx) }, Quiesce: quiesce})
	if err != nil {
		return err
	}
	// Regional hosts need their signed enrollment delivery before any broker can be reached.
	footprint, err := local.foundations.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return err
	}
	for _, intent := range footprint.Regions {
		cell, ok := intent.Plan["cell"].(string)
		if !ok {
			return errors.New("NetBird enrollment footprint has no canonical cell")
		}
		if err := reconcileNetBirdRegionEnrollment(ctx, local, admission, cell, quiesce, api); err != nil {
			log.Printf("NetBird %s enrollment pending: %v", cell, err)
			continue
		}
		check := func() error {
			if err := admission.Check(ctx); err != nil {
				return err
			}
			current, err := region.DiscoverCurrentFoundation(ctx, local.factory)
			if err != nil {
				return err
			}
			footprint, err := current.Footprint.AuthorizedRegions(ctx)
			if err != nil {
				return err
			}
			for _, authorized := range footprint.Regions {
				if authorized.Plan["cell"] == cell {
					return admission.Check(ctx)
				}
			}
			return errors.New("NetBird manager broker access region left the current signed footprint")
		}
		if err := manager.BootstrapManagerBrokerAccess(ctx, api, strings.ToLower(cell), check); err != nil {
			return err
		}
	}
	return nil
}

func readNetBirdManagerSetupKey(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager, cfg netbird.Config) ([]byte, error) {
	ctx, cancel := context.WithDeadline(ctx, admission.ExpiresAt())
	defer cancel()
	if cfg.ManagementURL != netbird.DefaultManagementURL || cfg.Region != local.factory.Region() {
		return nil, errors.New("NetBird manager client differs from its admitted regional management endpoint")
	}
	if err := admission.Check(ctx); err != nil {
		return nil, err
	}
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return nil, err
	}
	current, err := vaultsecret.ReadVersioned(ctx, bundles, admission.VaultTarget().VaultID, manager.ManagerSetupKeySecret)
	if err != nil {
		return nil, err
	}
	key, err := netbird.ReadSetupKey(ctx, cfg.Region, current.SecretID)
	if err != nil {
		return nil, err
	}
	latest, err := vaultsecret.ReadVersioned(ctx, bundles, admission.VaultTarget().VaultID, manager.ManagerSetupKeySecret)
	if err != nil || latest != current || !bytes.Equal(key, []byte(current.Value)) {
		clear(key)
		return nil, errors.New("NetBird manager enrollment CURRENT changed during delivery")
	}
	if err := admission.Check(ctx); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func connectNetBirdManagerMesh(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager) error {
	ctx, expire := context.WithDeadline(ctx, admission.ExpiresAt())
	defer expire()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := admission.Check(ctx); err != nil {
		return err
	}
	pin, cfg, err := client.ReadBootstrapConfig(ctx, netbird.PublicConfigPath, true)
	if err != nil {
		return err
	}
	if cfg.ManagementURL != netbird.DefaultManagementURL || cfg.Region != local.factory.Region() {
		return errors.New("NetBird manager image enrollment config differs from its admitted region")
	}
	archive, err := pin.Archive(runtime.GOARCH)
	if err != nil {
		return err
	}
	const binary = "/usr/local/bin/netbird"
	const fallback = "/usr/local/lib/terrascale-orchestrator/netbird-client"
	if err := client.VerifyBinary(fallback, archive.BinarySHA256, runtime.GOARCH); err != nil {
		return errors.New("NetBird manager image has no verified pinned client")
	}
	reader := func(ctx context.Context, cfg netbird.Config) ([]byte, error) {
		return readNetBirdManagerSetupKey(ctx, local, admission, cfg)
	}
	if err := enrollNetBirdBootstrap(ctx, netbird.PublicConfigPath, io.Discard, netbirdBootstrapRuntime{
		binary: binary, fallback: fallback, status: client.ManagedStatus, defaults: client.ReadBootstrapConfig,
		install: func(ctx context.Context, pin client.Pin, cfg netbird.Config, options client.ManagedOptions) (client.ManagedResult, error) {
			if err := admission.Check(ctx); err != nil {
				return client.ManagedResult{}, err
			}
			installed, err := client.InstallManaged(ctx, pin, cfg, options, reader)
			if err != nil {
				return installed, err
			}
			return installed, admission.Check(ctx)
		}, confirm: func(ctx context.Context, transaction string) error {
			if err := admission.Check(ctx); err != nil {
				return err
			}
			if err := client.ConfirmManaged(ctx, transaction); err != nil {
				return err
			}
			return admission.Check(ctx)
		},
		enroll: func(ctx context.Context, _ netbird.Config) error {
			if err := client.VerifyBinary(binary, archive.BinarySHA256, runtime.GOARCH); err != nil {
				return errors.New("NetBird manager installed client differs from its qualified image pin")
			}
			if err := admission.Check(ctx); err != nil {
				return err
			}
			if err := exec.CommandContext(ctx, "systemctl", "start", "netbird.service").Run(); err != nil {
				return errors.New("NetBird manager client service could not start")
			}
			if err := admission.Check(ctx); err != nil {
				return err
			}
			return client.EnrollBootstrap(ctx, netbird.PublicConfigPath, reader)
		},
	}); err != nil {
		return err
	}
	status, err := netbird.Status(ctx)
	if err != nil || status.Version != pin.Version || status.State != "Connected" || !status.Management.Connected || !status.Signal.Connected || status.Management.URL != netbird.DefaultManagementURL {
		return errors.New("NetBird manager pinned client has no verified management and signal connection")
	}
	address, err := netip.ParsePrefix(status.IP)
	if err != nil || !netip.MustParsePrefix(networkplan.Mesh).Contains(address.Addr()) {
		return errors.New("NetBird manager client has no admitted mesh address")
	}
	api, err := netBirdManagerAPI(ctx, local, admission)
	if err != nil {
		return err
	}
	defer api.Close()
	inventory, err := manager.ReadInventory(ctx, api)
	if err != nil {
		return err
	}
	matched := 0
	for _, peer := range inventory.Peers {
		if peer.IP != address.Addr().String() {
			continue
		}
		matched++
		if !peer.Connected || peer.Version != pin.Version || !slices.Contains(peer.Groups, manager.ManagerGroup) {
			return errors.New("NetBird manager peer has no dedicated enrollment proof")
		}
		for _, group := range peer.Groups {
			if group != "All" && group != manager.ManagerGroup {
				return errors.New("NetBird manager peer belongs to an unauthorized group: " + strings.TrimSpace(group))
			}
		}
	}
	if matched != 1 {
		return errors.New("NetBird manager peer identity is absent or ambiguous")
	}
	return admission.Check(ctx)
}
