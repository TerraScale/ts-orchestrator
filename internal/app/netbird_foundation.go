package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// RunNetBirdFoundation owns the dedicated manager before regional serving admission.
func RunNetBirdFoundation(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: ts-orch netbird foundation install|serve|backup|reconcile")
	}
	switch args[0] {
	case "install", "serve", "backup", "reconcile":
	default:
		return errors.New("usage: ts-orch netbird foundation install|serve|backup|reconcile")
	}
	if os.Geteuid() != 0 {
		return errors.New("NetBird foundation requires root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return fmt.Errorf("discover NetBird foundation: %w", err)
	}
	local.foundations, err = region.DiscoverCurrentFoundation(ctx, local.factory)
	if err != nil {
		return err
	}
	admission, err := region.AdmitNetBirdManager(ctx, local.factory, local.foundations, local.instanceID)
	if err != nil {
		return fmt.Errorf("admit dedicated NetBird manager: %w", err)
	}
	supervisor, err := netBirdFoundationSupervisor(ctx, local, admission)
	if err != nil {
		return err
	}
	switch args[0] {
	case "install":
		if err := supervisor.Install(ctx); err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, "NetBird foundation installed")
	case "serve":
		err = supervisor.Run(ctx)
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		}
	case "reconcile":
		if _, err = supervisor.Reconcile(ctx); err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, "NetBird foundation reconciled")
	case "backup":
		targets, targetErr := netBirdFoundationBackupTargets(ctx, local, admission)
		if targetErr != nil {
			return targetErr
		}
		record, backupErr := foundation.Backup(ctx, foundation.DataDirectory+"/data", foundation.ConfigPath, targets, supervisor.Pause)
		if backupErr != nil {
			return backupErr
		}
		_, err = fmt.Fprintf(output, "NetBird backup verified in GRU and SFO: %s (%d bytes)\n", record.Object, record.Bytes)
	}
	return err
}

func netBirdFoundationSupervisor(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager) (foundation.Supervisor, error) {
	if err := admission.Check(ctx); err != nil {
		return foundation.Supervisor{}, err
	}
	client, err := ocivault.NewVaultsClientWithConfigurationProvider(local.factory.Provider())
	if err != nil {
		return foundation.Supervisor{}, err
	}
	client.SetRegion(local.factory.Region())
	local.factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return foundation.Supervisor{}, err
	}
	return foundation.Supervisor{
		PrepareStore: func(ctx context.Context) error { return prepareNetBirdFoundationStore(ctx, local, admission) },
		StoreReady:   admission.MarkStoreReady,
		Account: func(ctx context.Context, quiesce func(context.Context) error) error {
			return reconcileNetBirdFoundationAccount(ctx, local, admission, quiesce)
		},
		Vault: foundation.BootstrapVault{
			StoreGeneration: admission.StoreGeneration(), Target: admission.VaultTarget(), Management: &client, Bundles: &bundles,
			Check: func() error {
				// Backup must resume on cancellation, with the manager's current admission still required.
				checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
				defer cancel()
				return admission.Check(checkCtx)
			},
		}}, nil
}

func netBirdFoundationBackupTargets(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager) ([2]foundation.BackupTarget, error) {
	var targets [2]foundation.BackupTarget
	for index, cell := range []string{"GRU", "SFO"} {
		destination, err := local.foundations.BackupDestination(ctx, cell)
		if err != nil {
			return targets, fmt.Errorf("resolve protected NetBird backup destination in %s: %w", cell, err)
		}
		factory, err := local.factory.ForRegion(destination.OCIRegion())
		if err != nil {
			return targets, err
		}
		client, err := factory.ObjectStorage()
		if err != nil {
			return targets, err
		}
		previous := client.Interceptor
		client.Interceptor = func(request *http.Request) error {
			if previous != nil {
				if err := previous(request); err != nil {
					return err
				}
			}
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				if err := admission.Check(request.Context()); err != nil {
					return err
				}
				if err := destination.Check(request.Context()); err != nil {
					return err
				}
			}
			return nil
		}
		ociclient.ConfigureRequestCancellation(&client.BaseClient)
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil || tenancy == "" {
			return targets, errors.New("NetBird backup requires authenticated OCI tenancy")
		}
		namespace, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{CompartmentId: new(tenancy)})
		if err != nil {
			return targets, err
		}
		if namespace.Value == nil || *namespace.Value == "" || strings.ContainsAny(*namespace.Value, "/\\\r\n") {
			return targets, errors.New("NetBird backup namespace is invalid")
		}
		vault := destination.VaultTarget()
		targets[index] = foundation.BackupTarget{Client: client, Region: destination.OCIRegion(), Namespace: *namespace.Value,
			Bucket: destination.BucketName(), BucketID: destination.BucketID(), CompartmentID: vault.CompartmentID, KMSKeyID: vault.KeyID}
	}
	return targets, nil
}

// The durable source authorizes genesis once; backup absence never authorizes a fresh identity.
func prepareNetBirdFoundationStore(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager) error {
	resolver, err := region.DiscoverCurrentFoundation(ctx, local.factory)
	if err != nil {
		return err
	}
	current, err := region.AdmitNetBirdManager(ctx, local.factory, resolver, local.instanceID)
	if err != nil {
		return err
	}
	if current.StoreGeneration() != admission.StoreGeneration() || current.VaultTarget() != admission.VaultTarget() {
		return errors.New("NetBird manager store authority changed")
	}
	admission = current
	local.foundations = resolver
	return foundation.PrepareStore(ctx, foundation.DataDirectory, admission, func(ctx context.Context) ([2]foundation.BackupTarget, error) {
		return netBirdFoundationBackupTargets(ctx, local, admission)
	})
}

// Supervisor holds the same process lock used by bootstrap and snapshots throughout this call.
func reconcileNetBirdFoundationAccount(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager, quiesce func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return admission.Check(ctx)
	}
	if err := check(); err != nil {
		return err
	}
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return err
	}
	token, err := vaultsecret.Read(ctx, bundles, admission.VaultTarget().VaultID, foundation.ManagementSecretName)
	if err != nil {
		return err
	}
	api, err := manager.NewFencedAPI("http://127.0.0.1:18081", token, check)
	if err != nil {
		return err
	}
	defer api.Close()
	if err := manager.RestrictBaseline(ctx, api); err != nil {
		return err
	}
	footprint, err := local.foundations.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return err
	}
	var pending []error
	for _, intent := range footprint.Regions {
		cell, ok := intent.Plan["cell"].(string)
		if !ok {
			return errors.New("NetBird enrollment footprint has no canonical cell")
		}
		if err := reconcileNetBirdRegionEnrollment(ctx, local, admission, cell, quiesce, api); err != nil {
			pending = append(pending, fmt.Errorf("NetBird %s enrollment pending: %w", cell, err))
		}
	}
	report, syncErr := manager.Sync(ctx, api, manager.GRU(), true)
	for _, change := range report.Changes {
		log.Printf("NetBird account applied: %s", change)
	}
	// The sole host owner preserves independent hygiene even when an account shape refuses sync.
	report, pruneErr := manager.Prune(ctx, api, manager.GRU(), manager.PruneOptions{}, true)
	for _, change := range report.Changes {
		log.Printf("NetBird peer hygiene applied: %s", change)
	}
	for _, failure := range append(pending, syncErr, pruneErr) {
		if failure != nil {
			log.Printf("NetBird account reconciliation deferred: %v", failure)
		}
	}
	return nil
}

func reconcileNetBirdRegionEnrollment(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager, cell string, quiesce func(context.Context) error, api *manager.API) error {
	record, err := local.foundations.Resolve(ctx, cell)
	if err != nil {
		return err
	}
	target, err := record.VaultTarget()
	if err != nil {
		return err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := admission.Check(ctx); err != nil {
			return err
		}
		resolver, err := region.DiscoverCurrentFoundation(ctx, local.factory)
		if err != nil {
			return err
		}
		current, err := resolver.Resolve(ctx, cell)
		if err != nil {
			return err
		}
		currentTarget, err := current.VaultTarget()
		if err != nil || current.OperationID != record.OperationID || current.Generation != record.Generation || currentTarget != target {
			return errors.New("NetBird enrollment regional foundation changed")
		}
		return nil
	}
	factory, err := local.factory.ForRegion(record.OCIRegion)
	if err != nil {
		return err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return err
	}
	management.SetRegion(record.OCIRegion)
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return err
	}
	desired := manager.GRU()
	desired.ServersGroup = strings.ToLower(cell) + "-servers"
	desired.SetupKeyName = desired.ServersGroup
	_, err = manager.ReconcileServerEnrollment(ctx, api, desired, foundation.DataDirectory+"/data/terrascale-enrollment/"+strings.ToLower(cell), manager.EnrollmentVault{
		Target: target, Management: &management, Bundles: bundles, Name: strings.ToLower(cell) + "-1-netbird-setup-key",
	}, manager.EnrollmentAuthority{Check: check, Quiesce: quiesce})
	return err
}
