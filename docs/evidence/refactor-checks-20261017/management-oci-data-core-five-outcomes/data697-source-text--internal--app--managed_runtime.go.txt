package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// RunManagedRuntime owns the root runtime independently of the NATS controller.
func RunManagedRuntime(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("managed-runtime-start accepts no arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("managed-runtime-start requires root")
	}
	if _, err := bootstrapstart.NewMarkerStore().ReadIdentity(); errors.Is(err, os.ErrNotExist) {
		return runRuntimeWorker(ctx, output)
	} else if err != nil {
		return fmt.Errorf("inspect accepted runtime role: %w", err)
	}
	if err := runRestoreControllerMaterial(ctx, nil, output); err != nil {
		return fmt.Errorf("restore accepted controller runtime credentials: %w", err)
	}
	cfg, err := LoadConfig("/etc/terrascale-orchestrator/controller.json")
	if err != nil {
		return fmt.Errorf("read installed controller runtime configuration: %w", err)
	}
	markers := bootstrapstart.NewMarkerStore()
	accepted, err := markers.ReadIdentity()
	if err != nil {
		return fmt.Errorf("read accepted runtime identity: %w", err)
	}
	before, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		return err
	}
	// The existing child performs current OCI, signed identity and live material admission.
	if err := superviseControllerAdmission(ctx, cfg, "bootstrap-admit-restart", "/proc/self/exe"); err != nil {
		return fmt.Errorf("admit root runtime: %w", err)
	}
	current, err := markers.ReadIdentity()
	if err != nil {
		return err
	}
	after, err := bootstrapstart.EncodeAcceptedIdentity(current)
	if err != nil || !bytes.Equal(before, after) {
		return errors.New("accepted runtime identity changed during live admission")
	}
	initial, err := markers.ReadInitialFormation()
	if err != nil {
		return err
	}
	uid, _, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	floor, err := bootstrapstart.NewServiceFounderSelectionFloorStore(uid)
	if err != nil {
		return err
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return err
	}
	reader, err := currentControllerFounderReader(ctx, local.baked, initial, floor)
	if err != nil {
		return err
	}
	vault, err := ocivault.NewVaultsClientWithConfigurationProvider(local.factory.Provider())
	if err != nil {
		return err
	}
	vault.SetRegion(local.factory.Region())
	local.factory.Configure(&vault.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return err
	}
	executor, err := swarmruntime.NewExecutor("/run/containerd/containerd.sock", "/var/lib/terrascale-orchestrator-host/swarm")
	if err != nil {
		return err
	}
	defer executor.Close()
	admitted, err := swarmruntime.ReadAcceptedManagerAdmission(ctx, reader, accepted)
	if err != nil {
		return err
	}
	ownhost := &managedRuntimeHost{reader: reader, accepted: accepted.Clone()}
	if err := executor.BindContainerMaterial(admitted, ownhost); err != nil {
		return err
	}
	if err := executor.SetRegistryResolver(ownhost.registryResolver); err != nil {
		return err
	}
	node, err := swarmruntime.StartAcceptedNode(ctx, reader, accepted, local.foundations, &vault, &bundles, executor)
	if err != nil {
		return err
	}
	ownhost.mu.Lock()
	ownhost.node = node
	ownhost.mu.Unlock()
	defer func() {
		ownhost.mu.Lock()
		ownhost.node = nil
		ownhost.mu.Unlock()
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = node.Stop(stopCtx)
	}()
	management, err := swarmruntime.StartManagementServer(ctx, node, reader, accepted)
	if err != nil {
		return err
	}
	defer management.Close()
	if err := setManagedRuntimeAvailability(ctx, node, admitted, api.NodeAvailabilityPause); err != nil {
		return err
	}
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("admitted regional runtime management is ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintln(output, "regional runtime management ready"); err != nil {
		return err
	}
	ownhostCtx, stopOwnhost := context.WithCancel(ctx)
	ownhostDone := make(chan struct{})
	go func() {
		defer close(ownhostDone)
		runManagedRuntimeOwnHost(ownhostCtx, cfg, reader, accepted, node, admitted, ownhost)
	}()
	defer func() { stopOwnhost(); <-ownhostDone }()
	if err := node.Wait(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if ctx.Err() == nil {
		return errors.New("embedded regional runtime stopped unexpectedly")
	}
	return nil
}
