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
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
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
	parentCtx := ctx
	ctx, stopRuntime := context.WithCancelCause(parentCtx)
	defer stopRuntime(nil)
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
	initial, err := markers.ReadInitialFormation()
	if err != nil {
		return err
	}
	uid, gid, err := controllerServiceIdentity()
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
	ownhost := &managedRuntimeHost{reader: reader, accepted: accepted.Clone()}
	authority, err := newRootOCIAuthority(ctx, accepted, ownhost, selfupdate.NewLayout(selfUpdateRoot(cfg.Host.SelfUpdateRoot)), uid, gid)
	if err != nil {
		return err
	}
	defer authority.Close()
	backends, err := newManagedRootBackends(ctx, cfg, local, ownhost)
	if err != nil {
		return fmt.Errorf("construct admitted root backends: %w", err)
	}
	listener, err := rootoci.Listen(ctx, backends.service, authority.authorize, gid)
	if err != nil {
		return fmt.Errorf("listen for admitted root operations: %w", err)
	}
	defer listener.Close()
	if err := superviseControllerAdmissionWithAuthority(ctx, cfg, "bootstrap-admit-restart", "/proc/self/exe", authority); err != nil {
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
	ownhost.taskLoad = executor
	if err := executor.BindContainerMaterial(admitted, ownhost); err != nil {
		return err
	}
	if err := executor.SetRegistryResolver(ownhost.registryResolver); err != nil {
		return err
	}
	node, err := swarmruntime.StartAcceptedNode(ctx, reader, accepted, local.foundations, &vault, &bundles, executor, backends.service)
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
	stateful, err := newRootStatefulAuthorizer(cfg, authority, local.factory)
	if err != nil {
		return err
	}
	management, err := swarmruntime.StartManagementServer(ctx, node, reader, accepted, stateful)
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
	// The ordinary controller starts its broker only after this unit is ready.
	sourcesCtx, stopSources := context.WithCancel(authority.ctx)
	sourcesDone := make(chan struct{})
	go func() {
		defer close(sourcesDone)
		err := runManagedRuntimeRootSources(sourcesCtx, cfg, local.factory, ownhost, authority, backends)
		stopRuntime(fmt.Errorf("root runtime source authority ended: %w", err))
	}()
	defer func() { stopSources(); <-sourcesDone }()
	if err := node.Wait(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if ctx.Err() == nil {
		return errors.New("embedded regional runtime stopped unexpectedly")
	}
	if errors.Is(parentCtx.Err(), context.Canceled) {
		return nil
	}
	return context.Cause(ctx)
}
