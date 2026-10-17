package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"
)

type functionWorkerRelease struct {
	Architecture string
	Bundle       release.ContainerBundle
	Floor        release.SequenceFloor
}

// Dependencies come from the admitted regional manager and current role channel.
// Function/task labels select records; neither labels nor a requested image grant authority.
type functionControllerConfig struct {
	Authority         *authority.Runtime
	JS                jetstream.JetStream
	Startup           bootstrap.DerivedStartupAuthority
	Material          functionmaterial.Controller
	Retirement        functionmaterial.RetirementClient
	Client            api.ControlClient
	Worker            func(context.Context, release.VerifiedFunction) (functionWorkerRelease, error)
	Evidence          func(context.Context, string) (io.ReadCloser, error)
	Probe             func(context.Context, *api.Task) error
	Channel           *channelSource
	Roots             *rootRegistry
	Factory           *ociclient.Factory
	Cell, Environment string
}

type functionController struct{ config functionControllerConfig }

type functionIntentSource struct {
	reader    functionmaterial.Reader
	js        jetstream.JetStream
	authority *authority.Runtime
	epoch     uint64
	roots     *rootRegistry
	rootHead  string
}

func (source functionIntentSource) CurrentFunction(ctx context.Context, tenant, function string) (release.VerifiedFunction, error) {
	if source.authority == nil || source.js == nil || source.roots == nil || source.roots.reply("").Head != source.rootHead {
		return release.VerifiedFunction{}, errors.New("function roots changed during current intent observation")
	}
	if err := source.authority.Guard(ctx, source.epoch); err != nil {
		return release.VerifiedFunction{}, err
	}
	proof, err := source.reader.CurrentFunction(ctx, tenant, function)
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, proof.ExpiresAt())
	defer cancel()
	if err := source.authority.Guard(ctx, source.epoch); err != nil {
		return release.VerifiedFunction{}, err
	}
	if err := rootTrustHeadCurrent(ctx, source.js, source.roots, source.rootHead); err != nil {
		return release.VerifiedFunction{}, err
	}
	state := source.authority.Current()
	if !state.CanMutate() || state.Epoch != source.epoch {
		return release.VerifiedFunction{}, authority.ErrFenced
	}
	if source.roots.reply("").Head != source.rootHead || !proof.Valid() {
		return release.VerifiedFunction{}, errors.New("function authority changed during current intent observation")
	}
	if err := ctx.Err(); err != nil {
		return release.VerifiedFunction{}, err
	}
	return proof, nil
}

func startFunctionController(ctx context.Context, config functionControllerConfig) (host.FunctionMaterialProvider, func(), error) {
	if config.Authority == nil || config.JS == nil || !config.Startup.IsVerified() || config.Client == nil || config.Roots == nil || config.Factory == nil || config.Worker == nil || config.Evidence == nil || config.Probe == nil || config.Retirement == nil ||
		config.Channel == nil || config.Material.Reader.Roots == nil || config.Material.Reader.Artifacts == nil ||
		config.Material.Conn == nil || config.Material.Issuer == nil || config.Material.Vault == nil || config.Material.Versions == nil ||
		config.Material.Reader.Bundles == nil || config.Material.Reader.Accounts == nil || config.Material.Reader.VaultID == "" || config.Material.Target.VaultID != config.Material.Reader.VaultID ||
		!release.ValidRegion(strings.ToUpper(config.Cell)) || !release.ValidEnvironment(config.Environment) {
		return nil, nil, errors.New("function controller requires current regional authority, release source, artifacts and manager")
	}
	if err := config.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	config.Material.Authority = config.Authority
	config.Material.Reader.Authority = config.Authority
	controller := functionController{config: config}
	stopSource := ownedLoop(ctx, "function publication source", controller.runSource)
	stopReconcile := ownedLoop(ctx, "function controller", controller.run)
	return controller.material, func() { stopSource(); stopReconcile() }, nil
}

func (controller functionController) runSource(ctx context.Context) error {
	ticker := time.NewTicker(releasechannel.PinRefreshInterval)
	defer ticker.Stop()
	for {
		state := controller.config.Authority.Current()
		if state.CanMutate() {
			if err := controller.ingest(ctx, state.Epoch); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "function publication source unavailable", "error", err)
			}
			if err := controller.retireMaterial(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "function material retirement pending", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (controller functionController) run(ctx context.Context) error {
	ticker := time.NewTicker(releasechannel.PinRefreshInterval)
	defer ticker.Stop()
	for {
		state := controller.config.Authority.Current()
		if state.CanMutate() {
			if err := controller.reconcile(ctx, state.Epoch); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "function reconciliation pending", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (controller functionController) ingest(ctx context.Context, epoch uint64) error {
	location, err := controller.config.Channel.get(ctx)
	if err != nil {
		return err
	}
	channel, found, err := releasechannel.ReadFunctionChannel(ctx, location)
	if err != nil || !found {
		return err
	}
	var failures []error
	for _, entry := range channel.Entries {
		if err := controller.ingestRelease(ctx, epoch, location, entry); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (controller functionController) ingestRelease(ctx context.Context, epoch uint64, location releasechannel.Location, entry releasechannel.FunctionRelease) error {
	if controller.config.Roots == nil {
		return errors.New("function publication requires current regional roots")
	}
	rootHead := controller.config.Roots.reply("").Head
	claim, err := entry.Claim()
	if err != nil {
		return err
	}
	if claim.Cell != strings.ToUpper(controller.config.Cell) || claim.Environment != controller.config.Environment {
		return release.ErrExpectationMismatch
	}
	minimum, expected := uint64(1), uint64(0)
	var previous authority.FunctionIntent
	current, err := controller.config.Authority.ReadFunctionIntent(ctx, claim.TenantID, claim.FunctionID)
	if err == nil {
		previous, err = authority.DecodeFunctionIntent(current)
		if err != nil {
			return err
		}
		minimum, expected = previous.Claim.Sequence, current.Sequence
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	module, err := releasechannel.ReadFunctionModule(ctx, location, claim.Digest)
	if err != nil {
		return err
	}
	proof, err := release.VerifyFunctionCurrent(entry.Envelope, entry.Delegation, module, controller.config.Material.Reader.Roots(), release.FunctionExpectation{
		Environment: controller.config.Environment, Cell: strings.ToUpper(controller.config.Cell), TenantID: claim.TenantID,
		FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: minimum,
	}, time.Now())
	if err != nil {
		return err
	}
	if previous.EnvelopeSHA256 == proof.EnvelopeSHA256() {
		if !bytes.Equal(previous.Delegation, proof.Delegation()) {
			return authority.ErrConflict
		}
		return nil
	}
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	// Publishing metadata before the intent invalidates stale garbage collection snapshots.
	stored, err := controller.config.Material.Reader.Artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader(proof.Module()))
	if err != nil {
		return err
	}
	if stored == nil || stored.Size != uint64(proof.Claim().Bytes) || stored.Opts != nil && stored.Opts.Link != nil {
		return errors.New("function artifact readback differs from verified module")
	}
	// Root adoption and its leader's KV writes wait until this intent CAS completes.
	controller.config.Roots.adopting.Lock()
	defer controller.config.Roots.adopting.Unlock()
	if controller.config.Roots.reply("").Head != rootHead {
		return errors.New("function roots changed during artifact publication")
	}
	proof, err = release.VerifyFunctionCurrent(entry.Envelope, entry.Delegation, module, controller.config.Roots.current(), release.FunctionExpectation{
		Environment: controller.config.Environment, Cell: strings.ToUpper(controller.config.Cell), TenantID: claim.TenantID,
		FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: minimum,
	}, time.Now())
	if err != nil {
		return err
	}
	_, err = controller.config.Authority.CommitFunctionIntent(ctx, epoch, entityid.Derive("function-publication", proof.EnvelopeSHA256()), expected, proof)
	return err
}

func (controller functionController) reconcile(ctx context.Context, epoch uint64) error {
	entries, err := controller.config.Authority.ListFunctionIntents(ctx)
	if err != nil {
		return err
	}
	var group errgroup.Group
	group.SetLimit(4)
	failures := make([]error, len(entries))
	for index, entry := range entries {
		group.Go(func() error {
			intent, err := authority.DecodeFunctionIntent(entry)
			if err != nil {
				failures[index] = err
				return nil
			}
			failures[index] = controller.apply(ctx, epoch, intent.Claim.TenantID, intent.Claim.FunctionID)
			return nil
		})
	}
	_ = group.Wait()
	return errors.Join(failures...)
}

func (controller functionController) apply(ctx context.Context, epoch uint64, tenant, function string) error {
	proof, err := controller.config.Material.Reader.CurrentFunction(ctx, tenant, function)
	if err != nil {
		return err
	}
	if proof.Claim().Cell != strings.ToUpper(controller.config.Cell) || proof.Claim().Environment != controller.config.Environment {
		return release.ErrExpectationMismatch
	}
	worker, err := controller.config.Worker(ctx, proof)
	if err != nil {
		return err
	}
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	intent := functionServiceTarget(proof, worker.Architecture)
	allocations, err := currentContainerAllocations(ctx, controller.config.Factory, worker.Bundle, controller.config.Material.Reader.Roots(),
		release.ContainerTarget{Cell: proof.Claim().Cell, Environment: proof.Claim().Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: worker.Architecture})
	if err != nil {
		return err
	}
	source := functionIntentSource{reader: controller.config.Material.Reader, js: controller.config.JS, authority: controller.config.Authority, epoch: epoch,
		roots: controller.config.Roots, rootHead: controller.config.Roots.reply("").Head}
	_, err = swarmruntime.ApplyFunctionService(ctx, controller.config.Client, intent, source,
		worker.Bundle, controller.config.Material.Reader.Roots(), worker.Floor, controller.config.Evidence, controller.config.Probe, allocations)
	return err
}

func functionServiceTarget(proof release.VerifiedFunction, architecture string) swarmruntime.FunctionServiceIntent {
	claim := proof.Claim()
	return swarmruntime.FunctionServiceIntent{TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Region: catalog.OCIRegion(claim.Cell), Environment: claim.Environment, Architecture: architecture}
}

func (controller functionController) material(ctx context.Context, registration host.Registration, request host.FunctionMaterialBinding) (host.FunctionMaterialFiles, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if controller.config.Authority == nil || controller.config.JS == nil || controller.config.Roots == nil {
		return host.FunctionMaterialFiles{}, functionmaterial.ErrMaterial
	}
	ctx, cancelStartup := context.WithDeadline(ctx, controller.config.Startup.ExpiresAt())
	defer cancelStartup()
	epoch, rootHead := controller.config.Authority.Current().Epoch, controller.config.Roots.reply("").Head
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return host.FunctionMaterialFiles{}, err
	}
	binding := functionmaterial.Binding{TaskID: request.TaskID, ServiceID: request.ServiceID, NodeID: request.NodeID,
		InstanceID: request.InstanceID, Region: request.Region, HostID: request.HostID, Fingerprint: request.Fingerprint}
	proof, err := controller.recipient(ctx, registration, binding)
	if err != nil {
		return host.FunctionMaterialFiles{}, err
	}
	ctx, cancelFunction := context.WithDeadline(ctx, proof.ExpiresAt())
	defer cancelFunction()
	material := controller.config.Material
	material.AuthorizeRecipient = func(ctx context.Context, selected functionmaterial.Binding) error {
		_, err := controller.recipient(ctx, registration, selected)
		return err
	}
	delivery, err := material.Prepare(ctx, proof.Claim().TenantID, proof.Claim().FunctionID, binding)
	if err != nil {
		return host.FunctionMaterialFiles{}, err
	}
	if !delivery.Valid() || delivery.Binding() != binding || delivery.Function().EnvelopeSHA256() != proof.EnvelopeSHA256() {
		return host.FunctionMaterialFiles{}, functionmaterial.ErrMaterial
	}
	ctx, cancelDelivery := context.WithDeadline(ctx, delivery.ExpiresAt())
	defer cancelDelivery()
	ctx, cancelCredentials := context.WithDeadline(ctx, delivery.CredentialExpiresAt())
	defer cancelCredentials()
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return host.FunctionMaterialFiles{}, err
	}
	if err := rootTrustHeadCurrent(ctx, controller.config.JS, controller.config.Roots, rootHead); err != nil {
		return host.FunctionMaterialFiles{}, err
	}
	state := controller.config.Authority.Current()
	if !state.CanMutate() || state.Epoch != epoch || controller.config.Roots.reply("").Head != rootHead {
		return host.FunctionMaterialFiles{}, errors.New("function roots changed during material preparation")
	}
	if !proof.Valid() || !delivery.Valid() || ctx.Err() != nil {
		return host.FunctionMaterialFiles{}, functionmaterial.ErrMaterial
	}
	return host.FunctionMaterialFiles{Files: delivery.Files(), ExpiresAt: delivery.ExpiresAt(), CredentialExpiresAt: delivery.CredentialExpiresAt()}, nil
}

func (controller functionController) recipient(ctx context.Context, registration host.Registration, binding functionmaterial.Binding) (release.VerifiedFunction, error) {
	fail := func() (release.VerifiedFunction, error) {
		return release.VerifiedFunction{}, errors.New("function material recipient is not the current assigned admitted host")
	}
	if err := controller.config.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return release.VerifiedFunction{}, err
	}
	ctx, cancelStartup := context.WithDeadline(ctx, controller.config.Startup.ExpiresAt())
	defer cancelStartup()
	if !entityid.Valid(registration.ID) || binding.HostID != registration.ID || registration.Cell != strings.ToLower(controller.config.Cell) || registration.Environment != controller.config.Environment {
		return fail()
	}
	if controller.config.Roots == nil {
		return fail()
	}
	rootHead := controller.config.Roots.reply("").Head
	epoch := controller.config.Authority.Current().Epoch
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return release.VerifiedFunction{}, err
	}
	taskResponse, err := controller.config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	if taskResponse == nil {
		return fail()
	}
	task := taskResponse.Task
	if task == nil || task.ID != binding.TaskID || task.ServiceID != binding.ServiceID || task.NodeID != binding.NodeID || task.DesiredState != api.TaskStateRunning {
		return fail()
	}
	serviceResponse, err := controller.config.Client.GetService(ctx, &api.GetServiceRequest{ServiceID: binding.ServiceID})
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	if serviceResponse == nil {
		return fail()
	}
	service := serviceResponse.Service
	if service == nil || service.ID != binding.ServiceID {
		return fail()
	}
	labels := service.Spec.Annotations.Labels
	source := functionIntentSource{reader: controller.config.Material.Reader, js: controller.config.JS, authority: controller.config.Authority, epoch: epoch,
		roots: controller.config.Roots, rootHead: rootHead}
	proof, err := source.CurrentFunction(ctx, labels[swarmruntime.LabelFunctionTenant], labels[swarmruntime.LabelFunctionID])
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	ctx, cancelFunction := context.WithDeadline(ctx, proof.ExpiresAt())
	defer cancelFunction()
	claim := proof.Claim()
	if claim.Cell != strings.ToUpper(controller.config.Cell) || claim.Environment != controller.config.Environment || catalog.OCIRegion(claim.Cell) != binding.Region {
		return fail()
	}
	nodeResponse, err := controller.config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	if nodeResponse == nil {
		return fail()
	}
	admittedNode := func(node *api.Node) bool {
		return node != nil && node.Description != nil && node.Description.Platform != nil && node.ID == task.NodeID &&
			node.Spec.Membership == api.NodeMembershipAccepted && node.Status.State == api.NodeStatus_READY &&
			node.Spec.Availability == api.NodeAvailabilityActive && node.Spec.Annotations.Name == registration.ID &&
			node.Spec.Annotations.Labels[swarmruntime.LabelRegion] == binding.Region &&
			node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] == "wasm" &&
			node.Spec.Annotations.Labels[swarmruntime.LabelExecutionScope] == "tenant" &&
			node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] == binding.InstanceID
	}
	node := nodeResponse.Node
	if !admittedNode(node) {
		return fail()
	}
	intent := functionServiceTarget(proof, node.Description.Platform.Architecture)
	bundle, err := intent.WorkerBundleForTask(ctx, controller.config.Client, task)
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	// Issued material is capped at function expiry, so worker qualification must cover it too.
	target := release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: intent.Architecture}
	allocations, err := currentContainerAllocations(ctx, controller.config.Factory, bundle, controller.config.Material.Reader.Roots(), target)
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	verifiedWorker, err := release.VerifyContainerCurrent(ctx, bundle, controller.config.Material.Reader.Roots(),
		target, time.Now(), proof.ExpiresAt(), controller.config.Evidence, allocations)
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	ctx, cancelWorker := context.WithDeadline(ctx, verifiedWorker.ExpiresAt())
	defer cancelWorker()
	if err := swarmruntime.VerifyFunctionMaterialTask(ctx, controller.config.Client, task, intent, source, verifiedWorker); err != nil {
		return release.VerifiedFunction{}, err
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil || fingerprint != binding.Fingerprint {
		return fail()
	}
	nodeResponse, err = controller.config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return release.VerifiedFunction{}, err
	}
	if nodeResponse == nil || !admittedNode(nodeResponse.Node) || nodeResponse.Node.Description.Platform.Architecture != intent.Architecture {
		return fail()
	}
	if err := ctx.Err(); err != nil {
		return release.VerifiedFunction{}, fmt.Errorf("verify current function recipient: %w", err)
	}
	if err := controller.config.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return release.VerifiedFunction{}, err
	}
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return release.VerifiedFunction{}, err
	}
	if err := rootTrustHeadCurrent(ctx, controller.config.JS, controller.config.Roots, rootHead); err != nil {
		return release.VerifiedFunction{}, err
	}
	state := controller.config.Authority.Current()
	if !state.CanMutate() || state.Epoch != epoch || controller.config.Roots.reply("").Head != rootHead {
		return fail()
	}
	if !proof.Valid() || !verifiedWorker.Valid(time.Now().UTC()) || ctx.Err() != nil {
		return fail()
	}
	return proof, nil
}
