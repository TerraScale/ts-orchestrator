//go:build linux

package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type rootMaterialAdmission struct {
	ownhost *managedRuntimeHost
	factory *ociclient.Factory
}

func newRootMaterialAdmission(source *managedRuntimeHost, factory *ociclient.Factory) (*rootMaterialAdmission, error) {
	if os.Geteuid() != 0 || source == nil || source.reader == nil || factory == nil {
		return nil, rootoci.ErrUnauthorized
	}
	return &rootMaterialAdmission{ownhost: source, factory: factory}, nil
}

func (producer *rootMaterialAdmission) container(ctx context.Context, call rootoci.Call, evidence host.ContainerMaterialEvidence) (containermaterial.Admission, error) {
	// Unverified envelope dates can only shorten the outer operation cap.
	deadline := earlier(call.Deadline(), evidence.Deadline())
	if ctx == nil || !time.Now().Before(deadline) {
		return containermaterial.Admission{}, containermaterial.ErrPending
	}
	original := ctx
	ctx, stop := context.WithDeadline(ctx, deadline)
	context.AfterFunc(original, stop)
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	controller, sources, err := producer.readers(ctx, call)
	if err != nil {
		return containermaterial.Admission{}, err
	}
	ctx = controller.config.credentialContext
	session, err := controller.config.Registrations.AdmitContainerMaterialSession(ctx, evidence)
	if err != nil {
		return containermaterial.Admission{}, err
	}
	readCtx, cancel := context.WithDeadline(ctx, session.Deadline())
	context.AfterFunc(ctx, cancel)
	if err := producer.lease(readCtx, call, controller, session.Binding().TaskID); err != nil {
		return containermaterial.Admission{}, err
	}
	registration, err := session.Registration()
	if err != nil {
		return containermaterial.Admission{}, err
	}
	selected, err := controller.recipient(readCtx, registration, session.Binding())
	if err != nil {
		return containermaterial.Admission{}, err
	}
	sources.Lease = controller.config.ReadLease
	sources.ContainerProfiles = rootMaterialProfiles{controller: controller, selected: selected}
	// The outer operation context stays alive after this resolver returns.
	admitted, err := containermaterial.AdmitMaterialTask(readCtx, sources, materialTask(selected), session)
	if err != nil {
		return containermaterial.Admission{}, err
	}
	if err := call.Guard(readCtx); err != nil {
		return containermaterial.Admission{}, err
	}
	return admitted, nil
}

func (producer *rootMaterialAdmission) generation(ctx context.Context, call rootoci.Call, taskID string) (containermaterial.GenerationAdmission, error) {
	if ctx == nil || !time.Now().Before(call.Deadline()) {
		return containermaterial.GenerationAdmission{}, rootoci.ErrUnauthorized
	}
	original := ctx
	ctx, stop := context.WithDeadline(ctx, call.Deadline())
	context.AfterFunc(original, stop)
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	controller, sources, err := producer.readers(ctx, call)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	ctx = controller.config.credentialContext
	task, err := controller.config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: taskID})
	if err != nil || task == nil || task.Task == nil {
		return containermaterial.GenerationAdmission{}, containermaterial.ErrPending
	}
	registration, binding, err := controller.taskRegistration(ctx, task.Task)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	session, err := controller.config.Registrations.AdmitContainerGenerationSession(ctx, registration.Node)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	readCtx, cancel := context.WithDeadline(ctx, session.Deadline())
	context.AfterFunc(ctx, cancel)
	if err := producer.lease(readCtx, call, controller, taskID); err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	selected, err := controller.recipient(readCtx, registration, binding)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	sources.Lease = controller.config.ReadLease
	sources.ContainerProfiles = rootMaterialProfiles{controller: controller, selected: selected}
	admitted, err := containermaterial.AdmitGenerationTask(readCtx, sources, materialTask(selected), session, binding)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	if err := call.Guard(readCtx); err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
	return admitted, nil
}

func materialTask(selected containerMaterialRecipient) containermaterial.CurrentTask {
	return containermaterial.CurrentTask{Task: selected.Task, Profile: selected.proof, Release: selected.Verified, Controller: selected.controllerProof}
}

func (producer *rootMaterialAdmission) lease(ctx context.Context, call rootoci.Call, controller *containerMaterialController, taskID string) error {
	if err := call.Guard(ctx); err != nil {
		return err
	}
	task, err := controller.config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: taskID})
	if err != nil || task == nil || task.Task == nil {
		return containermaterial.ErrPending
	}
	selection, err := selectContainerIntent(ctx, controller.config.JS, controller.config.Delivery, task.Task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
	if err != nil {
		return err
	}
	intent := selection.intent
	ctx, stopProof, err := currentContainerIntentContext(ctx, intent)
	defer stopProof()
	if err != nil {
		return err
	}
	admitted, err := controller.config.Mutations.AdmitCurrentLease(ctx, controller.config.Specs.identity.DeploymentID, call.RuntimeID(), intent.AuthorityEpoch)
	if err != nil {
		return err
	}
	controller.config.ReadLease = admitted
	return call.Guard(ctx)
}

func (producer *rootMaterialAdmission) readers(ctx context.Context, call rootoci.Call) (*containerMaterialController, containermaterial.CurrentTaskSources, error) {
	fail := func(err error) (*containerMaterialController, containermaterial.CurrentTaskSources, error) {
		return nil, containermaterial.CurrentTaskSources{}, err
	}
	if os.Geteuid() != 0 || producer == nil || producer.ownhost == nil || producer.factory == nil || call.RuntimeID() == "" {
		return fail(rootoci.ErrUnauthorized)
	}
	if err := call.Guard(ctx); err != nil {
		return fail(err)
	}
	producer.ownhost.mu.RLock()
	node, reader, accepted := producer.ownhost.node, producer.ownhost.reader, producer.ownhost.accepted.Clone()
	producer.ownhost.mu.RUnlock()
	if node == nil || reader == nil {
		return fail(containermaterial.ErrPending)
	}
	client, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		return fail(err)
	}
	// The connector independently authenticates the fixed current config and
	// derives controller credentials from signed accepted Vault generations.
	credentials, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return fail(err)
	}
	conn, credentialContext := credentials.Conn(), credentials.Context()
	if credentialContext == nil || credentialContext.Done() == nil || credentialContext.Err() != nil {
		conn.Close()
		return fail(rootoci.ErrUnauthorized)
	}
	credentialDeadline, ok := credentialContext.Deadline()
	if !ok || !time.Now().Before(credentialDeadline) {
		conn.Close()
		return fail(rootoci.ErrUnauthorized)
	}
	ctx, credentialCancel := context.WithDeadline(ctx, credentialDeadline)
	context.AfterFunc(credentialContext, credentialCancel)
	ctx = ociclient.WithRequestGuard(ctx, func(ctx context.Context) error {
		if call.Guard(ctx) != nil || credentials.Guard(ctx) != nil || call.Guard(ctx) != nil {
			return rootoci.ErrUnauthorized
		}
		return nil
	})
	closeOnFailure := true
	defer func() {
		if closeOnFailure {
			conn.Close()
		}
	}()
	js, err := jetstream.New(conn)
	if err != nil {
		return fail(err)
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return fail(err)
	}
	services, policy, err := runtimeRegistryPolicy(ctx, cfg, js)
	if err != nil {
		return fail(err)
	}
	service, err := delivery.ConnectClient(ctx, delivery.Config{Conn: conn, JS: js, Cell: cfg.NATS.Cell, Verifier: policy.codec, Authorize: policy.authorizeIntent,
		ArtifactVerifier: policy.codec, AuthorizeArtifact: policy.authorizeArtifact})
	if err != nil {
		return fail(err)
	}
	mutations, err := authority.OpenReader(ctx, js, cfg.NATS.Cell)
	if err != nil {
		return fail(err)
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(accepted)
	if err != nil {
		return fail(err)
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return fail(err)
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fail(rootoci.ErrUnauthorized)
	}
	bucket, err := releasechannel.BucketName(strings.ToUpper(cfg.NATS.Cell))
	if err != nil {
		return fail(err)
	}
	objects, err := producer.factory.ObjectStorage()
	if err != nil {
		return fail(err)
	}
	namespace, err := objects.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{})
	if err != nil || namespace.Value == nil || *namespace.Value == "" {
		return fail(errors.Join(rootoci.ErrUnauthorized, err))
	}
	location := releasechannel.Location{Client: objects, Namespace: *namespace.Value, Bucket: bucket}
	controller := &containerMaterialController{config: containerMaterialConfig{Client: client,
		credentialSource: credentials, credentialContext: ctx,
		Specs: services, Delivery: service, ContainerProfiles: &nativeHistory{js: js}, Founders: reader, Accepted: accepted, JS: js, Mutations: mutations, ResponsePublic: public,
		Evidence: func(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
			intent, err := service.ContainerIntent(ctx, operationID)
			if err != nil {
				return nil, err
			}
			return releasechannel.ReadContainerEvidence(ctx, location, intent.Role, digest)
		},
		Allocations: func(ctx context.Context, operationID string, requested release.ContainerBundle, _ trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
			intent, err := service.ContainerIntent(ctx, operationID)
			if err != nil {
				return release.SequenceLocation{}, err
			}
			if intent.Container == nil || target.Cell != strings.ToUpper(cfg.NATS.Cell) || target.Role != intent.Role || target.Environment != services.identity.Environment {
				return release.SequenceLocation{}, rootoci.ErrUnauthorized
			}
			actual, actualErr := release.ContainerBundleSHA256(*intent.Container)
			wanted, wantedErr := release.ContainerBundleSHA256(requested)
			if actualErr != nil || wantedErr != nil || actual != wanted {
				return release.SequenceLocation{}, rootoci.ErrUnauthorized
			}
			return currentContainerAllocations(ctx, producer.factory, *intent.Container, services.roots.current(), target)
		},
		CurrentBundle: func(ctx context.Context, role, architecture string) (release.ContainerBundle, time.Time, error) {
			deadline, ok := ctx.Deadline()
			if !ok || !time.Now().Before(deadline) || !(rootoci.ContainerReleaseRequest{Role: role, Architecture: architecture}).Valid() {
				return release.ContainerBundle{}, time.Time{}, rootoci.ErrUnauthorized
			}
			bundle, found, err := releasechannel.ReadContainerBundle(ctx, location, role, architecture)
			if err != nil || !found {
				return release.ContainerBundle{}, time.Time{}, errors.Join(containermaterial.ErrPending, err)
			}
			return bundle, deadline, ctx.Err()
		}}}
	if delegated := policy.release.Load(); delegated != nil {
		controller.config.releaseDeadline = delegated.expires
	}
	floor, err := producer.credentialFloor(ctx, call, cfg, controller.config)
	if err != nil {
		return fail(err)
	}
	registrations, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: conn, JS: js, StateReplicas: cfg.NATS.Replicas,
		HostMutations: mutations, ManagedCredentialFloor: floor})
	if err != nil {
		return fail(err)
	}
	controller.config.Hosts, controller.config.Registrations = registrations, registrations
	sources := containermaterial.CurrentTaskSources{Client: client, JS: js, Delivery: service, Mutations: mutations,
		Genesis: services.roots.genesis, RootIdentity: services.roots.identity, RootHead: services.roots.reply("").Head, ResponsePublic: public, Credentials: credentials}
	if call.Guard(ctx) != nil || credentials.Guard(ctx) != nil || call.Guard(ctx) != nil {
		return fail(rootoci.ErrUnauthorized)
	}
	closeOnFailure = false
	context.AfterFunc(ctx, conn.Close)
	return controller, sources, nil
}

// This reader is assembled only by the actual root recipient producer. Archive
// I/O keeps the independently current channel and protected selector pinned.
type rootMaterialProfiles struct {
	controller *containerMaterialController
	selected   containerMaterialRecipient
}

func (profiles rootMaterialProfiles) ReadContainerProfile(ctx context.Context, reference string) ([]byte, error) {
	if profiles.controller == nil || profiles.selected.continuityGuard == nil || profiles.controller.config.ContainerProfiles == nil || profiles.controller.config.credentialSource == nil {
		return nil, containermaterial.ErrPending
	}
	guard := func() error {
		if err := profiles.controller.config.credentialSource.Guard(ctx); err != nil {
			return err
		}
		return profiles.selected.continuityGuard(ctx)
	}
	if err := guard(); err != nil {
		return nil, err
	}
	wire, err := profiles.controller.config.ContainerProfiles.ReadContainerProfile(ctx, reference)
	if err != nil {
		return nil, err
	}
	if err := guard(); err != nil {
		return nil, err
	}
	return wire, nil
}

func (config containerMaterialConfig) materialEpoch(ctx context.Context) (uint64, error) {
	if config.ReadLease != nil {
		if err := config.ReadLease.Guard(ctx); err != nil {
			return 0, err
		}
		return config.ReadLease.Epoch(), nil
	}
	if config.Authority == nil {
		return 0, containermaterial.ErrPending
	}
	epoch := config.Authority.Current().Epoch
	return epoch, config.guardMaterialEpoch(ctx, epoch)
}

func (config containerMaterialConfig) guardMaterialEpoch(ctx context.Context, expected uint64) error {
	if config.ReadLease != nil {
		if expected != config.ReadLease.Epoch() {
			return containermaterial.ErrPending
		}
		return config.ReadLease.Guard(ctx)
	}
	if config.Authority == nil || !config.Authority.Current().CanMutate() || config.Authority.Current().Epoch != expected {
		return containermaterial.ErrPending
	}
	return config.Authority.Guard(ctx, expected)
}
