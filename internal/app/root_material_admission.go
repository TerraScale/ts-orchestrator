//go:build linux

package app

import (
	"context"
	"crypto/ed25519"
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
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
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
	deadline := earlier(evidence.Request.IssuedAt.Add(10*time.Second), evidence.Request.ExpiresAt)
	if !time.Now().Before(deadline) {
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
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	controller, sources, err := producer.readers(ctx, call)
	if err != nil {
		return containermaterial.GenerationAdmission{}, err
	}
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
	intent, err := controller.config.Delivery.ContainerIntent(ctx, task.Task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
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
	client, err := node.ControlClient(ctx)
	if err != nil {
		return fail(err)
	}
	// The connector independently authenticates the fixed current config and
	// derives controller credentials from signed accepted Vault generations.
	conn, err := rootsecret.ConnectControllerReader(ctx)
	if err != nil {
		return fail(err)
	}
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
	service, err := delivery.ConnectClient(ctx, delivery.Config{Conn: conn, JS: js, Cell: cfg.NATS.Cell, Verifier: policy.codec, Authorize: policy.authorizeIntent})
	if err != nil {
		return fail(err)
	}
	mutations, err := authority.OpenReader(ctx, js, cfg.NATS.Cell)
	if err != nil {
		return fail(err)
	}
	registrations, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: conn, JS: js, StateReplicas: cfg.NATS.Replicas, HostMutations: mutations})
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
	channel := instancePrincipalChannel(producer.factory.Region(), strings.ToUpper(cfg.NATS.Cell))
	controller := &containerMaterialController{config: containerMaterialConfig{Factory: producer.factory, Hosts: registrations, Client: client,
		Specs: services, Delivery: service, Founders: reader, Accepted: accepted, JS: js, Mutations: mutations, Registrations: registrations, ResponsePublic: public,
		Evidence: func(ctx context.Context, role, digest string) (io.ReadCloser, error) {
			location, err := channel.get(ctx)
			if err != nil {
				return nil, err
			}
			return releasechannel.ReadContainerEvidence(ctx, location, role, digest)
		}}}
	sources := containermaterial.CurrentTaskSources{Client: client, JS: js, Delivery: service, Mutations: mutations,
		Genesis: services.roots.genesis, RootIdentity: services.roots.identity, RootHead: services.roots.reply("").Head, ResponsePublic: public}
	if err := call.Guard(ctx); err != nil {
		return fail(err)
	}
	closeOnFailure = false
	return controller, sources, nil
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
