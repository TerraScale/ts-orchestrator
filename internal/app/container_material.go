package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
)

type containerMaterialConfig struct {
	Factory        *ociclient.Factory
	Hosts          seatrollout.Hosts
	Authority      authority.Fencer
	Client         api.ControlClient
	Specs          *specRegistry
	Delivery       *delivery.Service
	Evidence       func(context.Context, string, string) (io.ReadCloser, error)
	Founders       *bootstrapstart.CurrentFounderAuthorityReader
	Accepted       bootstrapstart.AcceptedIdentity
	JS             jetstream.JetStream
	Mutations      *authority.Reader
	Registrations  *host.Reader
	ResponsePublic ed25519.PublicKey
}

type containerMaterialController struct{ config containerMaterialConfig }

type containerMaterialRecipient struct {
	Task                *api.Task
	Service             *api.Service
	Intent              delivery.Intent
	Profile             WorkloadProfile
	Verified            release.VerifiedContainer
	Expected            swarmruntime.ServiceIntent
	SpecRevision        uint64
	proof               containermaterial.Profile
	controllerProof     *bootstrapstart.ControllerHostRecipient
	rootHead            string
	epoch               uint64
	enrollmentExpiresAt time.Time
}

func startContainerMaterial(ctx context.Context, config containerMaterialConfig) (*containerMaterialController, func(), error) {
	if config.Factory == nil || config.Hosts == nil || config.Authority == nil || config.Client == nil || config.Specs == nil || config.Specs.kv == nil || config.Specs.roots == nil || config.Delivery == nil || config.Evidence == nil ||
		config.Founders == nil || config.Accepted.Validate() != nil || config.JS == nil || config.Mutations == nil || config.Registrations == nil || len(config.ResponsePublic) != ed25519.PublicKeySize {
		return nil, nil, errors.New("container material requires current authority, signed profiles, delivery and manager")
	}
	controller := &containerMaterialController{config: config}
	stop := ownedLoop(ctx, "container material renewal", controller.run)
	return controller, stop, nil
}

func (controller *containerMaterialController) registryRecipient(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (containerMaterialRecipient, error) {
	fail := func() (containerMaterialRecipient, error) {
		return containerMaterialRecipient{}, containermaterial.ErrPending
	}
	config := controller.config
	if binding.HostID != registration.ID {
		return fail()
	}
	epoch := config.Authority.Current().Epoch
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return containerMaterialRecipient{}, err
	}
	taskResponse, err := config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	if taskResponse == nil || taskResponse.Task == nil {
		return fail()
	}
	task := taskResponse.Task
	intent, err := config.Delivery.ContainerIntent(ctx, task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	config.Specs.mu.Lock()
	adopted := config.Specs.revision
	config.Specs.mu.Unlock()
	if entry.Revision() != adopted {
		return fail()
	}
	roots := config.Specs.roots.current()
	rootHead := config.Specs.roots.reply("").Head
	proof, err := containermaterial.VerifyProfile(entry.Value(), roots, config.Specs.identity, intent)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	node, err := config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	if node == nil || node.Node == nil || node.Node.Description == nil || node.Node.Description.Platform == nil {
		return fail()
	}
	var enrollment controllerEnrollmentSnapshot
	if node.Node.Role == api.NodeRoleManager {
		enrollment, err = completedControllerEnrollment(ctx, config, registration, binding.InstanceID)
		if err != nil {
			return containerMaterialRecipient{}, err
		}
	}
	expected, err := containermaterial.ServiceIntent(proof, node.Node.Description.Platform.Architecture)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(intent.Cell), Environment: intent.Environment, Role: intent.Role, Architecture: expected.Architecture}
	allocations, err := currentContainerAllocations(ctx, config.Factory, *intent.Container, roots, target)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	validUntil := time.Now().UTC().Add(30 * time.Second)
	verified, err := release.VerifyContainerCurrent(ctx, *intent.Container, roots, target, time.Now().UTC(), validUntil, func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return config.Evidence(ctx, intent.Role, digest)
	}, allocations)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	taskBinding := binding
	var controllerProof *bootstrapstart.ControllerHostRecipient
	if node.Node.Role == api.NodeRoleManager {
		controllerProof, err = bootstrapstart.ReadControllerHostRecipient(ctx, config.Founders, config.Accepted, entry.Value(), registration.Node, binding.InstanceID, node.Node.Status.Addr)
		if err != nil {
			return containerMaterialRecipient{}, err
		}
		taskBinding.HostID = controllerProof.ControllerSlot()
	}
	if err := containermaterial.VerifyTask(ctx, config.Client, task, expected, verified, roots, proof, registration, taskBinding, controllerProof); err != nil {
		return containerMaterialRecipient{}, err
	}
	service, err := config.Client.GetService(ctx, &api.GetServiceRequest{ServiceID: binding.ServiceID})
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	if service == nil || service.Service == nil {
		return fail()
	}
	latest, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil || latest.Revision() != entry.Revision() || !bytes.Equal(latest.Value(), entry.Value()) {
		return fail()
	}
	confirmed, err := config.Delivery.ContainerIntent(ctx, intent.OperationID)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	before, beforeErr := intent.Fingerprint()
	after, afterErr := confirmed.Fingerprint()
	if beforeErr != nil || afterErr != nil || before != after {
		return fail()
	}
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return containerMaterialRecipient{}, err
	}
	if controllerProof != nil {
		confirmed, err := completedControllerEnrollment(ctx, config, registration, binding.InstanceID)
		before, beforeErr := protocol.EncodeJSON(enrollment)
		after, afterErr := protocol.EncodeJSON(confirmed)
		if err != nil || beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
			return fail()
		}
	}
	if err := controllerHostSpecCurrent(ctx, config.JS, config.Specs, entry, rootHead); err != nil {
		return containerMaterialRecipient{}, err
	}
	if err := containermaterial.VerifyCurrentTask(ctx, config.Client, task, expected, verified, roots, proof, registration, taskBinding, controllerProof); err != nil {
		return containerMaterialRecipient{}, err
	}
	config.Specs.mu.Lock()
	currentRevision := config.Specs.revision
	config.Specs.mu.Unlock()
	currentAuthority := config.Authority.Current()
	if currentRevision != entry.Revision() || config.Specs.roots.reply("").Head != rootHead || currentAuthority.Epoch != epoch || !currentAuthority.CanMutate() {
		return fail()
	}
	if ctx.Err() != nil || !verified.Valid(time.Now().UTC()) || controllerProof != nil && (!controllerProof.Valid(time.Now()) || !time.Now().Before(enrollment.ExpiresAt)) {
		return fail()
	}
	return containerMaterialRecipient{Task: task, Service: service.Service, Intent: intent, Profile: proof.Profile(), Verified: verified, Expected: expected, SpecRevision: entry.Revision(), proof: proof,
		controllerProof: controllerProof, rootHead: rootHead, epoch: epoch, enrollmentExpiresAt: enrollment.ExpiresAt}, nil
}

func (controller *containerMaterialController) recipient(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (containerMaterialRecipient, error) {
	selected, err := controller.registryRecipient(ctx, registration, binding)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	if !proto.Equal(&selected.Service.Spec.Task, &selected.Task.Spec) || !proto.Equal(&selected.Service.Spec.Annotations, &selected.Task.ServiceAnnotations) {
		return containerMaterialRecipient{}, containermaterial.ErrPending
	}
	if err := controller.currentMaterialTask(ctx, selected, registration, binding); err != nil {
		return containerMaterialRecipient{}, err
	}
	return selected, nil
}

func (controller *containerMaterialController) currentMaterialTask(ctx context.Context, selected containerMaterialRecipient, registration host.Registration, binding host.ContainerMaterialBinding) error {
	config := controller.config
	if selected.controllerProof != nil {
		binding.HostID = selected.controllerProof.ControllerSlot()
	}
	if err := containermaterial.VerifyCurrentMaterialTask(ctx, config.Client, selected.Task, selected.Expected, selected.Verified, config.Specs.roots.current(), selected.proof, registration, binding, selected.controllerProof); err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	now := time.Now().UTC()
	currentAuthority := config.Authority.Current()
	if revision != selected.SpecRevision || config.Specs.roots.reply("").Head != selected.rootHead || currentAuthority.Epoch != selected.epoch || !currentAuthority.CanMutate() ||
		!selected.Verified.Valid(now) || selected.controllerProof != nil && (!selected.controllerProof.Valid(now) || !now.Before(selected.enrollmentExpiresAt)) {
		return containermaterial.ErrPending
	}
	return ctx.Err()
}

func (controller *containerMaterialController) material(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (result host.ContainerMaterialFiles, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	recipient, err := controller.recipient(ctx, registration, binding)
	if err != nil {
		return result, err
	}
	result = host.ContainerMaterialFiles{Files: map[string][]byte{}, FileEnvironment: map[string]string{}, User: recipient.Expected.Container.User, ExpiresAt: recipient.Verified.ExpiresAt()}
	defer func() {
		if resultErr != nil {
			for _, value := range result.Files {
				clear(value)
			}
			result = host.ContainerMaterialFiles{}
		}
	}()
	if recipient.proof.NoSecrets() {
		return result, nil
	}
	for key := range recipient.Profile.Secrets {
		if !vaultsecret.FileKey(key) || len(key) > 128 || key != strings.ToUpper(key) || key[0] < 'A' || key[0] > 'Z' {
			return result, fmt.Errorf("%w: service requires supported signed _FILE secret keys", containermaterial.ErrPending)
		}
	}
	values, err := vaultsecret.ReadCurrentRefs(ctx, recipient.Profile.Secrets)
	if err != nil {
		return result, fmt.Errorf("%w: OCI Vault secret observation unavailable", containermaterial.ErrPending)
	}
	snapshot := containerSnapshot(recipient, values)
	if err := syncContainerSnapshot(ctx, controller.config.Client, controller.config.Authority, recipient.Service, snapshot); err != nil {
		return result, err
	}
	for key, value := range values {
		name := strings.ToLower(key)
		result.Files[name] = []byte(value.Value())
		result.FileEnvironment[key] = name
		if !value.ExpiresAt.IsZero() && (result.CredentialExpiresAt.IsZero() || value.ExpiresAt.Before(result.CredentialExpiresAt)) {
			result.CredentialExpiresAt = value.ExpiresAt
		}
	}
	if !result.CredentialExpiresAt.IsZero() && result.CredentialExpiresAt.Before(result.ExpiresAt) {
		result.ExpiresAt = result.CredentialExpiresAt
	}
	confirmed, err := controller.recipient(ctx, registration, binding)
	if err != nil || confirmed.SpecRevision != recipient.SpecRevision {
		return result, containermaterial.ErrPending
	}
	if err := checkContainerSnapshot(ctx, controller.config.Client, snapshot); err != nil {
		return result, err
	}
	if err := controller.currentMaterialTask(ctx, confirmed, registration, binding); err != nil {
		return result, err
	}
	if !time.Now().Before(result.ExpiresAt) {
		return result, containermaterial.ErrPending
	}
	return result, nil
}

func containerSnapshot(recipient containerMaterialRecipient, values map[string]vaultsecret.Current) containerSecretSnapshot {
	versions := make(map[string]containerSecretVersion, len(values))
	for key, value := range values {
		versions[key] = containerSecretVersion{ID: value.ID, Version: value.Version, ExpiresAt: value.ExpiresAt}
	}
	return containerSecretSnapshot{OperationID: recipient.Intent.OperationID, ServiceID: recipient.Service.ID, ConfigDigest: recipient.Intent.ConfigDigest, Generation: recipient.Service.Spec.Task.ForceUpdate, Versions: versions}
}

func (controller *containerMaterialController) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if controller.config.Authority.Current().CanMutate() {
			if err := controller.renew(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "container secret renewal pending", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (controller *containerMaterialController) renew(ctx context.Context) error {
	hosts, err := controller.config.Hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	tasks, err := controller.config.Client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil {
		return err
	}
	var failures []error
	seen := map[string]bool{}
	for _, task := range tasks.Tasks {
		if task == nil || seen[task.ServiceID] || task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID] == "" {
			continue
		}
		intent, err := controller.config.Delivery.ContainerIntent(ctx, task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
		if err != nil {
			failures = append(failures, err)
			continue
		}
		entry, err := controller.config.Specs.kv.Get(ctx, cellSpecKey)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		proof, err := containermaterial.VerifyProfile(entry.Value(), controller.config.Specs.roots.current(), controller.config.Specs.identity, intent)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if proof.NoSecrets() {
			continue
		}
		node, err := controller.config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if node == nil || node.Node == nil {
			continue
		}
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID], Region: node.Node.Spec.Annotations.Labels[swarmruntime.LabelRegion], HostID: node.Node.Spec.Annotations.Name, Fingerprint: fingerprint}
		var registration *host.Registration
		for _, status := range hosts {
			if status.Retired {
				continue
			}
			if node.Node.Role == api.NodeRoleManager {
				grant, _, ok := controller.config.Specs.hostGrant(status.Registration.Node)
				if !ok || grant.Controller == "" || grant.Controller != node.Node.Spec.Annotations.Name || grant.PrivateIP != node.Node.Status.Addr || status.Registration.ManagedOCI != nil {
					continue
				}
			} else if status.Registration.ManagedOCI == nil || status.Registration.ID != binding.HostID || status.Registration.ManagedOCI.InstanceID != binding.InstanceID {
				continue
			}
			if registration != nil {
				registration = nil
				break
			}
			current := status.Registration
			registration = &current
		}
		if registration == nil {
			failures = append(failures, containermaterial.ErrPending)
			continue
		}
		binding.HostID = registration.ID
		files, err := controller.material(ctx, *registration, binding)
		for _, value := range files.Files {
			clear(value)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		seen[task.ServiceID] = true
	}
	return errors.Join(failures...)
}
