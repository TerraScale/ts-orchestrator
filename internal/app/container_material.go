package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
)

type containerMaterialConfig struct {
	Root              *rootoci.Client
	releaseDeadline   time.Time
	credentialSource  containermaterial.ControllerCredentials
	credentialContext context.Context
	Hosts             seatrollout.Hosts
	Authority         authority.Fencer
	ReadLease         *authority.LeaseAdmission
	Client            api.ControlReader
	SnapshotMutations api.ControlClient
	Specs             *specRegistry
	Delivery          *delivery.Service
	ContainerProfiles containermaterial.ContainerProfiles
	Evidence          func(context.Context, string, string) (io.ReadCloser, error)
	Allocations       func(context.Context, string, release.ContainerBundle, trust.Keyring, release.ContainerTarget) (release.SequenceLocation, error)
	CurrentBundle     func(context.Context, string, string) (release.ContainerBundle, time.Time, error)
	Founders          *bootstrapstart.CurrentFounderAuthorityReader
	Accepted          bootstrapstart.AcceptedIdentity
	JS                jetstream.JetStream
	Mutations         *authority.Reader
	Registrations     *host.Reader
	ResponsePublic    ed25519.PublicKey
	WorkerMembership  func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error)
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
	continuityGuard     func(context.Context) error
}

// Evidence alone does not authorize a registry pull, material, or allocation.
type containerMaterialEvidence struct {
	recipient  containerMaterialRecipient
	entry      jetstream.KeyValueEntry
	roots      trust.Keyring
	enrollment controllerEnrollmentSnapshot
	binding    host.ContainerMaterialBinding
}

func (controller *containerMaterialController) taskRegistration(ctx context.Context, task *api.Task) (host.Registration, host.ContainerMaterialBinding, error) {
	if task == nil || task.NodeID == "" {
		return host.Registration{}, host.ContainerMaterialBinding{}, containermaterial.ErrPending
	}
	node, err := controller.config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return host.Registration{}, host.ContainerMaterialBinding{}, err
	}
	if node == nil || node.Node == nil {
		return host.Registration{}, host.ContainerMaterialBinding{}, containermaterial.ErrPending
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil {
		return host.Registration{}, host.ContainerMaterialBinding{}, err
	}
	binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID], Region: node.Node.Spec.Annotations.Labels[swarmruntime.LabelRegion], HostID: node.Node.Spec.Annotations.Name, Fingerprint: fingerprint}
	hosts, err := controller.config.Hosts.ListHosts(ctx)
	if err != nil {
		return host.Registration{}, binding, err
	}
	var selected *host.Registration
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
		if selected != nil {
			return host.Registration{}, binding, containermaterial.ErrPending
		}
		current := status.Registration
		selected = &current
	}
	if selected == nil {
		return host.Registration{}, binding, containermaterial.ErrPending
	}
	binding.HostID = selected.ID
	return *selected, binding, nil
}

func (controller *containerMaterialController) recipientEvidence(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (containerMaterialEvidence, error) {
	fail := func() (containerMaterialEvidence, error) {
		return containerMaterialEvidence{}, containermaterial.ErrPending
	}
	config := controller.config
	var observedEpoch uint64
	if config.ReadLease != nil {
		var stopLease context.CancelFunc
		ctx, stopLease = context.WithDeadline(ctx, config.ReadLease.Deadline())
		defer stopLease()
	} else if config.Authority != nil {
		observed := config.Authority.Current()
		if !observed.CanMutate() {
			return fail()
		}
		observedEpoch = observed.Epoch
		var stopLease context.CancelFunc
		ctx, stopLease = context.WithDeadline(ctx, observed.ExpiresAt)
		defer stopLease()
	}
	if binding.HostID != registration.ID {
		return fail()
	}
	epoch, err := config.materialEpoch(ctx)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	if observedEpoch != 0 && epoch != observedEpoch {
		return fail()
	}
	taskResponse, err := config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	if taskResponse == nil || taskResponse.Task == nil {
		return fail()
	}
	task := taskResponse.Task
	selection, err := selectContainerIntent(ctx, config.JS, config.Delivery, task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	intent := selection.intent
	ctx, stopProof, err := currentContainerIntentContext(ctx, intent)
	defer stopProof()
	if err != nil || config.ContainerProfiles == nil {
		return containerMaterialEvidence{}, errors.Join(containermaterial.ErrPending, err)
	}
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	config.Specs.mu.Lock()
	adopted := config.Specs.revision
	config.Specs.mu.Unlock()
	if entry.Revision() != adopted {
		return fail()
	}
	config.Specs.roots.mu.Lock()
	roots, historicalRoots, rootHead := config.Specs.roots.verified.Current, config.Specs.roots.verified.Historical, config.Specs.roots.verified.Head
	config.Specs.roots.mu.Unlock()
	proof, err := containermaterial.VerifyProfile(entry.Value(), roots, config.Specs.identity, intent)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	node, err := config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	if node == nil || node.Node == nil || node.Node.Description == nil || node.Node.Description.Platform == nil {
		return fail()
	}
	var enrollment controllerEnrollmentSnapshot
	if node.Node.Role == api.NodeRoleManager {
		enrollment, err = completedControllerEnrollment(ctx, config, registration, binding.InstanceID)
		if err != nil {
			return containerMaterialEvidence{}, err
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, enrollment.ExpiresAt)
		defer cancel()
	}
	expected, err := containermaterial.ServiceIntent(proof, node.Node.Description.Platform.Architecture)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(intent.Cell), Environment: intent.Environment, Role: intent.Role, Architecture: expected.Architecture}
	channelGuard, err := currentContainerChannel(ctx, intent, expected.Architecture, config.CurrentBundle)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	allocations, err := config.Allocations(ctx, intent.OperationID, *intent.Container, roots, target)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	target.Genesis = allocations.Genesis
	validUntil := time.Now().UTC().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		validUntil = earlier(validUntil, deadline)
	}
	verified, err := release.VerifyContainerCurrent(ctx, *intent.Container, roots, target, time.Now().UTC(), validUntil, func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return config.Evidence(ctx, intent.OperationID, digest)
	}, allocations)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, verified.ExpiresAt())
	defer cancel()
	originalWire, err := config.ContainerProfiles.ReadContainerProfile(ctx, selection.reference)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	originalProfile, err := containermaterial.VerifyProfile(originalWire, historicalRoots, config.Specs.identity, selection.original)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	historical, err := release.VerifyContainerHistorical(*selection.original.Container, historicalRoots, target)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	proof, err = containermaterial.ContinueProfile(originalProfile, historical, proof, verified, time.Now().UTC())
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	expected, err = containermaterial.ServiceIntent(proof, expected.Architecture)
	if err != nil {
		return containerMaterialEvidence{}, err
	}
	continuityGuard := func(ctx context.Context) error {
		if !verified.Valid(time.Now().UTC()) {
			return containermaterial.ErrPending
		}
		ctx, stop := context.WithDeadline(ctx, verified.ExpiresAt())
		defer stop()
		if err := selection.guard(ctx); err != nil {
			return err
		}
		wire, err := config.ContainerProfiles.ReadContainerProfile(ctx, selection.reference)
		if err != nil || !bytes.Equal(wire, originalWire) {
			return errors.Join(containermaterial.ErrPending, err)
		}
		if err := channelGuard(ctx); err != nil {
			return err
		}
		if err := selection.guard(ctx); err != nil {
			return err
		}
		if !verified.Valid(time.Now().UTC()) {
			return containermaterial.ErrPending
		}
		return ctx.Err()
	}
	if err := continuityGuard(ctx); err != nil {
		return containerMaterialEvidence{}, err
	}
	taskBinding := binding
	var controllerProof *bootstrapstart.ControllerHostRecipient
	if node.Node.Role == api.NodeRoleManager {
		controllerProof, err = bootstrapstart.ReadControllerHostRecipient(ctx, config.Founders, config.Accepted, entry.Value(), registration.Node, binding.InstanceID, node.Node.Status.Addr)
		if err != nil {
			return containerMaterialEvidence{}, err
		}
		taskBinding.HostID = controllerProof.ControllerSlot()
	}
	return containerMaterialEvidence{
		recipient: containerMaterialRecipient{Task: task, Intent: intent, Profile: proof.Profile(), Verified: verified, Expected: expected, SpecRevision: entry.Revision(), proof: proof,
			controllerProof: controllerProof, rootHead: rootHead, epoch: epoch, enrollmentExpiresAt: enrollment.ExpiresAt, continuityGuard: continuityGuard},
		entry: entry, roots: roots, enrollment: enrollment, binding: taskBinding,
	}, nil
}

func (controller *containerMaterialController) registryRecipient(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (containerMaterialRecipient, error) {
	fail := func() (containerMaterialRecipient, error) {
		return containerMaterialRecipient{}, containermaterial.ErrPending
	}
	evidence, err := controller.recipientEvidence(ctx, registration, binding)
	if err != nil {
		return containerMaterialRecipient{}, err
	}
	config := controller.config
	selected := evidence.recipient
	task, intent, expected, verified, proof := selected.Task, selected.Intent, selected.Expected, selected.Verified, selected.proof
	entry, roots, rootHead, epoch := evidence.entry, evidence.roots, selected.rootHead, selected.epoch
	enrollment, controllerProof, taskBinding := evidence.enrollment, selected.controllerProof, evidence.binding
	deadline := verified.ExpiresAt()
	if controllerProof != nil {
		if controllerProof.Deadline().Before(deadline) {
			deadline = controllerProof.Deadline()
		}
		if enrollment.ExpiresAt.Before(deadline) {
			deadline = enrollment.ExpiresAt
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
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
	if err := config.guardMaterialEpoch(ctx, epoch); err != nil {
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
	if selected.continuityGuard == nil {
		return containerMaterialRecipient{}, containermaterial.ErrPending
	}
	if err := selected.continuityGuard(ctx); err != nil {
		return containerMaterialRecipient{}, err
	}
	if err := controllerHostSpecCurrent(ctx, config.JS, config.Specs, entry, rootHead); err != nil {
		return containerMaterialRecipient{}, err
	}
	if err := containermaterial.VerifyCurrentTask(ctx, config.Client, task, expected, verified, roots, proof, registration, taskBinding, controllerProof); err != nil {
		return containerMaterialRecipient{}, err
	}
	if err := rootTrustHeadCurrent(ctx, config.JS, config.Specs.roots, rootHead); err != nil {
		return containerMaterialRecipient{}, err
	}
	config.Specs.mu.Lock()
	currentRevision := config.Specs.revision
	config.Specs.mu.Unlock()
	if currentRevision != entry.Revision() || config.Specs.roots.reply("").Head != rootHead {
		return fail()
	}
	if err := config.guardMaterialEpoch(ctx, epoch); err != nil {
		return containerMaterialRecipient{}, err
	}
	if err := selected.continuityGuard(ctx); err != nil {
		return containerMaterialRecipient{}, err
	}
	config.Specs.mu.Lock()
	currentRevision = config.Specs.revision
	config.Specs.mu.Unlock()
	if currentRevision != entry.Revision() || config.Specs.roots.reply("").Head != rootHead {
		return fail()
	}
	if ctx.Err() != nil || !verified.Valid(time.Now().UTC()) || controllerProof != nil && (!controllerProof.Valid(time.Now()) || !time.Now().Before(enrollment.ExpiresAt)) {
		return fail()
	}
	return containerMaterialRecipient{Task: task, Service: service.Service, Intent: intent, Profile: proof.Profile(), Verified: verified, Expected: expected, SpecRevision: entry.Revision(), proof: proof,
		controllerProof: controllerProof, rootHead: rootHead, epoch: epoch, enrollmentExpiresAt: enrollment.ExpiresAt, continuityGuard: selected.continuityGuard}, nil
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
	deadline := selected.Verified.ExpiresAt()
	if selected.controllerProof != nil {
		if selected.controllerProof.Deadline().Before(deadline) {
			deadline = selected.controllerProof.Deadline()
		}
		if selected.enrollmentExpiresAt.Before(deadline) {
			deadline = selected.enrollmentExpiresAt
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if now := time.Now().UTC(); !selected.Verified.Valid(now) || selected.controllerProof != nil && (!selected.controllerProof.Valid(now) || !now.Before(selected.enrollmentExpiresAt)) {
		return containermaterial.ErrPending
	}
	if selected.continuityGuard == nil {
		return containermaterial.ErrPending
	}
	if err := selected.continuityGuard(ctx); err != nil {
		return err
	}
	if selected.controllerProof != nil {
		binding.HostID = selected.controllerProof.ControllerSlot()
	}
	if err := containermaterial.VerifyCurrentMaterialTask(ctx, config.Client, selected.Task, selected.Expected, selected.Verified, config.Specs.roots.current(), selected.proof, registration, binding, selected.controllerProof); err != nil {
		return err
	}
	if err := rootTrustHeadCurrent(ctx, config.JS, config.Specs.roots, selected.rootHead); err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	if revision != selected.SpecRevision || config.Specs.roots.reply("").Head != selected.rootHead {
		return containermaterial.ErrPending
	}
	if err := config.guardMaterialEpoch(ctx, selected.epoch); err != nil {
		return err
	}
	if err := selected.continuityGuard(ctx); err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision = config.Specs.revision
	config.Specs.mu.Unlock()
	if revision != selected.SpecRevision || config.Specs.roots.reply("").Head != selected.rootHead {
		return containermaterial.ErrPending
	}
	if now := time.Now().UTC(); !selected.Verified.Valid(now) || selected.controllerProof != nil && (!selected.controllerProof.Valid(now) || !now.Before(selected.enrollmentExpiresAt)) {
		return containermaterial.ErrPending
	}
	return ctx.Err()
}
