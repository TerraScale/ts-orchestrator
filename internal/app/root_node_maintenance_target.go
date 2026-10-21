//go:build linux

package app

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// This is a current enrolled identity proof, not a provider phase receipt.
// Forgetting enrollment or completing termination requires a separate phase proof.
type rootNodeMaintenanceTarget struct {
	source         *rootNodeMaintenanceTargetSource
	node, from     string
	instanceID     string
	grant          cellspec.HostGrant
	enrollment     []byte
	grantRevision  uint64
	registration   []byte
	registeredNode string
	sequence       uint64
	query          swarmruntime.WorkerRegistrationQuery
	controller     *bootstrapstart.ControllerHostRecipient
	observed       bootstrapstart.InstanceObservation
	view           rootoci.NodeMaintenanceNode
	deadline       time.Time
}

type rootNodeMaintenanceTargetSource struct {
	producer     *rootMaterialAdmission
	call         rootoci.Call
	config       containerMaterialConfig
	credentials  *rootsecret.ControllerReader
	snapshot     rootResourceSnapshot
	lease        authority.Snapshot
	compute      core.ComputeClient
	observer     *bootstrapstart.OCIInstanceObserver
	compartments []string
	accepted     []byte
	deadline     time.Time
	grantCreated time.Time
	grantConfig  jetstream.StreamConfig
	runtimeNode  *swarmruntime.Node
	agent        *host.Agent
	session      context.Context
	generation   uint64
	nodeID       string
}

func (producer *rootMaterialAdmission) nodeMaintenanceTargets(ctx context.Context, call rootoci.Call) (_ *rootNodeMaintenanceTargetSource, resultErr error) {
	if ctx == nil || os.Geteuid() != 0 || producer == nil || producer.factory == nil || call.RuntimeID() == "" {
		return nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer func() {
		if resultErr != nil {
			cancel()
		}
	}()
	controller, _, err := producer.readers(ctx, call)
	if err != nil {
		return nil, err
	}
	config := controller.config
	defer func() {
		if resultErr != nil {
			config.JS.Conn().Close()
		}
	}()
	credentials, ok := config.credentialSource.(*rootsecret.ControllerReader)
	if !ok || credentials == nil || config.credentialContext == nil {
		return nil, rootoci.ErrUnauthorized
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return nil, err
	}
	snapshot, err := readRootResourceSnapshot(ctx, cfg, config.JS)
	if err != nil {
		return nil, err
	}
	lease, err := authority.Observe(ctx, config.JS, cfg.NATS.Cell)
	if err != nil || !lease.Ready || lease.Epoch == 0 || lease.Revision == 0 || lease.CandidateID != call.RuntimeID() || lease.DeploymentID != snapshot.services.identity.DeploymentID {
		return nil, errors.Join(authority.ErrFenced, err)
	}
	credentialDeadline, ok := config.credentialContext.Deadline()
	if !ok {
		return nil, rootoci.ErrUnauthorized
	}
	deadline := minResourceDeadline(call.Deadline(), credentialDeadline, lease.ExpiresAt, snapshot.specExpiresAt)
	if !config.releaseDeadline.IsZero() {
		deadline = earlier(deadline, config.releaseDeadline)
	}
	accepted, err := bootstrapstart.EncodeAcceptedIdentity(config.Accepted)
	if err != nil {
		return nil, err
	}
	compute, err := producer.factory.Compute()
	if err != nil {
		return nil, err
	}
	observer, err := bootstrapstart.NewOCIInstanceObserverWithFactory(snapshot.managed.region.Region, producer.factory)
	if err != nil {
		return nil, err
	}
	source := &rootNodeMaintenanceTargetSource{producer: producer, call: call, config: config, credentials: credentials,
		snapshot: snapshot, lease: lease, compute: compute, observer: observer, accepted: accepted, deadline: deadline}
	producer.ownhost.mu.RLock()
	source.runtimeNode, source.agent, source.session = producer.ownhost.node, producer.ownhost.agent, producer.ownhost.session
	source.generation, source.nodeID = producer.ownhost.generation, producer.ownhost.nodeID
	producer.ownhost.mu.RUnlock()
	if err := source.live(ctx); err != nil {
		return nil, err
	}
	stream, err := config.JS.Stream(ctx, "KV_"+hostenroll.GrantBucket)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil || info == nil || info.Created.IsZero() {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	source.grantCreated, source.grantConfig = info.Created, info.Config
	ctx = ociclient.WithRequestGuard(config.credentialContext, source.guard)
	if err := source.guard(ctx); err != nil {
		return nil, err
	}
	own, err := observer.ObserveInstance(ctx, config.Accepted.InstanceOCID)
	if err != nil || own.PrimaryVNICOCID != config.Accepted.PrimaryVNICOCID || own.PrimaryPrivateIP != config.Accepted.PrimaryPrivateIP || own.ImageOCID != config.Accepted.ImageOCID {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	source.compartments = slices.Compact(slices.Sorted(slices.Values([]string{own.CompartmentOCID, snapshot.managed.region.CompartmentID})))
	if err := source.guard(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *rootNodeMaintenanceTargetSource) live(ctx context.Context) error {
	if source == nil || source.producer == nil || source.producer.ownhost == nil || ctx == nil || ctx.Err() != nil ||
		source.runtimeNode == nil || source.agent == nil || source.session == nil || source.session.Err() != nil || source.nodeID == "" ||
		!reflect.TypeOf(source.session).Comparable() || !time.Now().Before(source.deadline) {
		return rootoci.ErrUnauthorized
	}
	source.producer.ownhost.mu.RLock()
	defer source.producer.ownhost.mu.RUnlock()
	ownhost := source.producer.ownhost
	accepted, err := bootstrapstart.EncodeAcceptedIdentity(ownhost.accepted)
	if err != nil || ownhost.reader != source.config.Founders || !bytes.Equal(accepted, source.accepted) ||
		ownhost.node != source.runtimeNode || ownhost.agent != source.agent || ownhost.session != source.session ||
		ownhost.generation != source.generation || ownhost.nodeID != source.nodeID || source.session.Err() != nil || ctx.Err() != nil || !time.Now().Before(source.deadline) {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (source *rootNodeMaintenanceTargetSource) guard(ctx context.Context) error {
	if os.Geteuid() != 0 || source == nil || source.producer == nil || source.producer.ownhost == nil || source.credentials == nil ||
		ctx == nil || ctx.Err() != nil || source.config.credentialContext == nil || source.config.credentialContext.Err() != nil || !time.Now().Before(source.deadline) {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, source.deadline)
	defer cancel()
	if err := source.call.Guard(ctx); err != nil {
		return err
	}
	if err := source.credentials.Guard(ctx); err != nil {
		return err
	}
	if err := source.live(ctx); err != nil {
		return err
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return err
	}
	current, err := readRootResourceSnapshot(ctx, cfg, source.config.JS)
	if err != nil || !source.snapshot.same(current) {
		return errors.Join(rootoci.ErrUnauthorized, err)
	}
	stream, err := source.config.JS.Stream(ctx, "KV_"+hostenroll.GrantBucket)
	if err != nil {
		return err
	}
	info, err := stream.Info(ctx)
	if err != nil || info == nil || !info.Created.Equal(source.grantCreated) || !reflect.DeepEqual(info.Config, source.grantConfig) {
		return errors.Join(rootoci.ErrUnauthorized, err)
	}
	lease, err := authority.Observe(ctx, source.config.JS, source.lease.Scope)
	if err != nil || !lease.Ready || lease.DeploymentID != source.lease.DeploymentID || lease.CandidateID != source.lease.CandidateID || lease.OwnerID != source.lease.OwnerID ||
		lease.Scope != source.lease.Scope || lease.Epoch != source.lease.Epoch || lease.Revision < source.lease.Revision || !time.Now().Before(lease.ExpiresAt) {
		return errors.Join(authority.ErrFenced, err)
	}
	if err := ociclient.LimitAdmission(ctx, source.deadline); err != nil {
		return err
	}
	if err := source.credentials.Guard(ctx); err != nil {
		return err
	}
	if err := source.call.Guard(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || source.config.credentialContext.Err() != nil || !time.Now().Before(source.deadline) {
		return rootoci.ErrUnauthorized
	}
	return source.live(ctx)
}

// Enumeration supplies locators only. Signed scope, enrollment and OCI must agree.
func (source *rootNodeMaintenanceTargetSource) candidates(ctx context.Context) ([]core.Instance, error) {
	ctx = ociclient.WithRequestGuard(ctx, source.guard)
	ids := make(map[string]core.Instance)
	for _, binding := range source.config.Accepted.ControllerBindings {
		ids[binding.InstanceOCID] = core.Instance{Id: new(binding.InstanceOCID)}
	}
	if len(ids) > 512 {
		return nil, rootoci.ErrUnauthorized
	}
	for _, compartment := range source.compartments {
		var page *string
		pages := make(map[string]struct{})
		count := 0
		for {
			response, err := source.compute.ListInstances(ociclient.RequestContext(ctx), core.ListInstancesRequest{CompartmentId: new(compartment), Page: page, Limit: new(100)})
			if err != nil {
				return nil, err
			}
			count += len(response.Items)
			if count > 512 || len(pages) > 512 {
				return nil, errors.New("node maintenance candidate enumeration exceeds its fixed bound")
			}
			for _, instance := range response.Items {
				if instance.Id == nil || instance.CompartmentId == nil || *instance.CompartmentId != compartment {
					return nil, rootoci.ErrUnauthorized
				}
				if instance.LifecycleState != core.InstanceLifecycleStateTerminated && instance.LifecycleState != core.InstanceLifecycleStateTerminating {
					ids[*instance.Id] = instance
					if len(ids) > 512 {
						return nil, errors.New("node maintenance candidates exceed their fixed total bound")
					}
				}
			}
			if response.OpcNextPage == nil || *response.OpcNextPage == "" {
				break
			}
			if len(*response.OpcNextPage) > 4096 {
				return nil, errors.New("node maintenance candidate page exceeds its fixed bound")
			}
			if _, repeated := pages[*response.OpcNextPage]; repeated {
				return nil, errors.New("node maintenance candidate page repeated")
			}
			pages[*response.OpcNextPage] = struct{}{}
			page = response.OpcNextPage
		}
	}
	var candidates []core.Instance
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		instance := ids[id]
		if instance.DisplayName == nil {
			response, err := source.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
			if err != nil {
				return nil, err
			}
			if response.Instance.Id == nil || *response.Instance.Id != id {
				return nil, rootoci.ErrUnauthorized
			}
			instance = response.Instance
		}
		candidates = append(candidates, instance)
	}
	return candidates, source.guard(ctx)
}

func (source *rootNodeMaintenanceTargetSource) target(ctx context.Context, node, from string, candidates []core.Instance) (*rootNodeMaintenanceTarget, error) {
	grant, _, ok := source.snapshot.services.hostGrant(node)
	if !ok || grant.PrivateIP == "" {
		return nil, rootoci.ErrUnauthorized
	}
	if from != "" {
		if _, _, exists := source.snapshot.services.hostGrant(from); exists || from == node {
			return nil, errors.New("node rename does not replace its exact original grant")
		}
	}
	var selected *rootNodeMaintenanceTarget
	ctx = ociclient.WithRequestGuard(ctx, source.guard)
	for _, candidate := range candidates {
		if candidate.Id == nil || candidate.DisplayName == nil || (*candidate.DisplayName != node && (from == "" || *candidate.DisplayName != from)) {
			continue
		}
		id := *candidate.Id
		response, err := source.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
		if err != nil {
			return nil, err
		}
		instance := response.Instance
		if instance.Id == nil || *instance.Id != id {
			return nil, rootoci.ErrUnauthorized
		}
		if instance.DisplayName == nil || (*instance.DisplayName != node && (from == "" || *instance.DisplayName != from)) {
			continue
		}
		target, err := source.bind(ctx, grant, from, instance)
		if err != nil {
			return nil, err
		}
		if selected != nil {
			return nil, errors.New("node maintenance has multiple authenticated targets")
		}
		selected = target
	}
	if selected == nil {
		return nil, errors.New("node maintenance has no authenticated enrolled target")
	}
	return selected, selected.Revalidate(ctx)
}

func (source *rootNodeMaintenanceTargetSource) bind(ctx context.Context, grant cellspec.HostGrant, from string, instance core.Instance) (*rootNodeMaintenanceTarget, error) {
	if instance.Id == nil || instance.CompartmentId == nil || instance.DisplayName == nil ||
		(*instance.DisplayName != grant.Node && (from == "" || *instance.DisplayName != from)) || instance.LifecycleState != core.InstanceLifecycleStateRunning {
		return nil, rootoci.ErrPending
	}
	id := *instance.Id
	if !slices.Contains(source.compartments, *instance.CompartmentId) && !slices.ContainsFunc(source.config.Accepted.ControllerBindings, func(binding bootstrapstart.ControllerBinding) bool {
		return binding.InstanceOCID == id && binding.Slot == grant.Controller
	}) {
		return nil, rootoci.ErrUnauthorized
	}
	observed, err := source.observer.ObserveInstance(ctx, id)
	if err != nil || observed.LifecycleState != "RUNNING" || observed.PrimaryPrivateIP != grant.PrivateIP || observed.CompartmentOCID != *instance.CompartmentId {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	current, revision, err := hostenroll.ReadCurrentGrant(ctx, source.config.JS, id)
	if err != nil || current.Disabled || current.TerminalOperationID != "" || current.IdentityResetOperationID != "" {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	query := swarmruntime.WorkerRegistrationQuery{Request: current.Request, Response: current.Response}
	if len(current.RenewalResponse) != 0 {
		query.Request, query.Response = current.RenewalRequest, current.RenewalResponse
	}
	if !current.MatchesCompletedWorkerEnrollment(hostenroll.WorkerTransport{Request: query.Request, Response: query.Response}) {
		return nil, rootoci.ErrUnauthorized
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil || !descriptor.IsStatic() || request.InstanceID != id || descriptor.Cell != source.snapshot.services.identity.Cell ||
		!strings.EqualFold(descriptor.Region, source.config.Accepted.Cell) || (descriptor.Node != grant.Node && (from == "" || descriptor.Node != from)) {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	if err := refuseUnprovenPoolDescriptor(descriptor); err != nil {
		return nil, err
	}
	digest, err := descriptor.Digest()
	if err != nil || current.DescriptorSHA256 != digest || current.CreateKey != entityid.Derive("static-enrollment", descriptor.Cell, descriptor.Node) {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	response, err := hostenroll.VerifyResponse(query.Response, source.config.ResponsePublic, request, query.Request, descriptor)
	if err != nil || response.Swarm != nil {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	registration, err := currentWorkerRegistration(ctx, source.config.Mutations, source.config.Registrations, source.config.JS, query, id, descriptor.Node, descriptor.Cell)
	registered := registration.Registration
	if err != nil || registration.Pending || registration.Retired || registration.Disabled || registration.TerminalOperationID != "" || registration.IdentityResetOperationID != "" ||
		registered.PublicKey != request.IdentityPublicKey || registered.NATSUserPublicKey != request.NATSUserPublicKey || registered.Generation != response.RegistrationReceipt.Generation || registration.Sequence != response.RegistrationReceipt.Revision ||
		registered.Environment != grant.Environment || !slices.Equal(registered.Roles, grant.Roles) || !slices.Equal(registered.Roles, response.Roles) ||
		registered.ManagedOCI != nil || registered.ManagedMember != nil || registered.ManagedPlacement != nil || len(grant.Roles) == 0 {
		return nil, errors.Join(rootoci.ErrUnauthorized, err)
	}
	var controller *bootstrapstart.ControllerHostRecipient
	if grant.Controller != "" || descriptor.IsController() {
		if err := controllerHostRegistration(query, registration, request, descriptor, response, source.config.Accepted); err != nil {
			return nil, err
		}
		controller, err = bootstrapstart.ReadControllerHostRecipient(ctx, source.config.Founders, source.config.Accepted,
			source.snapshot.specWire, grant.Node, id, grant.PrivateIP)
		if err != nil {
			return nil, err
		}
		if from == "" || descriptor.Node == grant.Node {
			err = controller.VerifyRegistration(ctx, registered)
		} else {
			// The signed rename joins the old registered keys to the new granted slot.
			err = controller.Verify(ctx)
		}
		if err != nil {
			return nil, err
		}
	}
	enrollment, err := protocol.EncodeJSON(current)
	if err != nil {
		return nil, err
	}
	registrationWire, err := protocol.EncodeJSON(registration)
	if err != nil {
		return nil, err
	}
	deadline := earlier(source.deadline, response.ExpiresAt)
	if controller != nil {
		deadline = earlier(deadline, controller.Deadline())
	}
	view := rootoci.NodeMaintenanceNode{InstanceID: id, Node: grant.Node, State: string(instance.LifecycleState)}
	if instance.ShapeConfig != nil && instance.ShapeConfig.Ocpus != nil && instance.ShapeConfig.MemoryInGBs != nil {
		view.OCPUs, view.MemoryGB = *instance.ShapeConfig.Ocpus, *instance.ShapeConfig.MemoryInGBs
	}
	return &rootNodeMaintenanceTarget{source: source, node: grant.Node, from: from, instanceID: id, grant: grant,
		enrollment: enrollment, grantRevision: revision, registration: registrationWire, registeredNode: descriptor.Node, sequence: registration.Sequence,
		query: query, controller: controller, observed: observed, view: view, deadline: deadline}, nil
}

func (target *rootNodeMaintenanceTarget) Revalidate(ctx context.Context) error {
	if ctx == nil || target == nil || target.source == nil || target.instanceID == "" || target.grantRevision == 0 || target.sequence == 0 || !time.Now().Before(target.deadline) {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, target.deadline)
	defer cancel()
	if err := target.source.guard(ctx); err != nil {
		return err
	}
	ctx = ociclient.WithRequestGuard(ctx, target.source.guard)
	instance, err := target.source.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(target.instanceID)})
	if err != nil {
		return err
	}
	current, err := target.source.bind(ctx, target.grant, target.from, instance.Instance)
	if err != nil {
		return err
	}
	if current.instanceID != target.instanceID || current.grantRevision != target.grantRevision || current.sequence != target.sequence ||
		!bytes.Equal(current.enrollment, target.enrollment) || !bytes.Equal(current.registration, target.registration) ||
		current.observed.CompartmentOCID != target.observed.CompartmentOCID || current.observed.PrimaryVNICOCID != target.observed.PrimaryVNICOCID ||
		current.observed.PrimaryPrivateIP != target.observed.PrimaryPrivateIP || current.observed.ImageOCID != target.observed.ImageOCID {
		return errors.New("node maintenance original enrolled target changed")
	}
	if target.controller != nil {
		if err := target.controller.Verify(ctx); err != nil {
			return err
		}
	}
	if err := ociclient.LimitAdmission(ctx, target.deadline); err != nil {
		return err
	}
	if err := target.source.guard(ctx); err != nil {
		return err
	}
	registration, err := currentWorkerRegistration(ctx, target.source.config.Mutations, target.source.config.Registrations,
		target.source.config.JS, target.query, target.instanceID, target.registeredNode, target.source.snapshot.services.identity.Cell)
	if err != nil {
		return err
	}
	registrationWire, err := protocol.EncodeJSON(registration)
	if err != nil || registration.Sequence != target.sequence || !bytes.Equal(registrationWire, target.registration) {
		return errors.Join(rootoci.ErrUnauthorized, err)
	}
	grant, revision, err := hostenroll.ReadCurrentGrant(ctx, target.source.config.JS, target.instanceID)
	if err != nil {
		return err
	}
	grantWire, err := protocol.EncodeJSON(grant)
	if err != nil || revision != target.grantRevision || !bytes.Equal(grantWire, target.enrollment) {
		return errors.Join(rootoci.ErrUnauthorized, err)
	}
	if err := target.source.credentials.Guard(ctx); err != nil {
		return err
	}
	if err := target.source.call.Guard(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || !time.Now().Before(target.deadline) {
		return rootoci.ErrUnauthorized
	}
	return target.source.live(ctx)
}

func (producer *rootMaterialAdmission) nodeMaintenanceTarget(ctx context.Context, call rootoci.Call, admission rootNodeOperationAdmission) (*rootNodeMaintenanceTarget, error) {
	if err := admission.Revalidate(ctx); err != nil {
		return nil, err
	}
	source, err := producer.nodeMaintenanceTargets(ctx, call)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*rootNodeMaintenanceTarget, error) { source.config.JS.Conn().Close(); return nil, err }
	if !source.snapshot.same(admission.source.snapshot) || source.lease.Epoch != admission.original.Epoch || source.call.RuntimeID() != admission.source.call.RuntimeID() {
		return fail(rootoci.ErrUnauthorized)
	}
	candidates, err := source.candidates(ctx)
	if err != nil {
		return fail(err)
	}
	target, err := source.target(ctx, admission.Node(), admission.From(), candidates)
	if err != nil {
		return fail(err)
	}
	if err := admission.Revalidate(ctx); err != nil {
		return fail(err)
	}
	return target, nil
}

func (producer *rootMaterialAdmission) ObserveNodeMaintenanceNodes(ctx context.Context, call rootoci.Call) ([]rootoci.NodeMaintenanceNode, error) {
	source, err := producer.nodeMaintenanceTargets(ctx, call)
	if err != nil {
		return nil, err
	}
	defer source.config.JS.Conn().Close()
	candidates, err := source.candidates(ctx)
	if err != nil {
		return nil, err
	}
	var observed []rootoci.NodeMaintenanceNode
	for _, grant := range source.snapshot.services.hostGrants() {
		target, err := source.target(ctx, grant.Node, "", candidates)
		if err != nil {
			return nil, err
		}
		observed = append(observed, target.view)
	}
	return observed, source.guard(ctx)
}
