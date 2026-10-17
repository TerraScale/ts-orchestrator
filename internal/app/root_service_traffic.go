//go:build linux

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// ReconcileTaskTraffic derives endpoints inside root from original authenticated
// manager recipients and signed material; the request selects only a signed role.
func (b *rootOCIResources) ReconcileTaskTraffic(ctx context.Context, call rootoci.Call, request rootoci.TaskTrafficRequest) (rootoci.TaskTrafficReceipt, error) {
	fail := func(err error) (rootoci.TaskTrafficReceipt, error) { return rootoci.TaskTrafficReceipt{}, err }
	if ctx == nil || b == nil || b.traffic == nil || os.Geteuid() != 0 || call.Operation() != rootoci.OperationReconcileTaskTraffic || request.Role == "" {
		return fail(rootoci.ErrUnauthorized)
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	if err := lockFenceContext(ctx, &b.trafficMu); err != nil {
		return fail(err)
	}
	defer b.trafficMu.Unlock()
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	scope, err := b.foundation.TaskTrafficFoundation(ctx, call)
	if err != nil {
		return fail(err)
	}
	foundation := scope.Foundation
	ctx, stopFoundation := context.WithDeadline(ctx, scope.ExpiresAt)
	defer stopFoundation()
	operations, err := b.traffic.nodeOperations(ctx, call, b.cfg.NATS.Cell, request.Role)
	if err != nil {
		return fail(err)
	}
	ctx, stopOperations := context.WithDeadline(ctx, operations.Deadline())
	defer stopOperations()
	b.traffic.ownhost.mu.RLock()
	node, session, generation, agent := b.traffic.ownhost.node, b.traffic.ownhost.session, b.traffic.ownhost.generation, b.traffic.ownhost.agent
	b.traffic.ownhost.mu.RUnlock()
	if node == nil || session == nil || session.Err() != nil {
		return fail(containermaterial.ErrPending)
	}
	controller, _, err := b.traffic.readers(ctx, call)
	if err != nil {
		return fail(err)
	}
	ctx = controller.config.credentialContext
	credentials, ok := controller.config.credentialSource.(*rootsecret.ControllerReader)
	if !ok {
		return fail(rootoci.ErrUnauthorized)
	}
	snapshot, err := readRootResourceSnapshot(ctx, b.cfg, controller.config.JS)
	if err != nil {
		return fail(err)
	}
	ctx, stopSpec := context.WithDeadline(ctx, snapshot.specExpiresAt)
	defer stopSpec()
	cell := string(snapshot.managed.region.Region)
	if foundation.Cell != cell || len(snapshot.specWire) == 0 || snapshot.specRevision != controller.config.Specs.revision || snapshot.services.roots.reply("").Head != controller.config.Specs.roots.reply("").Head {
		return fail(rootoci.ErrUnauthorized)
	}
	fence, _ := snapshot.services.releaseFence()
	if fence == nil {
		return fail(rootoci.ErrUnauthorized)
	}
	var sets []cellspec.FencedSet
	for _, set := range fence.BackendSets {
		if set.Role == request.Role {
			sets = append(sets, set)
		}
	}
	if len(sets) == 0 {
		return fail(rootoci.ErrUnauthorized)
	}
	lease, err := controller.config.Mutations.AdmitRuntimeLease(ctx, snapshot.services.identity.DeploymentID, call.RuntimeID())
	if err != nil {
		return fail(err)
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.Deadline())
	defer stopLease()
	controller.config.ReadLease = lease
	controller.config.WorkerMembership = node.ReadWorkerMembership
	observed, err := authority.Observe(ctx, controller.config.JS, b.cfg.NATS.Cell)
	if err != nil {
		return fail(err)
	}
	credentialDeadline, ok := ctx.Deadline()
	if !ok {
		return fail(rootoci.ErrUnauthorized)
	}
	deadline := minResourceDeadline(call.Deadline(), lease.Deadline(), snapshot.specExpiresAt, credentialDeadline, operations.Deadline(), scope.ExpiresAt)
	if deadline.IsZero() {
		return fail(rootoci.ErrUnauthorized)
	}
	ctx, stopSource := context.WithDeadline(ctx, deadline)
	defer stopSource()
	captureContext := ctx
	var captureStops []context.CancelFunc
	defer func() {
		for _, stop := range captureStops {
			stop()
		}
	}()
	retained := []func(context.Context) error{operations.Revalidate}
	var statefulReadiness *swarmruntime.RootTaskReadiness
	var probeAuthorityErr error
	addresses := map[string]string{}
	guardSource := func(ctx context.Context) error {
		ctx, stop := context.WithDeadline(ctx, deadline)
		defer stop()
		if captureContext.Err() != nil || !time.Now().Before(deadline) || session.Err() != nil {
			return ociresource.ErrFenced
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if err := credentials.Guard(ctx); err != nil {
			return err
		}
		if err := lease.Guard(ctx); err != nil {
			return err
		}
		b.traffic.ownhost.mu.RLock()
		same := b.traffic.ownhost.node == node && b.traffic.ownhost.session == session && b.traffic.ownhost.generation == generation && b.traffic.ownhost.agent == agent
		b.traffic.ownhost.mu.RUnlock()
		if !same {
			return ociresource.ErrFenced
		}
		current, err := readRootResourceSnapshot(ctx, b.cfg, controller.config.JS)
		if err != nil || !snapshot.same(current) {
			return errors.Join(ociresource.ErrFenced, err)
		}
		currentScope, err := b.foundation.TaskTrafficFoundation(ctx, call)
		if err != nil || !rootTrafficFoundationCurrent(scope, currentScope, deadline) {
			return errors.Join(ociresource.ErrFenced, err)
		}
		return call.Guard(ctx)
	}
	probe := func(ctx context.Context, task *api.Task) error {
		if task.ServiceAnnotations.Labels[swarmruntime.LabelRole] != request.Role {
			return nil
		}
		reject := func(err error) error { probeAuthorityErr = errors.Join(probeAuthorityErr, err); return err }
		registration, binding, err := controller.taskRegistration(ctx, task)
		if err != nil {
			return reject(err)
		}
		selected, err := controller.registryRecipient(ctx, registration, binding)
		if err != nil {
			return reject(err)
		}
		if err := controller.currentMaterialTask(ctx, selected, registration, binding); err != nil {
			return reject(err)
		}
		address := addresses[registration.Node]
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Is4() || !ip.IsPrivate() {
			return reject(containermaterial.ErrPending)
		}
		if task.Endpoint == nil || task.Endpoint.Spec == nil || len(task.Endpoint.Spec.Ports) != 1 {
			return reject(containermaterial.ErrPending)
		}
		port := task.Endpoint.Spec.Ports[0]
		if port == nil || port.PublishMode != api.PublishModeHost || port.Protocol != api.ProtocolTCP || port.PublishedPort < 1024 || port.PublishedPort > 65535 || port.TargetPort != port.PublishedPort {
			return reject(containermaterial.ErrPending)
		}
		for _, set := range sets {
			if int(port.PublishedPort) != set.Port {
				return reject(containermaterial.ErrPending)
			}
		}
		deadline = earlier(deadline, selected.Verified.ExpiresAt())
		if selected.controllerProof != nil {
			deadline = earlier(deadline, earlier(selected.controllerProof.Deadline(), selected.enrollmentExpiresAt))
		}
		check := func(ctx context.Context) error {
			return controller.currentMaterialTask(ctx, selected, registration, binding)
		}
		retained = append(retained, check)
		if execution.Stateful(task) {
			if err := guardSource(ctx); err != nil {
				return reject(err)
			}
			if statefulReadiness == nil {
				statefulReadiness, err = b.rootStatefulTrafficReadiness(ctx, controller, snapshot, agent, guardSource)
				if err != nil {
					return reject(err)
				}
			}
			probeDeadline, ok := ctx.Deadline()
			if !ok {
				return reject(rootoci.ErrUnauthorized)
			}
			// The manager cancels its temporary probe context after this call.
			// Retain its original cap under the live root operation instead.
			capture, stop := context.WithDeadline(captureContext, earlier(deadline, probeDeadline))
			captureStops = append(captureStops, stop)
			witness, err := statefulReadiness.CaptureTaskReadiness(capture, selected.Task)
			if err != nil {
				return reject(err)
			}
			deadline = earlier(deadline, witness.Deadline())
			witnessContext, finishWitness := context.WithDeadline(captureContext, deadline)
			captureStops = append(captureStops, finishWitness)
			context.AfterFunc(witnessContext, stopSource)
			retained = append(retained, witness.Recheck)
			if err := check(ctx); err != nil {
				return reject(err)
			}
			return guardSource(ctx)
		}
		if err := swarmruntime.ProbeTask(ctx, selected.Task, ip); err != nil {
			return err
		}
		retained = append(retained, func(ctx context.Context) error {
			if err := check(ctx); err != nil {
				return err
			}
			if err := swarmruntime.ProbeTask(ctx, selected.Task, ip); err != nil {
				return err
			}
			return check(ctx)
		})
		return check(ctx)
	}
	source := managerEdgeSource{client: controller.config.Client, specs: controller.config.Specs, hosts: controller.config.Hosts, guard: guardSource, probe: probe,
		recipient: func(ctx context.Context, managerNode *api.Node, registration host.Registration) (managerEdgeRecipient, error) {
			proof, err := controller.edgeRecipient(ctx, managerNode, registration)
			if err != nil {
				return managerEdgeRecipient{}, err
			}
			address := ""
			if managerNode.Role == api.NodeRoleManager {
				grant, _, ok := snapshot.services.hostGrant(registration.Node)
				if !ok {
					return managerEdgeRecipient{}, rootoci.ErrUnauthorized
				}
				address = grant.PrivateIP
			} else {
				membership, err := node.ReadWorkerMembership(ctx, managerNode.ID)
				if err != nil || membership.Validate() != nil || membership.RegistrationID() != registration.ID {
					return managerEdgeRecipient{}, containermaterial.ErrPending
				}
				address = membership.PrivateIP()
				deadline = earlier(deadline, membership.Info().ExpiresAt)
			}
			addresses[registration.Node] = address
			deadline = earlier(deadline, proof.deadline)
			return proof, nil
		}}
	manager, guardManager, err := source.snapshot(ctx)
	if err != nil {
		return fail(err)
	}
	if probeAuthorityErr != nil {
		return fail(probeAuthorityErr)
	}
	guard := func(ctx context.Context) error {
		if err := guardSource(ctx); err != nil {
			return err
		}
		if err := guardManager(ctx); err != nil {
			return err
		}
		for _, check := range retained {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return guardSource(ctx)
	}
	ctx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	fencer := rootResourceFencer{call: call, epoch: foundation.Epoch, observed: observed, js: controller.config.JS, guard: guard, deadline: deadline, credentials: credentials}
	guardCurrent := func(ctx context.Context) error { return fencer.Guard(ctx, foundation.Epoch) }
	if err := guardCurrent(ctx); err != nil {
		return fail(err)
	}
	ctx = ociclient.WithRequestGuard(ctx, guardCurrent)
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := guardCurrent(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	observations, err := ociresource.OpenObservationStore(ctx, controller.config.JS, b.cfg.NATS.Replicas)
	if err != nil {
		return fail(err)
	}
	authorized := rootfoundation.ResourceAuthority{Source: ociresource.ResourceSource{ControllerConfigSHA256: snapshot.configDigest, GrantSHA256: foundation.GrantDigest,
		CellSpecSHA256: controllerSHA256(snapshot.specWire), CellSpecGeneration: snapshot.services.current.Generation}, Specs: map[string]string{}}
	store, err := b.foundation.OpenResourceStore(ctx, call, foundation, authorized, observations)
	if err != nil {
		return fail(err)
	}
	kind := "task-traffic-" + controllerSHA256([]byte(request.Role))[:32]
	previous, err := store.List(ctx, cell, kind)
	if err != nil {
		return fail(err)
	}
	nodeNames := map[string]bool{}
	for node := range manager {
		nodeNames[node] = true
	}
	for _, grant := range snapshot.services.hostGrants() {
		nodeNames[grant.Node] = true
	}
	for _, entry := range previous {
		var before rootTaskTrafficSpec
		if err := json.Unmarshal(entry.Spec, &before, json.RejectUnknownMembers(true)); err != nil {
			return fail(err)
		}
		if err := before.Validate(); err != nil {
			return fail(err)
		}
		for _, backend := range before.Backends {
			nodeNames[backend.Node] = true
		}
	}
	var names []string
	for node := range nodeNames {
		names = append(names, node)
	}
	slices.Sort(names)
	holds, guardHolds, err := rootTrafficHolds(ctx, controller.config.JS, names)
	if err != nil {
		return fail(err)
	}
	retained = append(retained, guardHolds)
	drains, restores := map[string]string{}, map[string]bool{}
	for _, operation := range operations.Operations() {
		node := operation.Node()
		if operation.Operation() == "rename" {
			node = operation.From()
		}
		switch operation.Operation() {
		case "drain", "reboot", "resize", "retire", "rename":
			drains[node] = "nodeop:" + operation.OperationID() + ":" + operation.RequestSHA256()
		case "undrain":
			restores[node] = true
		}
	}
	for node, record := range holds {
		for _, holder := range record.holders() {
			// Release/rollout phases and DATA fences need their own genuine
			// signed root admissions; unsigned progress cannot replace them.
			if holder != holdMaintenance && holder != holdOperation || drains[node] == "" && !restores[node] {
				return fail(containermaterial.ErrPending)
			}
		}
	}
	pins := map[string]rootTaskTrafficSpec{}
	keys := make([]ociresource.Key, 0, len(sets))
	for _, set := range sets {
		key := ociresource.Key{Region: cell, Kind: kind, Name: set.Name}
		var before rootTaskTrafficSpec
		for _, entry := range previous {
			if entry.Key == key {
				if err := json.Unmarshal(entry.Spec, &before, json.RejectUnknownMembers(true)); err != nil {
					return fail(err)
				}
				if before.LoadBalancerID != fence.LoadBalancerID || before.BackendSet != set.Name || before.Port != set.Port {
					return fail(ociresource.ErrFenced)
				}
			}
		}
		wanted, err := rootTrafficBackends(manager, addresses, request.Role, before.Backends, drains, restores, durationOr(fence.DrainGraceSeconds, defaultFenceGrace), time.Now().UTC())
		if err != nil {
			return fail(err)
		}
		spec := rootTaskTrafficSpec{LoadBalancerID: fence.LoadBalancerID, BackendSet: set.Name, Port: set.Port, MinServing: set.Min(), Backends: wanted}
		desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce, spec)
		if err != nil {
			return fail(err)
		}
		authorized.Specs[key.String()] = desired.SpecDigest
		pins[set.Name], keys = spec, append(keys, key)
	}
	store, err = b.foundation.OpenResourceStore(ctx, call, foundation, authorized, observations)
	if err != nil {
		return fail(err)
	}
	regionName, err := snapshot.managed.region.Region.OCIRegion()
	if err != nil {
		return fail(err)
	}
	if scope.OCIRegion != regionName {
		return fail(ociresource.ErrFenced)
	}
	factory, err := b.traffic.factory.ForRegion(regionName)
	if err != nil {
		return fail(err)
	}
	apiClient, err := lb.NewSDKAPI(factory)
	if err != nil {
		return fail(err)
	}
	sdk, err := factory.LoadBalancer()
	if err != nil {
		return fail(err)
	}
	resource := rootTaskTrafficResource{kind: kind, api: apiClient, client: sdk, region: regionName, compartment: scope.CompartmentID, pins: pins}
	control := ociresource.Controller[rootTaskTrafficSpec, []lb.Backend]{Region: cell, Resource: resource, Store: store, Authority: fencer, Ownership: ociresource.Ownership{Owner: snapshot.managed.region.Owner}}
	for _, key := range keys {
		if _, err := ociresource.Publish(ctx, store, key, ociresource.PolicyEnforce, pins[key.Name]); err != nil {
			return fail(err)
		}
		desired, err := store.Get(ctx, key)
		if err != nil {
			return fail(err)
		}
		if desired.Operation == nil {
			if _, err := store.SaveOperation(ctx, desired, foundation.Epoch, time.Now().UTC(), false); err != nil {
				return fail(err)
			}
		}
	}
	if _, err := control.Reconcile(ctx, foundation.Epoch); err != nil {
		return fail(err)
	}
	// Confirm actual provider outcomes before returning a protected receipt.
	if _, err := control.Reconcile(ctx, foundation.Epoch); err != nil {
		return fail(err)
	}
	result := rootoci.TaskTrafficReceipt{Role: request.Role, ExpiresAt: deadline}
	for _, key := range keys {
		desired, err := store.Get(ctx, key)
		if err != nil || desired.Operation == nil || desired.Operation.CompletedAt.IsZero() {
			return fail(errors.Join(containermaterial.ErrPending, err))
		}
		result.OperationIDs = append(result.OperationIDs, desired.Operation.ID)
	}
	if err := guardCurrent(ctx); err != nil {
		return fail(err)
	}
	result.ObservedAt = time.Now().UTC()
	return result, nil
}

func rootTrafficBackends(manager managerEdgeSnapshot, addresses map[string]string, role string, previous []rootTaskTrafficBackend, drains map[string]string, restores map[string]bool, grace time.Duration, now time.Time) ([]rootTaskTrafficBackend, error) {
	byNode := map[string]rootTaskTrafficBackend{}
	for _, backend := range previous {
		byNode[backend.Node] = backend
	}
	for node, state := range manager {
		if _, assigned := state.roles[role]; !assigned {
			continue
		}
		address := addresses[node]
		if old, exists := byNode[node]; exists {
			if address != "" && old.IP != address {
				return nil, ociresource.ErrFenced
			}
		} else if address != "" {
			backend := rootTaskTrafficBackend{Node: node, IP: address}
			if !state.roles[role].ready {
				backend.Hold, backend.DrainSince, backend.Offline = holdHealth, now, true
			}
			byNode[node] = backend
		}
	}
	var wanted []rootTaskTrafficBackend
	for node, backend := range byNode {
		state, assigned := manager[node].roles[role]
		ready := assigned && state.ready && addresses[node] == backend.IP
		if ready {
			backend.UnreadySince = time.Time{}
			if backend.Hold == holdHealth || strings.HasPrefix(backend.Hold, "nodeop:") && restores[node] {
				backend.Hold, backend.DrainSince, backend.Offline = "", time.Time{}, false
			}
		} else {
			if backend.UnreadySince.IsZero() {
				backend.UnreadySince = now
			}
			if backend.Hold == "" && now.Sub(backend.UnreadySince) >= edgeDownFor {
				backend.Hold, backend.DrainSince = holdHealth, now
			}
		}
		if hold := drains[node]; hold != "" {
			if backend.Hold != hold {
				backend.Hold, backend.DrainSince = hold, now
			}
		}
		if backend.Hold != "" {
			backend.Offline = now.Sub(backend.DrainSince) >= grace
		}
		wanted = append(wanted, backend)
	}
	slices.SortFunc(wanted, func(a, b rootTaskTrafficBackend) int { return strings.Compare(a.Node, b.Node) })
	if len(wanted) > 64 {
		return nil, errors.New("task traffic exceeds its backend bound")
	}
	return wanted, nil
}

var _ rootoci.Foundation = (*rootOCIResources)(nil)

func rootTrafficFoundationCurrent(original, current rootfoundation.TaskTrafficScope, deadline time.Time) bool {
	return !deadline.IsZero() && !current.ExpiresAt.Before(deadline) &&
		reflect.DeepEqual(original.Foundation, current.Foundation) && original.OCIRegion == current.OCIRegion && original.CompartmentID == current.CompartmentID
}
