//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/controllercredential"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// One installed source serves both native operations on every actual manager.
// The retained credentials and root/spec adoption cannot follow a successor.
type controllerNodeSource struct {
	original    context.Context
	node        *Node
	binding     *ControllerHostBinding
	credentials *controllercredential.ControllerReader
	factory     *ociclient.Factory
	js          nats.JetStreamContext
	stream      jetstream.JetStream
	mutations   *authority.Reader
	hosts       *host.Reader
	pins        []controllerSourcePin
}

func (n *Node) InstallControllerNodeSources(ctx context.Context, binding *ControllerHostBinding, credentials *controllercredential.ControllerReader, factory *ociclient.Factory) error {
	if os.Geteuid() != 0 || n == nil || n.upstream == nil || n.upstream.Manager() == nil || binding == nil || credentials == nil || factory == nil || ctx == nil || ctx.Err() != nil {
		return ErrControllerActivationPending
	}
	if err := credentials.Guard(ctx); err != nil {
		return err
	}
	original := ctx
	deadline, ok := credentials.Context().Deadline()
	if !ok {
		return ErrControllerActivationPending
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stopCredentials := context.AfterFunc(credentials.Context(), cancel)
	defer cancel()
	defer stopCredentials()
	if _, err := binding.currentRegistration(ctx); err != nil {
		return err
	}
	id := binding.Identity()
	if n.admission.HostID != id.Slot || n.admission.InstanceID != id.InstanceID || n.admission.Region != id.OCIRegion {
		return ErrControllerActivationPending
	}
	js, err := credentials.Conn().JetStream()
	if err != nil {
		return err
	}
	stream, err := jetstream.New(credentials.Conn())
	if err != nil {
		return err
	}
	mutations, err := authority.OpenReader(ctx, stream, strings.ToLower(id.Cell))
	if err != nil {
		return err
	}
	hosts, err := host.NewReader(ctx, host.ReaderConfig{Cell: strings.ToLower(id.Cell), Conn: credentials.Conn(), JS: stream, HostMutations: mutations, StateReplicas: 3})
	if err != nil {
		return err
	}
	source := &controllerNodeSource{original: original, node: n, binding: binding, credentials: credentials, factory: factory, js: js, stream: stream, mutations: mutations, hosts: hosts}
	read := &controllerActivationAdmission{js: js}
	for _, location := range [][2]string{{"TS_TRUST_ROOTS", "chain"}, {"TS_SERVICE_SET", "current"}} {
		pin, err := read.readPin(ctx, location[0], location[1])
		if err != nil {
			return err
		}
		source.pins = append(source.pins, pin)
	}
	inputs, err := bootstrapstart.LoadTrustInputs(binding.accepted)
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(source.pins[0].wire)
	if err != nil || !reflect.DeepEqual(chain, inputs.Chain) {
		return ErrControllerActivationPending
	}
	if _, err := source.signedSpec(); err != nil {
		return err
	}
	if err := source.live(ctx); err != nil {
		return err
	}
	if err := n.upstream.Manager().InstallControllerNodeSource(source); err != nil {
		return err
	}
	n.controllerSources.Store(source)
	return nil
}

func (source *controllerNodeSource) live(ctx context.Context) error {
	if source == nil || source.original == nil || ctx == nil || ctx.Err() != nil || source.original.Err() != nil || source.node == nil || source.credentials == nil {
		return ErrControllerActivationPending
	}
	if err := source.credentials.Guard(ctx); err != nil {
		return err
	}
	if _, err := source.binding.currentRegistration(ctx); err != nil {
		return err
	}
	read := &controllerActivationAdmission{js: source.js}
	for _, pin := range source.pins {
		current, err := read.readPin(ctx, pin.bucket, pin.key)
		if err != nil || current.sequence != pin.sequence || !bytes.Equal(current.wire, pin.wire) {
			return ErrControllerActivationPending
		}
	}
	return ctx.Err()
}

func (source *controllerNodeSource) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if source == nil || source.original == nil || source.credentials == nil || source.credentials.Context() == nil || ctx == nil || ctx.Err() != nil || source.original.Err() != nil {
		return nil, nil, ErrControllerActivationPending
	}
	deadline, ok := source.credentials.Context().Deadline()
	if !ok {
		return nil, nil, ErrControllerActivationPending
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	stopRoot := context.AfterFunc(source.original, cancel)
	stopCredentials := context.AfterFunc(source.credentials.Context(), cancel)
	release := func() { stopRoot(); stopCredentials(); cancel() }
	if err := source.live(bounded); err != nil {
		release()
		return nil, nil, err
	}
	return bounded, release, nil
}

func (source *controllerNodeSource) signedSpec() (cellspec.Verified, error) {
	inputs, err := bootstrapstart.LoadTrustInputs(source.binding.accepted)
	if err != nil {
		return cellspec.Verified{}, err
	}
	id := source.binding.Identity()
	signed, err := cellspec.VerifyHistorical(source.pins[1].wire, inputs.Roots.Current, cellspec.Identity{DeploymentID: id.DeploymentID, Cell: strings.ToLower(id.Cell), Environment: id.Environment})
	if err != nil || !signed.RootSigned {
		return cellspec.Verified{}, ErrControllerActivationPending
	}
	return signed, nil
}

func (source *controllerNodeSource) recipient(ctx context.Context, slot, instanceID string) (*bootstrapstart.ControllerHostRecipient, error) {
	signed, err := source.signedSpec()
	if err != nil {
		return nil, err
	}
	for _, grant := range signed.Spec.HostGrants {
		if grant.Controller == slot && slices.Contains(grant.Roles, "ts-auth") {
			return bootstrapstart.ReadControllerHostRecipient(ctx, source.binding.reader, source.binding.accepted, source.pins[1].wire, grant.Node, instanceID, grant.PrivateIP)
		}
	}
	return nil, ErrControllerActivationPending
}

func (source *controllerNodeSource) read(ctx context.Context, origin, nodeID string, activation bool) (_ *controllerActivationAdmission, _ *api.Node, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	cancels := []context.CancelFunc{cancel}
	release := func() {
		for _, stop := range slices.Backward(cancels) {
			stop()
		}
	}
	defer func() {
		if retErr != nil {
			release()
		}
	}()
	capAt := func(deadline time.Time) {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		cancels = append(cancels, stop)
	}
	if err := source.live(ctx); err != nil {
		return nil, nil, err
	}
	candidate, err := source.node.ReadManagerRuntimeCandidate(ctx, source.hosts, source.mutations, source.binding, origin)
	if err != nil {
		return nil, nil, err
	}
	capAt(candidate.ExpiresAt())
	control, err := source.node.readControllerActivationControl(ctx, source.binding)
	if err != nil {
		return nil, nil, err
	}
	nodes := control.nodesSnapshot()
	index := slices.IndexFunc(nodes, func(n *api.Node) bool { return n.ID == nodeID })
	if index < 0 {
		return nil, nil, ErrControllerActivationPending
	}
	target := nodes[index]
	slot, instanceID := source.binding.Identity().Slot, source.binding.Identity().InstanceID
	if activation {
		slot, instanceID = target.Spec.Annotations.Name, target.Spec.Annotations.Labels[LabelInstanceID]
	}
	recipient, err := source.recipient(ctx, slot, instanceID)
	if err != nil {
		return nil, nil, err
	}
	capAt(recipient.ExpiresAt())
	session, err := source.hosts.AdmitContainerGenerationSession(ctx, recipient.Node())
	if err != nil {
		return nil, nil, err
	}
	capAt(session.Deadline())
	deadline, ok := source.credentials.Context().Deadline()
	if !ok {
		return nil, nil, ErrControllerActivationPending
	}
	for _, until := range []time.Time{candidate.ExpiresAt(), recipient.ExpiresAt(), session.Deadline()} {
		if until.IsZero() {
			return nil, nil, ErrControllerActivationPending
		}
		if until.Before(deadline) {
			deadline = until
		}
	}
	if until, ok := ctx.Deadline(); !ok {
		return nil, nil, ErrControllerActivationPending
	} else if until.Before(deadline) {
		deadline = until
	}
	admitted := &controllerActivationAdmission{original: ctx, release: release, local: control, binding: source.binding, recipient: recipient, session: session, origin: candidate,
		credentials: source.credentials, js: source.js, stream: source.stream, mutations: source.mutations, pins: source.pins, deadline: deadline}
	admitted.domains, err = recipient.VerifyActivationTopology(ctx)
	if err != nil {
		return nil, nil, err
	}
	admitted.grant, admitted.grantRevision, admitted.enrollmentDeadline, err = admitted.currentEnrollment(ctx)
	if err != nil {
		return nil, nil, err
	}
	if admitted.enrollmentDeadline.Before(admitted.deadline) {
		admitted.deadline = admitted.enrollmentDeadline
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, nil, err
	}
	return admitted, target, nil
}

func (admitted *controllerActivationAdmission) constraints(operation string, target *api.Node) (manager.ControllerNodeConstraints, error) {
	targetHash, err := manager.ControllerNodeTargetSHA256(target)
	if err != nil {
		return manager.ControllerNodeConstraints{}, err
	}
	type pin struct {
		Bucket, Key, SHA256 string
		Sequence            uint64
	}
	pins := make([]pin, len(admitted.pins))
	for i, current := range admitted.pins {
		digest := sha256.Sum256(current.wire)
		pins[i] = pin{current.bucket, current.key, hex.EncodeToString(digest[:]), current.sequence}
	}
	wire, err := json.Marshal(struct {
		Pins            []pin
		Binding, Source string
		Epoch           uint64
	}{pins, admitted.origin.BindingSHA256(), admitted.origin.SourceSHA256(), admitted.origin.LeaseEpoch()}, json.Deterministic(true))
	if err != nil {
		return manager.ControllerNodeConstraints{}, err
	}
	digest := sha256.Sum256(append([]byte("terrascale.controller-node-source.v1\x00"), wire...))
	return manager.ControllerNodeConstraints{Operation: operation, LeaseEpoch: admitted.origin.LeaseEpoch(), RaftTerm: admitted.local.observation.Term, RaftLeader: admitted.local.observation.Leader, TargetSHA256: targetHash, SourceSHA256: hex.EncodeToString(digest[:])}, nil
}

func (source *controllerNodeSource) UpdateControllerNode(ctx context.Context, origin string, request *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	ctx, cancelSource, err := source.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancelSource()
	constraints, err := manager.ControllerNodeConstraintsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.NodeVersion == nil || request.Spec == nil {
		return nil, ErrControllerActivationPending
	}
	admitted, target, err := source.read(ctx, origin, request.NodeID, constraints.Operation == manager.ControllerNodeActivate)
	if err != nil {
		return nil, err
	}
	defer admitted.release()
	exact, err := admitted.constraints(constraints.Operation, target)
	if err != nil || exact != constraints || *request.NodeVersion != target.Meta.Version {
		return nil, ErrControllerActivationPending
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	stop := context.AfterFunc(source.original, cancel)
	defer cancel()
	defer stop()
	ctx = admitted.requestContext(ctx)
	if constraints.Operation == manager.ControllerNodeRetire {
		proof, err := admitted.recipient.ReadManagerRetirement(ctx, target.Spec.Annotations.Name, target.Spec.Annotations.Labels[LabelInstanceID])
		if err != nil {
			return nil, err
		}
		if err := admitted.guard(ctx); err != nil {
			return nil, err
		}
		return source.node.updateControllerRetirementAtConstraints(ctx, proof, &constraints, request)
	}
	spec := target.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	if !proto.Equal(spec, request.Spec) {
		return nil, ErrControllerActivationPending
	}
	updated, err := admitted.activate(ctx, target.ID, target.Meta.Version.Index)
	if err != nil {
		return nil, err
	}
	return &api.UpdateNodeResponse{Node: updated}, nil
}

func (source *controllerNodeSource) RemoveControllerNode(ctx context.Context, origin string, request *api.RemoveNodeRequest) (*api.RemoveNodeResponse, error) {
	ctx, cancelSource, err := source.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancelSource()
	constraints, err := manager.ControllerNodeConstraintsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.Force || constraints.Operation != manager.ControllerNodeRetire {
		return nil, ErrControllerActivationPending
	}
	admitted, target, err := source.read(ctx, origin, request.NodeID, false)
	if err != nil {
		return nil, err
	}
	defer admitted.release()
	exact, err := admitted.constraints(constraints.Operation, target)
	if err != nil || exact != constraints {
		return nil, ErrControllerActivationPending
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	defer cancel()
	ctx = admitted.requestContext(ctx)
	proof, err := admitted.recipient.ReadManagerRetirement(ctx, target.Spec.Annotations.Name, target.Spec.Annotations.Labels[LabelInstanceID])
	if err != nil {
		return nil, err
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	// A reconstructed proof cannot continue a prior observation's cleanup.
	return source.node.removeControllerRetirementAtConstraints(ctx, proof, &constraints, request)
}

// ActivateControllerNode uses the existing authenticated native forwarding path.
func (n *Node) ActivateControllerNode(ctx context.Context, nodeID string, expectedVersion, epoch uint64) (*api.Node, error) {
	if n == nil || n.controllerSources.Load() == nil {
		return nil, ErrControllerActivationPending
	}
	source := n.controllerSources.Load()
	ctx, cancelSource, err := source.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancelSource()
	admitted, target, err := source.read(ctx, n.ID(), nodeID, true)
	if err != nil {
		return nil, err
	}
	defer admitted.release()
	if target.Meta.Version.Index != expectedVersion || admitted.origin.LeaseEpoch() != epoch {
		return nil, ErrControllerActivationPending
	}
	constraints, err := admitted.constraints(manager.ControllerNodeActivate, target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	stop := context.AfterFunc(admitted.original, cancel)
	defer cancel()
	defer stop()
	ctx = admitted.requestContext(ctx)
	ctx, err = manager.WithControllerNodeConstraints(ctx, constraints)
	if err != nil {
		return nil, err
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return nil, err
	}
	spec := target.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	if err := ociclient.CheckRequestGuard(ctx); err != nil {
		return nil, err
	}
	response, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: nodeID, NodeVersion: target.Meta.Version.Copy(), Spec: spec})
	if err != nil {
		return nil, errors.Join(manager.ErrMutationAmbiguous, err)
	}
	if response == nil || response.Node == nil {
		return nil, manager.ErrMutationAmbiguous
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, errors.Join(manager.ErrMutationAmbiguous, err)
	}
	return response.Node, nil
}
