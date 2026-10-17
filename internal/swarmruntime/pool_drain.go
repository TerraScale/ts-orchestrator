//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

var ErrPoolDrainPending = errors.New("exact pool child drain evidence is pending")

// CapturePoolDrain pauses the actual worker before retaining every possible
// execution. The caller must commit this capture in the protected own-cell
// record before FinishPoolDrainCapture may request DRAIN.
func (n *Node) CapturePoolDrain(ctx context.Context, child drainwire.PoolChild, source drainwire.PoolSource, specWire, rootWire []byte,
	leases *authority.Reader, hosts *host.Reader,
) (drainwire.PoolReceipt, error) {
	var empty drainwire.PoolReceipt
	if n == nil || n.role != "manager" || leases == nil || hosts == nil || child.Validate() != nil ||
		source.ManagerInstanceID != n.admission.InstanceID || source.ManagerNodeID != n.ID() {
		return empty, ErrPoolDrainPending
	}
	region, err := oci.Region(child.Cell).OCIRegion()
	if err != nil || region != n.admission.Region {
		return empty, ErrPoolDrainPending
	}
	lease, err := leases.AdmitCurrentLease(ctx, source.DeploymentID, source.CandidateID, source.Epoch)
	if err != nil {
		return empty, err
	}
	original := lease.Original()
	if source.OwnerID != original.OwnerID || source.LeaseRevision != original.Revision || source.ExpiresAt.After(original.ExpiresAt) {
		return empty, authority.ErrFenced
	}
	reader, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return empty, err
	}
	nodes, err := reader.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || nodes == nil {
		return empty, errors.Join(ErrPoolDrainPending, err)
	}
	worker, err := poolDrainWorker(nodes.Nodes, child.InstanceID)
	if err != nil {
		return empty, err
	}
	hostNode, err := poolDrainHost(ctx, hosts, worker.Spec.Annotations.Name)
	if err != nil {
		return empty, err
	}
	current, err := hosts.CurrentGenericExecutionSession(ctx, hostNode)
	if err != nil || current.InstanceID != "" && current.InstanceID != child.InstanceID || current.RegistrationID != worker.Spec.Annotations.Name ||
		current.Cell != strings.ToLower(child.Cell) {
		return empty, errors.Join(ErrPoolDrainPending, err)
	}
	current.InstanceID = child.InstanceID
	if worker.Spec.Availability == api.NodeAvailabilityDrain {
		return empty, errors.New("already drained worker has no original protected capture")
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return empty, err
	}
	if err := lease.Guard(ctx); err != nil {
		return empty, err
	}
	if worker.Spec.Availability != api.NodeAvailabilityPause {
		spec := worker.Spec.Copy()
		spec.Availability = api.NodeAvailabilityPause
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: worker.ID, NodeVersion: &worker.Meta.Version, Spec: spec}); err != nil {
			return empty, err
		}
	}
	cluster, err := reader.ClusterIdentity(ctx)
	if err != nil || cluster == nil {
		return empty, errors.Join(ErrPoolDrainPending, err)
	}
	tasks, err := reader.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{worker.ID}}})
	if err != nil || tasks == nil || len(tasks.Tasks) > drainwire.MaxDrainTasks {
		return empty, errors.Join(ErrPoolDrainPending, err)
	}
	history, err := leases.ListGenericExecutions(ctx)
	if err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	deadline := source.ExpiresAt
	if current.ExpiresAt.Before(deadline) {
		deadline = current.ExpiresAt
	}
	if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	receipt := drainwire.PoolReceipt{Child: child, Source: source, Host: current, NodeID: worker.ID,
		CellSpecWire: bytes.Clone(specWire), RootChainWire: bytes.Clone(rootWire),
		ClusterID: cluster.ID, ClusterCAPEM: bytes.Clone(cluster.RootCACert), WorkerCertificate: bytes.Clone(worker.Certificate.Certificate),
		CapturedAt: now, ExpiresAt: deadline, Phase: drainwire.PoolCaptured}
	for _, node := range nodes.Nodes {
		if node != nil && node.Role == api.NodeRoleManager && node.Spec.Membership == api.NodeMembershipAccepted {
			receipt.ManagerCertificates = append(receipt.ManagerCertificates, bytes.Clone(node.Certificate.Certificate))
		}
	}
	for _, task := range tasks.Tasks {
		captured, err := poolDrainTask(task, worker.ID)
		if err != nil {
			return empty, err
		}
		receipt.Tasks = append(receipt.Tasks, captured)
	}
	slices.SortFunc(receipt.Tasks, func(a, b drainwire.PoolTask) int { return strings.Compare(a.TaskID, b.TaskID) })
	for _, signed := range history {
		if signed.Hold.InstanceID != child.InstanceID {
			continue
		}
		if err := verifyPoolHeldExecution(receipt, signed, now); err != nil {
			return empty, err
		}
		receipt.Holds = append(receipt.Holds, signed)
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return empty, err
		}
		hold := signed.Hold
		receipt.Challenges = append(receipt.Challenges, drainwire.DrainStopChallenge{
			Cell: hold.Cell, HostNode: hold.HostNode, RegistrationID: hold.RegistrationID, InstanceID: hold.InstanceID,
			HostSessionID: hold.HostSessionID, RegistrationGeneration: hold.RegistrationGeneration, HostEpoch: hold.HostEpoch,
			OriginalEpoch: hold.OriginalEpoch, Epoch: source.Epoch, ExecutionSessionID: hold.ExecutionSessionID,
			BirthOperationID: child.BirthOperationID, RemovalOperationID: child.RemovalOperationID,
			NodeID: hold.NodeID, TaskID: hold.TaskID, ServiceID: hold.ServiceID, TaskSHA256: hold.TaskSHA256,
			ExecutionSHA256: hold.ExecutionSHA256, Nonce: hex.EncodeToString(nonce[:]), IssuedAt: now, Deadline: deadline})
	}
	if err := receipt.Validate(); err != nil {
		return empty, err
	}
	if err := n.checkPoolDrain(ctx, receipt, leases, hosts, api.NodeAvailabilityPause, false); err != nil {
		return empty, err
	}
	if err := lease.Guard(ctx); err != nil {
		return empty, err
	}
	return receipt, nil
}

// FinishPoolDrainCapture is called only after exact protected CAS readback.
// This method never manufactures a capture for a worker already in DRAIN.
func (n *Node) FinishPoolDrainCapture(ctx context.Context, receipt drainwire.PoolReceipt, leases *authority.Reader, hosts *host.Reader) error {
	if err := n.checkPoolDrain(ctx, receipt, leases, hosts, api.NodeAvailabilityPause, false); err != nil {
		return err
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	worker, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: receipt.NodeID})
	if err != nil || worker == nil || worker.Node == nil {
		return errors.Join(ErrPoolDrainPending, err)
	}
	spec := worker.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: receipt.NodeID, NodeVersion: &worker.Node.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	return n.checkPoolDrain(ctx, receipt, leases, hosts, api.NodeAvailabilityDrain, false)
}

// VerifyPoolDrain checks the original capture against current actual manager,
// exact retained task assignments, host session, raw stop proofs and DATA holds.
// Backend and retained-volume checks additionally run in the root OCI producer.
func (n *Node) VerifyPoolDrain(ctx context.Context, receipt drainwire.PoolReceipt, leases *authority.Reader, hosts *host.Reader) error {
	return n.checkPoolDrain(ctx, receipt, leases, hosts, api.NodeAvailabilityDrain, true)
}

func (n *Node) checkPoolDrain(ctx context.Context, receipt drainwire.PoolReceipt, leases *authority.Reader, hosts *host.Reader,
	availability api.NodeSpec_Availability, stopped bool,
) error {
	if n == nil || n.role != "manager" || ctx == nil || ctx.Err() != nil || leases == nil || hosts == nil ||
		receipt.Validate() != nil || !time.Now().Before(receipt.ExpiresAt) || receipt.Source.ManagerInstanceID != n.admission.InstanceID || receipt.Source.ManagerNodeID != n.ID() {
		return ErrPoolDrainPending
	}
	lease, err := leases.AdmitCurrentLease(ctx, receipt.Source.DeploymentID, receipt.Source.CandidateID, receipt.Source.Epoch)
	if err != nil {
		return errors.Join(ErrPoolDrainPending, err)
	}
	original := lease.Original()
	if original.OwnerID != receipt.Source.OwnerID || original.Revision < receipt.Source.LeaseRevision || original.ExpiresAt.Before(receipt.ExpiresAt) {
		return errors.Join(ErrPoolDrainPending, err)
	}
	current, err := hosts.CurrentGenericExecutionSession(ctx, receipt.Host.HostNode)
	if err != nil || !current.SameIdentity(receipt.Host) || current.ExpiresAt.Before(receipt.ExpiresAt) ||
		current.InstanceID != "" && current.InstanceID != receipt.Child.InstanceID {
		return errors.Join(ErrPoolDrainPending, err)
	}
	reader, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return errors.Join(ErrPoolDrainPending, err)
	}
	cluster, err := reader.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID != receipt.ClusterID || !bytes.Equal(cluster.RootCACert, receipt.ClusterCAPEM) {
		return errors.Join(ErrPoolDrainPending, err)
	}
	nodes, err := reader.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || nodes == nil {
		return errors.Join(ErrPoolDrainPending, err)
	}
	worker, err := poolDrainWorker(nodes.Nodes, receipt.Child.InstanceID)
	if err != nil || worker.ID != receipt.NodeID || worker.Spec.Availability != availability ||
		!bytes.Equal(worker.Certificate.Certificate, receipt.WorkerCertificate) || worker.Spec.Annotations.Name != receipt.Host.RegistrationID {
		return errors.Join(ErrPoolDrainPending, err)
	}
	tasks, err := reader.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{receipt.NodeID}}})
	if err != nil || tasks == nil || len(tasks.Tasks) != len(receipt.Tasks) {
		return errors.Join(ErrPoolDrainPending, err)
	}
	for _, task := range tasks.Tasks {
		actual, err := poolDrainTask(task, receipt.NodeID)
		if err != nil || !slices.Contains(receipt.Tasks, actual) || stopped &&
			(task.Status.State < api.TaskStateCompleted || task.Status.State == api.TaskStateOrphaned) {
			return errors.Join(ErrPoolDrainPending, err)
		}
	}
	history, err := leases.ListGenericExecutions(ctx)
	if err != nil {
		return err
	}
	count := 0
	for _, signed := range history {
		if signed.Hold.InstanceID != receipt.Child.InstanceID {
			continue
		}
		count++
		if !slices.ContainsFunc(receipt.Holds, func(captured drainwire.SignedHold) bool {
			return captured.Hold == signed.Hold && bytes.Equal(captured.Signature, signed.Signature)
		}) {
			return errors.New("worker acquired execution outside its protected drain capture")
		}
	}
	if count != len(receipt.Holds) {
		return errors.New("worker lost retained possible-execution history")
	}
	data, err := leases.ListAllRuntimeEffectHistory(ctx)
	if err != nil {
		return err
	}
	for _, effect := range data {
		if effect.InstanceID == receipt.Child.InstanceID || effect.NodeID == receipt.NodeID || effect.RegistrationID == receipt.Host.RegistrationID {
			return errors.New("pool child has retained DATA execution history")
		}
	}
	if stopped {
		if err := VerifyPoolDrainStops(receipt, time.Now().UTC()); err != nil {
			return err
		}
	}
	if err := lease.Guard(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func poolDrainHost(ctx context.Context, hosts *host.Reader, registrationID string) (string, error) {
	statuses, err := hosts.ListHosts(ctx)
	if err != nil {
		return "", err
	}
	node := ""
	for _, status := range statuses {
		if status.Registration.ID != registrationID {
			continue
		}
		if node != "" || status.Retired || status.Registration.Node == "" {
			return "", ErrPoolDrainPending
		}
		node = status.Registration.Node
	}
	if node == "" {
		return "", ErrPoolDrainPending
	}
	return node, nil
}

func poolDrainWorker(nodes []*api.Node, instanceID string) (*api.Node, error) {
	var found *api.Node
	for _, node := range nodes {
		if node == nil || node.Spec.Annotations.Labels[LabelInstanceID] != instanceID {
			continue
		}
		if found != nil || node.Role != api.NodeRoleWorker || node.Spec.DesiredRole != api.NodeRoleWorker ||
			node.Spec.Membership != api.NodeMembershipAccepted || node.Spec.Annotations.Name == "" ||
			node.Status.State != api.NodeStatus_READY || len(node.Certificate.Certificate) == 0 {
			return nil, ErrPoolDrainPending
		}
		found = node
	}
	if found == nil {
		return nil, ErrPoolDrainPending
	}
	return found, nil
}

func poolDrainTask(task *api.Task, nodeID string) (drainwire.PoolTask, error) {
	if task == nil || task.NodeID != nodeID || task.Annotations.Labels[LabelRole] == "terrabase" || task.ServiceAnnotations.Labels[LabelRole] == "terrabase" {
		return drainwire.PoolTask{}, ErrPoolDrainPending
	}
	if _, present := task.Annotations.Labels["terrascale.stateful"]; present {
		return drainwire.PoolTask{}, ErrPoolDrainPending
	}
	if _, present := task.ServiceAnnotations.Labels["terrascale.stateful"]; present {
		return drainwire.PoolTask{}, ErrPoolDrainPending
	}
	hash, err := executionwire.TaskSHA256(task)
	if err != nil {
		return drainwire.PoolTask{}, err
	}
	fingerprint, err := ContainerTaskFingerprint(task)
	return drainwire.PoolTask{TaskID: task.ID, ServiceID: task.ServiceID, TaskSHA256: hash, ExecutionSHA256: fingerprint}, err
}

func verifyPoolHeldExecution(receipt drainwire.PoolReceipt, hold drainwire.SignedHold, now time.Time) error {
	if hold.Hold.NodeID != receipt.NodeID || hold.Hold.RegistrationID != receipt.Host.RegistrationID ||
		!slices.ContainsFunc(receipt.Tasks, func(task drainwire.PoolTask) bool {
			return task.TaskID == hold.Hold.TaskID && task.ServiceID == hold.Hold.ServiceID &&
				task.TaskSHA256 == hold.Hold.TaskSHA256 && task.ExecutionSHA256 == hold.Hold.ExecutionSHA256
		}) || len(hold.CertificateChain) == 0 {
		return errors.New("retained possible execution has no exact captured manager task")
	}
	for _, certificate := range receipt.ManagerCertificates {
		if drainwire.VerifySignedHold(hold, certificate, receipt.ClusterCAPEM, receipt.ClusterID, now) == nil {
			return nil
		}
	}
	return errors.New("retained execution hold has no actual admitted manager signing key")
}

// VerifyPoolDrainStops is also used by HOME after its independent SDK read of
// the protected target-cell receipt. It grants no authority to an inert DTO.
func VerifyPoolDrainStops(receipt drainwire.PoolReceipt, now time.Time) error {
	return drainwire.VerifyPoolReceiptStops(receipt, now)
}
