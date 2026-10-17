package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
)

// WorkerMembershipInfo is inert transport for the authenticated root bridge.
// Only that bridge or the concrete live reader can construct the opaque proof.
type WorkerMembershipInfo struct {
	NodeID, RegistrationID, InstanceID, Region, Cell, Role, Architecture, PrivateIP string
	PublicKey, NATSUserPublicKey                                                    string
	Generation, Revision                                                            uint64
	ObservedAt, ExpiresAt                                                           time.Time
}

type VerifiedWorkerMembership struct{ info WorkerMembershipInfo }

func (v VerifiedWorkerMembership) NodeID() string             { return v.info.NodeID }
func (v VerifiedWorkerMembership) RegistrationID() string     { return v.info.RegistrationID }
func (v VerifiedWorkerMembership) InstanceID() string         { return v.info.InstanceID }
func (v VerifiedWorkerMembership) OCIRegion() string          { return v.info.Region }
func (v VerifiedWorkerMembership) Cell() string               { return v.info.Cell }
func (v VerifiedWorkerMembership) Role() string               { return v.info.Role }
func (v VerifiedWorkerMembership) Architecture() string       { return v.info.Architecture }
func (v VerifiedWorkerMembership) PrivateIP() string          { return v.info.PrivateIP }
func (v VerifiedWorkerMembership) Info() WorkerMembershipInfo { return v.info }

func (v VerifiedWorkerMembership) Validate() error {
	i := v.info
	now := time.Now()
	if i.NodeID == "" || !entityid.Valid(i.RegistrationID) || i.InstanceID == "" || i.Region == "" || i.Cell == "" ||
		i.Role != "container" && i.Role != "wasm" || i.Architecture != "amd64" && i.Architecture != "arm64" || i.PrivateIP == "" ||
		i.PublicKey == "" || i.NATSUserPublicKey == "" || i.Generation == 0 || i.Revision == 0 || i.ObservedAt.IsZero() ||
		i.ObservedAt.After(now.Add(time.Second)) || !now.Before(i.ExpiresAt) || !i.ObservedAt.Before(i.ExpiresAt) || i.ExpiresAt.Sub(i.ObservedAt) > 30*time.Second {
		return errors.New("current worker membership proof unavailable or expired")
	}
	return nil
}

// verifiedWorkerMembership is deliberately package-private: management clients
// may wrap only replies from the existing authenticated root process bridge.
func verifiedWorkerMembership(info WorkerMembershipInfo) (VerifiedWorkerMembership, error) {
	proof := VerifiedWorkerMembership{info: info}
	return proof, proof.Validate()
}

// ReadWorkerMembership independently verifies current ordered membership, OCI
// state and actual Swarm identity. An old signed enrollment alone cannot pass.
func (n *Node) ReadWorkerMembership(ctx context.Context, nodeID string) (VerifiedWorkerMembership, error) {
	return n.readWorkerMembership(ctx, nodeID, nil)
}

func (n *Node) readWorkerMembership(ctx context.Context, nodeID string, source *hostenroll.WorkerMembershipSource) (VerifiedWorkerMembership, error) {
	fail := func(err error) (VerifiedWorkerMembership, error) { return VerifiedWorkerMembership{}, err }
	if n == nil || n.workerAuthority == nil || n.workerAuthority.observer == nil {
		return fail(errors.New("worker membership requires admitted regional authority"))
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return fail(err)
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return fail(err)
	}
	if node.Node.Role != api.NodeRoleWorker || node.Node.Spec.Availability == api.NodeAvailabilityDrain || !entityid.Valid(node.Node.Spec.Annotations.Name) || node.Node.Spec.Annotations.Labels[LabelInstanceID] == "" {
		return fail(errors.New("worker membership has no admitted worker locator"))
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		return fail(errors.New("worker membership requires one actual regional cluster"))
	}
	snapshot, err := readWorkerMembershipSource(ctx, source, WorkerMembershipQuery{NodeID: nodeID, RegistrationID: node.Node.Spec.Annotations.Name, InstanceID: node.Node.Spec.Annotations.Labels[LabelInstanceID]})
	if err != nil {
		return fail(err)
	}
	operation, err := n.beginWorkerMembership(ctx, snapshot)
	if err != nil {
		return fail(err)
	}
	defer operation.close()
	availability, revoke, err := n.workerMembershipDisposition(ctx, node.Node, clusters.Clusters[0], snapshot, operation)
	if err != nil || revoke || availability != api.NodeAvailabilityActive {
		return fail(errors.New("worker membership is not independently current"))
	}
	ctx, cancel := operation.boundedContext(ctx)
	defer cancel()
	if _, err := n.confirmWorkerMembershipSource(ctx, client, node.Node, clusters.Clusters[0], snapshot, source, operation); err != nil {
		return fail(err)
	}
	verified, err := hostenroll.VerifySwarmMembership(*snapshot.Admission, n.workerAuthority.public)
	if err != nil {
		return fail(err)
	}
	w := verified.Worker()
	if err := operation.revalidate(ctx); err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	expires := operation.expiresAt(now.Add(30 * time.Second))
	return verifiedWorkerMembership(WorkerMembershipInfo{NodeID: nodeID, RegistrationID: w.RegistrationID, InstanceID: w.InstanceID,
		Region: w.Region, Cell: w.Cell, Role: w.Role, Architecture: w.Architecture, PrivateIP: w.PrivateIP,
		PublicKey: snapshot.Registration.PublicKey, NATSUserPublicKey: snapshot.Registration.NATSUserPublicKey,
		Generation: snapshot.Registration.Generation, Revision: snapshot.Sequence, ObservedAt: now, ExpiresAt: expires})
}

// WorkerMembershipQuery contains locators, never authority. Admission is present
// only when publishing the just-verified dual-key admission before placement.
type WorkerMembershipQuery = hostenroll.WorkerMembershipQuery

// WorkerMembershipSnapshot comes from the fixed service-account child reading
// the ordered registration/retirement log and the existing instance grant.
type WorkerMembershipSnapshot = hostenroll.WorkerMembershipSnapshot

func readWorkerMembershipSource(ctx context.Context, source *hostenroll.WorkerMembershipSource, query WorkerMembershipQuery) (WorkerMembershipSnapshot, error) {
	if source != nil {
		return source.Read(ctx, query)
	}
	return readCurrentWorkerMembership(ctx, query)
}

func readCurrentWorkerMembership(ctx context.Context, query WorkerMembershipQuery) (WorkerMembershipSnapshot, error) {
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return WorkerMembershipSnapshot{}, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return WorkerMembershipSnapshot{}, errors.New("worker membership requires the controller service account")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return WorkerMembershipSnapshot{}, errors.New("worker membership requires the controller service group")
	}
	wire, err := protocol.EncodeJSON(query)
	if err != nil || len(wire) > 128<<10 {
		return WorkerMembershipSnapshot{}, errors.New("worker membership query oversized")
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(childCtx, "/proc/self/exe", "runtime-worker-membership-source")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	command.Stdin = bytes.NewReader(wire)
	var output workerSourceOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return WorkerMembershipSnapshot{}, errors.New("current worker membership source unavailable")
	}
	var snapshot WorkerMembershipSnapshot
	if err := json.Unmarshal(output.data, &snapshot, json.RejectUnknownMembers(true)); err != nil {
		return WorkerMembershipSnapshot{}, err
	}
	return snapshot, nil
}

// AuditWorkerMembership pauses new placements on unavailable evidence, preserving
// running tasks. Only independently verified revocation drains a worker.
func (n *Node) AuditWorkerMembership(ctx context.Context) error {
	if n == nil || n.workerAuthority == nil || n.workerAuthority.observer == nil {
		return errors.New("worker membership audit requires admitted regional authority")
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	clusters, clusterErr := client.ListClusters(ctx, &api.ListClustersRequest{})
	var cluster *api.Cluster
	if clusterErr == nil && len(clusters.Clusters) == 1 {
		cluster = clusters.Clusters[0]
	}
	var failures []error
	if cluster == nil {
		failures = append(failures, errors.New("worker membership audit lacks one current regional cluster"))
	}
	for _, node := range nodes.Nodes {
		if node.Role == api.NodeRoleManager {
			continue
		}
		availability, revoke := api.NodeAvailabilityPause, false
		var operation *workerOperation
		query := WorkerMembershipQuery{NodeID: node.ID, RegistrationID: node.Spec.Annotations.Name, InstanceID: node.Spec.Annotations.Labels[LabelInstanceID]}
		if cluster != nil && entityid.Valid(query.RegistrationID) && query.InstanceID != "" {
			snapshot, err := readCurrentWorkerMembership(ctx, query)
			if err == nil {
				operation, err = n.beginWorkerMembership(ctx, snapshot)
			}
			if err == nil {
				availability, revoke, err = n.workerMembershipDisposition(ctx, node, cluster, snapshot, operation)
				if err == nil {
					node, err = n.confirmWorkerMembershipSource(ctx, client, node, cluster, snapshot, nil, operation)
					if err != nil {
						availability, revoke = api.NodeAvailabilityPause, false
					}
				}
			}
			if err != nil {
				failures = append(failures, err)
			}
		}
		if availability == api.NodeAvailabilityActive {
			if err := operation.revalidate(ctx); err != nil {
				availability, revoke = api.NodeAvailabilityPause, false
				failures = append(failures, err)
			}
		}
		guarded := client
		if availability == api.NodeAvailabilityActive && operation != nil {
			guarded = workerControlClient{ControlClient: client, operation: operation}
		}
		if err := updateWorkerMembership(ctx, guarded, node, availability, revoke); err != nil {
			failures = append(failures, err)
		}
		operation.close()
	}
	return errors.Join(failures...)
}

func (n *Node) confirmWorkerMembershipSource(ctx context.Context, client api.ControlClient, node *api.Node, cluster *api.Cluster, snapshot WorkerMembershipSnapshot, source *hostenroll.WorkerMembershipSource, operation *workerOperation) (*api.Node, error) {
	confirmed, err := readWorkerMembershipSource(ctx, source, WorkerMembershipQuery{NodeID: node.ID, RegistrationID: node.Spec.Annotations.Name, InstanceID: node.Spec.Annotations.Labels[LabelInstanceID]})
	if err != nil {
		return node, err
	}
	expected, err := json.Marshal(snapshot, json.Deterministic(true))
	actual, actualErr := json.Marshal(confirmed, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return node, errors.New("worker membership changed during current OCI and Vault reads")
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID})
	if err != nil {
		return node, err
	}
	if current.Node.Role != api.NodeRoleWorker || !bytes.Equal(current.Node.Certificate.Certificate, node.Certificate.Certificate) ||
		current.Node.Spec.Annotations.Name != node.Spec.Annotations.Name || current.Node.Spec.Annotations.Labels[LabelInstanceID] != node.Spec.Annotations.Labels[LabelInstanceID] ||
		current.Node.Spec.Availability == api.NodeAvailabilityDrain && node.Spec.Availability != api.NodeAvailabilityDrain {
		return current.Node, errors.New("actual worker identity or placement changed during membership audit")
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 || clusters.Clusters[0].ID != cluster.ID || !bytes.Equal(clusters.Clusters[0].RootCA.CACert, cluster.RootCA.CACert) {
		return current.Node, errors.New("actual regional worker root changed during membership audit")
	}
	if err := n.workerAuthority.refresh(ctx); err != nil {
		return current.Node, err
	}
	if err := operation.revalidate(ctx); err != nil {
		return current.Node, err
	}
	return current.Node, nil
}

func (n *Node) workerMembershipDisposition(ctx context.Context, node *api.Node, cluster *api.Cluster, snapshot WorkerMembershipSnapshot, operation *workerOperation) (api.NodeSpec_Availability, bool, error) {
	pause := func(err error) (api.NodeSpec_Availability, bool, error) { return api.NodeAvailabilityPause, false, err }
	if err := n.workerAuthority.refresh(ctx); err != nil {
		return pause(err)
	}
	if snapshot.Admission == nil || snapshot.Sequence == 0 || snapshot.GrantRevision == 0 {
		return pause(errors.New("worker membership lacks retained admission or current ordered evidence"))
	}
	verified, err := hostenroll.VerifySwarmMembership(*snapshot.Admission, n.workerAuthority.public)
	if err != nil {
		return pause(err)
	}
	worker := verified.Worker()
	if snapshot.Admission.Binding.NodeID != node.ID || worker.InstanceID != snapshot.GrantInstanceID ||
		worker.RegistrationID != node.Spec.Annotations.Name || worker.InstanceID != node.Spec.Annotations.Labels[LabelInstanceID] {
		return pause(errors.New("worker membership locators differ from authenticated retained admission"))
	}
	identity := n.workerAuthority.identity
	if worker.DeploymentID != identity.DeploymentID || worker.ClusterID != identity.ClusterID || worker.Environment != identity.Environment ||
		worker.Region != identity.OCIRegion || worker.OCIRegion != identity.OCIRegion || worker.FounderID != identity.SeedSlot || worker.SwarmID != cluster.ID {
		return pause(errors.New("worker membership belongs to another admitted region or cluster"))
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(snapshot.Admission.Transport.Request, snapshot.Admission.Binding.IssuedAt)
	if err != nil {
		return pause(err)
	}
	registration := snapshot.Registration
	role := "container"
	for _, granted := range registration.Roles {
		if granted == "function-worker" {
			if len(registration.Roles) != 1 {
				return api.NodeAvailabilityDrain, true, nil
			}
			role = "wasm"
		}
	}
	if snapshot.Retired || snapshot.Disabled || snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" ||
		registration.ID != worker.RegistrationID || registration.ID != entityid.Derive("host", descriptor.Cell, descriptor.Node) ||
		registration.Cell != worker.Cell || registration.Node != descriptor.Node || registration.Environment != worker.Environment ||
		registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != worker.Generation || snapshot.Sequence != worker.Revision || len(registration.Roles) == 0 || role != worker.Role ||
		registration.ManagedOCI != nil && (registration.ManagedOCI.InstanceID != worker.InstanceID || !strings.EqualFold(registration.ManagedOCI.Region, identity.Cell)) {
		return api.NodeAvailabilityDrain, true, nil
	}
	if err := operation.requireBindings(ctx, descriptor, worker.InstanceID, registration); err != nil {
		return pause(err)
	}
	ctx, cancel := operation.boundedContext(ctx)
	defer cancel()
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil {
		return pause(errors.New("actual upstream worker certificate missing"))
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(cluster.RootCA.CACert) || certificate.Subject.CommonName != node.ID ||
		len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != cluster.ID ||
		len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != "swarm-worker" {
		return pause(errors.New("actual worker certificate differs from current regional cluster"))
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return pause(err)
	}
	lifecycle, err := n.workerAuthority.observer.ObserveLifecycle(ctx, worker.InstanceID)
	if err != nil {
		return pause(err)
	}
	if lifecycle == "TERMINATED" || lifecycle == "TERMINATING" {
		return api.NodeAvailabilityDrain, true, nil
	}
	if lifecycle != "RUNNING" {
		return pause(errors.New("worker OCI instance is temporarily unavailable"))
	}
	observed, err := n.workerAuthority.observer.ObserveInstance(ctx, worker.InstanceID)
	if err != nil {
		return pause(err)
	}
	if observed.InstanceOCID != worker.InstanceID || observed.PrimaryPrivateIP != worker.PrivateIP || !observed.PrimaryVNIC ||
		!descriptor.IsStatic() && observed.ImageOCID != descriptor.ImageID || observed.LifecycleState == "TERMINATED" || observed.LifecycleState == "TERMINATING" {
		return api.NodeAvailabilityDrain, true, nil
	}
	if observed.LifecycleState != "RUNNING" {
		return pause(errors.New("worker OCI instance is temporarily unavailable"))
	}
	architecture, err := n.workerAuthority.observer.ObserveWorkerArchitecture(ctx, observed)
	if err != nil {
		return pause(err)
	}
	if err := operation.requireObservation(ctx, descriptor, observed, role, architecture); err != nil {
		return pause(err)
	}
	if architecture != worker.Architecture {
		return api.NodeAvailabilityDrain, true, nil
	}
	if n.workerAuthority.bundles == nil {
		return pause(errors.New("current worker Vault source unavailable"))
	}
	name := vaultsecret.Name(strings.ToLower(identity.Cell)+"-"+strings.ToLower(identity.ClusterID)+"-"+strings.ToLower(worker.RegistrationID)+"-"+worker.SecretSHA256, "TS_ORCHESTRATOR_SWARM_WORKER")
	version, err := vaultsecret.ReadVersioned(ctx, n.workerAuthority.bundles, n.workerAuthority.target.VaultID, name)
	if err != nil || version.SecretID != worker.SecretID || version.Number != worker.SecretVersion {
		return pause(errors.New("current worker Vault evidence unavailable or changed"))
	}
	digest := sha256.Sum256([]byte(version.Value))
	if hex.EncodeToString(digest[:]) != worker.SecretSHA256 {
		return pause(errors.New("current worker Vault material differs from retained admission"))
	}
	if err := n.workerAuthority.refresh(ctx); err != nil {
		return pause(err)
	}
	if err := operation.revalidate(ctx); err != nil {
		return pause(err)
	}
	return api.NodeAvailabilityActive, false, nil
}

func updateWorkerMembership(ctx context.Context, client api.ControlClient, node *api.Node, availability api.NodeSpec_Availability, revoke bool) error {
	if node == nil || node.Role != api.NodeRoleWorker {
		return errors.New("worker membership cannot update a manager")
	}
	spec := node.Spec.Copy()
	if spec.Availability == api.NodeAvailabilityDrain && !revoke {
		return nil
	}
	spec.Availability = availability
	if revoke {
		for _, label := range []string{LabelRegion, LabelHostRole, LabelInstanceID, LabelExecutionScope} {
			delete(spec.Annotations.Labels, label)
		}
	}
	if spec.Availability == node.Spec.Availability && !revoke {
		return nil
	}
	_, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	return err
}
