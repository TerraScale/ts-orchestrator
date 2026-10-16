package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// WorkerRegistrationQuery retains exact existing signed enrollment bytes.
type WorkerRegistrationQuery struct {
	Request  []byte                  `json:"request"`
	Response []byte                  `json:"response"`
	Swarm    *hostenroll.SwarmWorker `json:"swarm,omitempty"`
}

// WorkerRegistrationSnapshot is emitted only by the fixed service-account child
// after current ordered registration and retirement reads.
type WorkerRegistrationSnapshot struct {
	Registration  host.Registration `json:"registration"`
	Sequence      uint64            `json:"sequence"`
	Retired       bool              `json:"retired"`
	RequestSHA256 string            `json:"request_sha256"`
	InstanceID    string            `json:"instance_id"`
	Response      []byte            `json:"response,omitempty"`
}

type workerAuthority struct {
	identity    bootstrapstart.RuntimeIdentity
	public      ed25519.PublicKey
	target      vaultsecret.Target
	vault       vaultsecret.VaultClient
	bundles     vaultsecret.BundleClient
	observer    *bootstrapstart.OCIInstanceObserver
	refresh     func(context.Context) error
	homeIAM     *region.HomeIAMAuthority
	foundations region.FoundationResolver
}

func readCurrentWorkerRegistration(ctx context.Context, query WorkerRegistrationQuery) (WorkerRegistrationSnapshot, error) {
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return WorkerRegistrationSnapshot{}, errors.New("worker source requires the controller service account")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return WorkerRegistrationSnapshot{}, errors.New("worker source requires the controller service group")
	}
	wire, err := protocol.EncodeJSON(query)
	if err != nil || len(wire) > 128<<10 {
		return WorkerRegistrationSnapshot{}, errors.New("worker enrollment query oversized")
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(childCtx, "/proc/self/exe", "runtime-worker-admission-source")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	command.Stdin = bytes.NewReader(wire)
	var output workerSourceOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return WorkerRegistrationSnapshot{}, errors.New("current worker registration source unavailable")
	}
	var snapshot WorkerRegistrationSnapshot
	if err := json.Unmarshal(output.data, &snapshot, json.RejectUnknownMembers(true)); err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	return snapshot, nil
}

type workerSourceOutput struct{ data []byte }

func (output *workerSourceOutput) Write(data []byte) (int, error) {
	if len(output.data)+len(data) > 128<<10 {
		return 0, errors.New("worker source result oversized")
	}
	output.data = append(output.data, data...)
	return len(data), nil
}

func (authority *workerAuthority) current(ctx context.Context, query WorkerRegistrationQuery) (hostenroll.Request, hostenroll.Response, host.Registration, bootstrapstart.InstanceObservation, string, error) {
	fail := func(err error) (hostenroll.Request, hostenroll.Response, host.Registration, bootstrapstart.InstanceObservation, string, error) {
		return hostenroll.Request{}, hostenroll.Response{}, host.Registration{}, bootstrapstart.InstanceObservation{}, "", err
	}
	if authority == nil || authority.observer == nil {
		return fail(errors.New("worker admission source unavailable"))
	}
	if err := authority.refresh(ctx); err != nil {
		return fail(err)
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	response, err := hostenroll.VerifyResponse(query.Response, authority.public, request, query.Request, descriptor)
	if err != nil {
		return fail(err)
	}
	if !strings.EqualFold(descriptor.Region, authority.identity.Cell) {
		return fail(errors.New("worker enrollment differs from regional manager authority"))
	}
	current, err := readCurrentWorkerRegistration(ctx, query)
	if err != nil {
		return fail(err)
	}
	registration := current.Registration
	if current.Retired || current.RequestSHA256 != hostenroll.RequestSHA256(query.Request) || current.InstanceID != request.InstanceID ||
		registration.ID != entityid.Derive("host", descriptor.Cell, descriptor.Node) || registration.Cell != descriptor.Cell || registration.Node != descriptor.Node ||
		registration.Environment != authority.identity.Environment || registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != response.RegistrationReceipt.Generation || current.Sequence != response.RegistrationReceipt.Revision {
		return fail(errors.New("worker enrollment differs from current registered identity or generation"))
	}
	if len(registration.Roles) == 0 {
		return fail(errors.New("worker registration grants no execution role"))
	}
	role := "container"
	for _, granted := range registration.Roles {
		if granted == "function-worker" {
			if len(registration.Roles) != 1 {
				return fail(errors.New("WASM worker must be dedicated to tenant execution"))
			}
			role = "wasm"
		}
	}
	observed, err := authority.observer.ObserveInstance(ctx, request.InstanceID)
	if err != nil {
		return fail(err)
	}
	if !observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
		return fail(errors.New("worker instance is not running at its attached primary address"))
	}
	if registration.ManagedOCI != nil && (registration.ManagedOCI.InstanceID != request.InstanceID || !strings.EqualFold(registration.ManagedOCI.Region, authority.identity.Cell)) {
		return fail(errors.New("current registration differs from observed OCI recipient"))
	}
	if !descriptor.IsStatic() && descriptor.ImageID != observed.ImageOCID {
		return fail(errors.New("worker image differs from admitted launch"))
	}
	architecture, err := authority.observer.ObserveWorkerArchitecture(ctx, observed)
	if err != nil {
		return fail(err)
	}
	return request, response, registration, observed, role + ":" + architecture, nil
}

// PrepareEnrolledWorker publishes only a recipient-bound worker token after the
// current signed enrollment, ordered registration and OCI state agree.
func (n *Node) PrepareEnrolledWorker(ctx context.Context, query WorkerRegistrationQuery) ([]byte, error) {
	if query.Swarm != nil {
		return nil, errors.New("worker projection is derived only by the root manager")
	}
	authority := n.workerAuthority
	request, response, registration, observed, execution, err := authority.current(ctx, query)
	if err != nil {
		return nil, err
	}
	role, architecture, _ := strings.Cut(execution, ":")
	client, err := n.ControlClient(ctx)
	if err != nil {
		return nil, err
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		return nil, errors.New("worker source requires one current regional upstream cluster")
	}
	cluster := clusters.Clusters[0]
	material := workerJoinMaterial{Version: 1, DeploymentID: authority.identity.DeploymentID, ClusterID: authority.identity.ClusterID, Environment: authority.identity.Environment,
		Region: authority.identity.OCIRegion, FounderID: authority.identity.SeedSlot, RegistrationID: registration.ID, InstanceID: request.InstanceID, Role: role, Architecture: architecture,
		SwarmID: cluster.ID, CAPEM: string(cluster.RootCA.CACert), ManagerAddress: net.JoinHostPort(authority.identity.SeedPrivateIP, swarmManagerPort), WorkerToken: cluster.RootCA.JoinTokens.Worker}
	wire, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	// Replacement instances and rotated upstream tokens need separate immutable records.
	digest := sha256.Sum256(wire)
	name := vaultsecret.Name(strings.ToLower(authority.identity.Cell)+"-"+strings.ToLower(authority.identity.ClusterID)+"-"+strings.ToLower(registration.ID)+"-"+hex.EncodeToString(digest[:]), "TS_ORCHESTRATOR_SWARM_WORKER")
	stored, err := vaultsecret.Ensure(ctx, authority.vault, authority.target, name, "Recipient-bound SwarmKit worker enrollment", func(ctx context.Context) (string, error) {
		if err := authority.refresh(ctx); err != nil {
			return "", err
		}
		return string(wire), nil
	})
	if err != nil {
		return nil, errors.New("store recipient worker Vault material failed")
	}
	readback, err := vaultsecret.ReadBack(ctx, authority.bundles, authority.target.VaultID, name, stored.Created || stored.Provisioning)
	if err != nil || readback != string(wire) {
		return nil, errors.New("recipient worker Vault material differs from current upstream cluster")
	}
	version, err := vaultsecret.ReadVersioned(ctx, authority.bundles, authority.target.VaultID, name)
	if err != nil || version.SecretID != stored.ID || version.Value != string(wire) {
		return nil, errors.New("recipient worker Vault version differs from current upstream cluster")
	}
	if _, _, _, _, _, err := authority.current(ctx, query); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := minTime(now.Add(10*time.Minute), response.ExpiresAt)
	worker := hostenroll.SwarmWorker{Version: 1, DeploymentID: material.DeploymentID, ClusterID: material.ClusterID, Environment: material.Environment, Cell: registration.Cell, Region: material.Region,
		OCIRegion: authority.identity.OCIRegion, FounderID: material.FounderID, RegistrationID: registration.ID, Generation: registration.Generation, Revision: response.RegistrationReceipt.Revision,
		InstanceID: request.InstanceID, PrivateIP: observed.PrimaryPrivateIP, Architecture: architecture, Role: role, ManagerAddress: material.ManagerAddress, SwarmID: material.SwarmID, CAPEM: material.CAPEM,
		SecretID: stored.ID, SecretVersion: version.Number, SecretSHA256: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: expires}
	if err := worker.Validate(now); err != nil {
		return nil, err
	}
	signingQuery := query
	signingQuery.Swarm = &worker
	signed, err := readCurrentWorkerRegistration(ctx, signingQuery)
	if err != nil {
		return nil, err
	}
	transport, err := protocol.EncodeJSON(hostenroll.WorkerTransport{Request: query.Request, Response: signed.Response})
	if err != nil {
		return nil, err
	}
	_, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, now)
	if err != nil {
		return nil, err
	}
	verified, err := hostenroll.VerifyWorkerTransport(transport, authority.public, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, architecture, time.Now().UTC())
	if err != nil || verified.Worker() != worker {
		return nil, errors.New("worker source signed another recipient projection")
	}
	currentQuery := WorkerRegistrationQuery{Request: query.Request, Response: signed.Response}
	if _, _, _, _, _, err := authority.current(ctx, currentQuery); err != nil {
		return nil, err
	}
	if err := n.authorizeWorkerVaultRead(ctx, verified, currentQuery); err != nil {
		return nil, err
	}
	return signed.Response, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// AdmitEnrolledWorker binds current recipient identity to a real certificate
// only after both independently owned private keys prove that exact mapping.
func (n *Node) AdmitEnrolledWorker(ctx context.Context, query WorkerRegistrationQuery, binding hostenroll.SwarmNodeBinding) error {
	if query.Swarm != nil {
		return errors.New("worker projection is supplied only inside the signed response")
	}
	authority := n.workerAuthority
	request, response, registration, observed, execution, err := authority.current(ctx, query)
	if err != nil {
		return err
	}
	transport, err := protocol.EncodeJSON(hostenroll.WorkerTransport{Request: query.Request, Response: query.Response})
	if err != nil {
		return err
	}
	_, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil {
		return err
	}
	_, architecture, _ := strings.Cut(execution, ":")
	verified, err := hostenroll.VerifyWorkerTransport(transport, authority.public, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, architecture, time.Now().UTC())
	if err != nil {
		return err
	}
	worker := verified.Worker()
	role, _, _ := strings.Cut(execution, ":")
	if worker.DeploymentID != authority.identity.DeploymentID || worker.ClusterID != authority.identity.ClusterID || worker.Environment != authority.identity.Environment ||
		worker.Region != authority.identity.OCIRegion || worker.OCIRegion != authority.identity.OCIRegion || worker.ManagerAddress != net.JoinHostPort(authority.identity.SeedPrivateIP, swarmManagerPort) ||
		worker.FounderID != authority.identity.SeedSlot || worker.Role != role || worker.PrivateIP != observed.PrimaryPrivateIP || response.Swarm == nil {
		return errors.New("worker binding differs from current regional and OCI execution scope")
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	hostPublic, err := base64.StdEncoding.DecodeString(registration.PublicKey)
	if err != nil {
		return err
	}
	if err := hostenroll.VerifyWorkerBinding(binding, verified, hostPublic, node.Node.Certificate.Certificate, time.Now().UTC()); err != nil {
		return err
	}
	if _, _, _, _, _, err := authority.current(ctx, query); err != nil {
		return err
	}
	record := hostenroll.SwarmMembership{Transport: hostenroll.WorkerTransport{Request: query.Request, Response: query.Response}, Binding: binding, Certificate: node.Node.Certificate.Certificate}
	snapshot, err := readCurrentWorkerMembership(ctx, WorkerMembershipQuery{NodeID: binding.NodeID, RegistrationID: worker.RegistrationID, InstanceID: worker.InstanceID, Admission: &record})
	if err != nil {
		return err
	}
	if snapshot.Admission == nil || snapshot.Retired || snapshot.Disabled || snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" ||
		snapshot.GrantInstanceID != worker.InstanceID || snapshot.GrantRevision == 0 || snapshot.Sequence != worker.Revision {
		return errors.New("worker admission was not retained by the current instance grant")
	}
	expected, err := json.Marshal(record, json.Deterministic(true))
	actual, actualErr := json.Marshal(snapshot.Admission, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return errors.New("retained worker admission differs from actual dual-key binding")
	}
	expectedRegistration, err := json.Marshal(registration, json.Deterministic(true))
	actualRegistration, actualErr := json.Marshal(snapshot.Registration, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(expectedRegistration, actualRegistration) {
		return errors.New("worker registration changed during durable admission publication")
	}
	admitted, err := AdmitNode(ctx, client, binding.NodeID, Admission{Region: worker.Region, HostID: worker.RegistrationID, InstanceID: worker.InstanceID, FounderID: worker.FounderID, Role: worker.Role})
	if err != nil || admitted.Spec.Availability == api.NodeAvailabilityActive {
		return err
	}
	spec := admitted.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: admitted.ID, NodeVersion: &admitted.Meta.Version, Spec: spec})
	return err
}
