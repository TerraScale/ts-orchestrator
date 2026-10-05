package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/nats.go/jetstream"
)

// staticHostFleet is the regional fleet as the static enrollment path sees
// it: only ObserveStaticHost is reachable.
type staticHostFleet struct {
	oci.Fleet
	instances map[string]oci.CloudInstance
}

func (fleet *staticHostFleet) ObserveStaticHost(_ context.Context, instanceID, node string) (oci.CloudInstance, error) {
	instance, ok := fleet.instances[instanceID]
	if !ok || instance.FreeformTags["terrascale-host-node"] != node {
		return oci.CloudInstance{}, oci.ErrForeignResource
	}
	return instance, nil
}

type staticEnrollmentLab struct {
	enrollment *managedHostEnrollment
	controller *host.Controller
	fleet      *staticHostFleet
	bundle     hostenroll.PublicBundle
	epoch      uint64
}

func startStaticEnrollmentLab(t *testing.T, ctx context.Context, workloads map[string]WorkloadProfile) staticEnrollmentLab {
	t.Helper()
	root := t.TempDir()
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "static-enrollment", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{Scope: "gru", CandidateID: "static-enrollment", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	controllerPublic, controllerPrivate := testEd25519(t, root, "controller.key")
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: "STATIC_ENROLLMENT_ARTIFACTS", Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	hostController, err := host.NewController(ctx, host.ControllerConfig{
		Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: controllerPrivate, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hostController.Run(ctx) }()
	select {
	case <-hostController.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	grants, err := hostenroll.OpenGrantStore(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle, issuer, _ := testHostEnrollmentTLSMaterial(t, controllerPublic)
	members, err := newStaticTerraBaseMembers(workloads)
	if err != nil {
		t.Fatal(err)
	}
	fleet := &staticHostFleet{instances: map[string]oci.CloudInstance{}}
	return staticEnrollmentLab{enrollment: &managedHostEnrollment{cell: "gru", region: oci.RegionGRU,
		owner: "regional-owner", generation: 1, environment: "production", fleet: fleet,
		controller: hostController, grants: grants, issuer: issuer, responseKey: controllerPrivate,
		fencer: control, terraBase: members},
		controller: hostController, fleet: fleet, bundle: bundle, epoch: control.Current().Epoch}
}

// launch records an operator-launched instance carrying the static
// descriptor of node at ip, as preview member-launch writes it.
func (lab staticEnrollmentLab) launch(t *testing.T, id, node, ip string) hostenroll.InstanceMetadata {
	t.Helper()
	descriptor := hostboot.Static("gru", "GRU", node)
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	lab.fleet.instances[id] = oci.CloudInstance{ID: id, PrivateIP: ip, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", Metadata: map[string]string{hostboot.MetadataKey: string(wire)},
		FreeformTags: map[string]string{"terrascale-host-node": node}}
	return hostenroll.InstanceMetadata{InstanceID: id, Descriptor: descriptor, Wire: wire}
}

// setup runs the guest host-setup flow against the handler as the direct
// peer peerIP.
func (lab staticEnrollmentLab) setup(ctx context.Context, root string, metadata hostenroll.InstanceMetadata, peerIP string) error {
	return runHostSetupWithMetadata(ctx, lab.bundle, metadata, root, &bytes.Buffer{}, hostSetupRuntime{
		ownerUID: uint32(os.Geteuid()), post: func(_ context.Context, _ hostenroll.PublicBundle, wire []byte) ([]byte, error) {
			return lab.post(wire, peerIP)
		}})
}

func (lab staticEnrollmentLab) post(wire []byte, peerIP string) ([]byte, error) {
	request := httptest.NewRequest(http.MethodPost, "https://10.251.0.11:8443/v1/host-enrollment", bytes.NewReader(wire))
	request.RemoteAddr = peerIP + ":44321"
	reply := httptest.NewRecorder()
	lab.enrollment.ServeHTTP(reply, request)
	if reply.Code != http.StatusOK {
		return nil, &hostEnrollmentHTTPStatusError{Code: reply.Code}
	}
	return reply.Body.Bytes(), nil
}

func (lab staticEnrollmentLab) registration(t *testing.T, ctx context.Context, node string) host.Registration {
	t.Helper()
	statuses, err := lab.controller.ListHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Registration.Node == node {
			return status.Registration
		}
	}
	t.Fatalf("%s is not registered", node)
	return host.Registration{}
}

func staticTerraBaseWorkloads() map[string]WorkloadProfile {
	return map[string]WorkloadProfile{terrabase.Role: {
		Resources: placement.Resources{CPU: 1, MemoryBytes: 4 << 30, DiskBytes: 20 << 30},
		Env: map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvClientPort: "9465",
			terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443"}}}
}

func TestStaticTerraBaseHostEnrollsAsAListedMemberWithoutManagedBindings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, "10.251.0.21"); err != nil {
		t.Fatalf("static host setup: %v", err)
	}
	var installed Config
	wire, err := os.ReadFile(filepath.Join(root, "host.json"))
	if err != nil || json.Unmarshal(wire, &installed) != nil {
		t.Fatalf("installed host config: %v", err)
	}
	if installed.Host.Node != "gru-1-db-1" || !slices.Equal(installed.Host.Roles, []string{terrabase.Role}) ||
		installed.Host.TerraBaseRoot != filepath.Join(lab.bundle.ManagedRuntimeRoot, "terrabase") {
		t.Fatalf("static host config = %+v", installed.Host)
	}
	registration := lab.registration(t, ctx, "gru-1-db-1")
	if registration.Generation != 1 || !slices.Equal(registration.Roles, []string{terrabase.Role}) ||
		registration.ManagedOCI != nil || registration.ManagedPlacement != nil || registration.ManagedMember != nil ||
		registration.FailureDomain != "fault-domain-1" || registration.Environment != "production" ||
		registration.Capacity != (host.Capacity{CPU: 1, MemoryBytes: 4 << 30, DiskBytes: 20 << 30}) {
		t.Fatalf("static registration = %+v", registration)
	}

	// Renewal keeps the enrolled identity and the registration generation.
	var pending pendingHostEnrollment
	pendingWire, err := os.ReadFile(filepath.Join(root, pendingHostEnrollmentFile))
	if err != nil || json.Unmarshal(pendingWire, &pending) != nil {
		t.Fatalf("pending enrollment: %v", err)
	}
	original, err := parsePersistedHostRequest(pending.Request)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := createRenewalRequest(root, pending, original)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := lab.post(renewal, "10.251.0.21")
	if err != nil {
		t.Fatalf("static renewal: %v", err)
	}
	responseKey, err := lab.bundle.ResponsePublicKey()
	if err != nil {
		t.Fatal(err)
	}
	renewRequest, err := parsePersistedHostRequest(renewal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostenroll.VerifyResponse(renewed, responseKey, renewRequest, renewal, metadata.Descriptor); err != nil {
		t.Fatalf("static renewal response: %v", err)
	}
	if lab.registration(t, ctx, "gru-1-db-1").Generation != 1 {
		t.Fatal("renewal changed the static registration generation")
	}

	// A replacement instance holding the node's address takes the next
	// generation with its own keys; the old grant stays with the old instance.
	replacement := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1b", "gru-1-db-1", "10.251.0.21")
	delete(lab.fleet.instances, metadata.InstanceID)
	if err := lab.setup(ctx, t.TempDir(), replacement, "10.251.0.21"); err != nil {
		t.Fatalf("replacement host setup: %v", err)
	}
	if next := lab.registration(t, ctx, "gru-1-db-1"); next.Generation != 2 || next.PublicKey == registration.PublicKey {
		t.Fatalf("replacement registration = %+v", next)
	}
	if _, err := lab.post(renewal, "10.251.0.21"); err == nil {
		t.Fatal("terminated instance renewed its credentials")
	}
}

func TestStaticTerraBaseHostEnrollmentRefusesUnlistedOrMismatchedHosts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	for _, test := range []struct {
		name, id, node, ip, peer string
		mutate                   func(*oci.CloudInstance)
	}{
		{name: "unlisted node", id: "ocid1.instance.oc1.sa-saopaulo-1.db3", node: "gru-1-db-3", ip: "10.251.0.23", peer: "10.251.0.23"},
		{name: "peer is not the listed address", id: "ocid1.instance.oc1.sa-saopaulo-1.db2a", node: "gru-1-db-2", ip: "10.251.0.22", peer: "10.251.0.21"},
		{name: "instance holds another address", id: "ocid1.instance.oc1.sa-saopaulo-1.db2b", node: "gru-1-db-2", ip: "10.251.0.99", peer: "10.251.0.22"},
		{name: "instance carries another descriptor", id: "ocid1.instance.oc1.sa-saopaulo-1.db2c", node: "gru-1-db-2", ip: "10.251.0.22", peer: "10.251.0.22",
			mutate: func(instance *oci.CloudInstance) {
				instance.Metadata[hostboot.MetadataKey] = `{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-1"}`
			}},
		{name: "fleet does not own the instance", id: "ocid1.instance.oc1.sa-saopaulo-1.db2d", node: "gru-1-db-2", ip: "10.251.0.22", peer: "10.251.0.22",
			mutate: func(instance *oci.CloudInstance) { instance.FreeformTags["terrascale-host-node"] = "gru-1-db-1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := lab.launch(t, test.id, test.node, test.ip)
			if test.mutate != nil {
				instance := lab.fleet.instances[test.id]
				test.mutate(&instance)
				lab.fleet.instances[test.id] = instance
			}
			err := lab.setup(ctx, t.TempDir(), metadata, test.peer)
			if status, ok := errors.AsType[*hostEnrollmentHTTPStatusError](err); !ok || status.Code != http.StatusConflict {
				t.Fatalf("enrollment was not held: %v", err)
			}
			if _, _, err := lab.enrollment.grants.Read(ctx, test.id); err == nil {
				t.Fatal("a refused static host left an enrollment grant")
			}
		})
	}
	statuses, err := lab.controller.ListHosts(ctx)
	if err != nil || len(statuses) != 0 {
		t.Fatalf("refused static hosts registered: %+v, %v", statuses, err)
	}
}

func TestStaticTerraBaseHostEnrollmentRequiresASignedProfile(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, nil)
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	err := lab.setup(ctx, t.TempDir(), metadata, "10.251.0.21")
	if status, ok := errors.AsType[*hostEnrollmentHTTPStatusError](err); !ok || status.Code != http.StatusConflict {
		t.Fatalf("enrollment without a TerraBase profile was not held: %v", err)
	}
	if _, err := newStaticTerraBaseMembers(map[string]WorkloadProfile{terrabase.Role: {
		Env: map[string]string{terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}}); err == nil {
		t.Fatal("accepted a TerraBase profile without a peer port")
	}
}

func TestStaticRegistrationReplacesKeysOnlyAfterTheSessionEnds(t *testing.T) {
	enrolled := host.Registration{Cell: "gru", Node: "gru-1-db-1", Environment: "production", Roles: []string{terrabase.Role},
		PublicKey: "old-identity", NATSUserPublicKey: "old-user", Generation: 3, Capacity: host.Capacity{CPU: 1}}
	live := []host.HostStatus{{Registration: enrolled, SessionExpiresAt: time.Now().Add(time.Minute)}}
	ended := []host.HostStatus{{Registration: enrolled}}
	candidate := enrolled
	candidate.Generation = 1
	if got, err := nextStaticRegistration(candidate, live); err != nil || got.Generation != 3 {
		t.Fatalf("unchanged registration = %+v, %v", got, err)
	}
	resized := candidate
	resized.Capacity.CPU = 2
	if got, err := nextStaticRegistration(resized, live); err != nil || got.Generation != 4 {
		t.Fatalf("same host with a new profile = %+v, %v", got, err)
	}
	replacement := candidate
	replacement.PublicKey = "new-identity"
	if _, err := nextStaticRegistration(replacement, live); err == nil {
		t.Fatal("new keys took over a node with a current session")
	}
	if got, err := nextStaticRegistration(replacement, ended); err != nil || got.Generation != 4 {
		t.Fatalf("replacement after the session ended = %+v, %v", got, err)
	}
	if got, err := nextStaticRegistration(candidate, nil); err != nil || got.Generation != 1 {
		t.Fatalf("first registration = %+v, %v", got, err)
	}
}

func TestStaticTerraBaseHostRevocationStopsRenewalAndReenrollment(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db2", "gru-1-db-2", "10.251.0.22")
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, "10.251.0.22"); err != nil {
		t.Fatalf("static host setup: %v", err)
	}
	receipt, err := lab.enrollment.revoke(ctx, lab.epoch, metadata.InstanceID)
	if err != nil || !receipt.Disabled || receipt.GrantRevision == 0 {
		t.Fatalf("revoke = %+v, %v", receipt, err)
	}
	var pending pendingHostEnrollment
	pendingWire, err := os.ReadFile(filepath.Join(root, pendingHostEnrollmentFile))
	if err != nil || json.Unmarshal(pendingWire, &pending) != nil {
		t.Fatalf("pending enrollment: %v", err)
	}
	original, err := parsePersistedHostRequest(pending.Request)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := createRenewalRequest(root, pending, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.post(renewal, "10.251.0.22"); err == nil {
		t.Fatal("a revoked static host renewed its credentials")
	}
	if _, err := lab.post(pending.Request, "10.251.0.22"); err == nil {
		t.Fatal("a revoked static host replayed its enrollment")
	}
	if err := lab.setup(ctx, t.TempDir(), metadata, "10.251.0.22"); err == nil {
		t.Fatal("a revoked static instance enrolled again with new keys")
	}
}

// fenceAfterCommit loses authority the moment an instance's grant holds a
// committed response, as when the commit stalls across a leadership change.
type fenceAfterCommit struct {
	authority.Fencer
	grants   *hostenroll.GrantStore
	instance string
}

func (fence fenceAfterCommit) Guard(ctx context.Context, epoch uint64) error {
	if grant, _, err := fence.grants.Read(ctx, fence.instance); err == nil && len(grant.Response) != 0 {
		return authority.ErrFenced
	}
	return fence.Fencer.Guard(ctx, epoch)
}

// Credentials committed by a controller that lost authority during the
// commit are not released by it; the host retries and gets the committed
// response from a controller that holds authority.
func TestStaticEnrollmentReleasesCredentialsOnlyUnderCurrentAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	current := lab.enrollment.fencer
	lab.enrollment.fencer = fenceAfterCommit{Fencer: current, grants: lab.enrollment.grants, instance: metadata.InstanceID}
	root := t.TempDir()
	err := lab.setup(ctx, root, metadata, "10.251.0.21")
	if status, ok := errors.AsType[*hostEnrollmentHTTPStatusError](err); !ok || status.Code != http.StatusConflict {
		t.Fatalf("a fenced controller released credentials: %v", err)
	}
	grant, _, err := lab.enrollment.grants.Read(ctx, metadata.InstanceID)
	if err != nil || len(grant.Response) == 0 {
		t.Fatalf("the response was not committed before the fence: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "host.json")); !os.IsNotExist(err) {
		t.Fatal("the host installed credentials a fenced controller released")
	}
	lab.enrollment.fencer = current
	if err := lab.setup(ctx, root, metadata, "10.251.0.21"); err != nil {
		t.Fatalf("the committed response was not replayed under current authority: %v", err)
	}
}
