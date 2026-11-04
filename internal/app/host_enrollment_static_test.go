package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"

	"github.com/nats-io/nats.go/jetstream"
)

// staticHostFleet is the regional fleet as the static enrollment path sees
// it: only ObserveStaticHost is reachable.
type staticHostFleet struct {
	oci.Fleet
	instances map[string]oci.CloudInstance
	// observed, when set, runs before each static host observation.
	observed func()
}

func (fleet *staticHostFleet) ObserveStaticHost(_ context.Context, instanceID, node string) (oci.CloudInstance, error) {
	if fleet.observed != nil {
		fleet.observed()
	}
	instance, ok := fleet.instances[instanceID]
	if !ok || instance.FreeformTags["terrascale-host-node"] != node {
		return oci.CloudInstance{}, oci.ErrForeignResource
	}
	return instance, nil
}

// ObserveNamedHost returns the running instance named node, as the OCI
// observer does for a granted host.
func (fleet *staticHostFleet) ObserveNamedHost(_ context.Context, instanceID, node string) (oci.CloudInstance, error) {
	if fleet.observed != nil {
		fleet.observed()
	}
	instance, ok := fleet.instances[instanceID]
	if !ok || instance.DisplayName != node {
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
	js         jetstream.JetStream
}

func startStaticEnrollmentLab(t *testing.T, ctx context.Context, workloads map[string]WorkloadProfile) staticEnrollmentLab {
	t.Helper()
	root := t.TempDir()
	broker, err := newAuthenticatedNATS(t, "gru").start(t, ctx, natscell.Config{
		Cell: "gru", Instance: "static-enrollment", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000F8TA328PVB21XWJY", Replicas: 1})
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
	fleet := &staticHostFleet{instances: map[string]oci.CloudInstance{}}
	cfg := Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{Workloads: workloads, SpecTrust: newTestSpecTrust(t, root, cellspec.Identity{
			DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Cell: "gru", Environment: "production"}).config()}}
	newAcceptedSpecTrust(t, &cfg)
	services, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	return staticEnrollmentLab{enrollment: &managedHostEnrollment{cell: "gru", region: oci.RegionGRU,
		owner: "regional-owner", generation: 1, environment: "production", fleet: fleet,
		controller: hostController, grants: grants, issuer: issuer, responseKey: controllerPrivate,
		fencer: control, services: services, js: broker.JetStream(),
		prepareWorker: func(_ context.Context, _, response []byte) ([]byte, error) { return response, nil }},
		controller: hostController, fleet: fleet, bundle: bundle, epoch: control.Current().Epoch, js: broker.JetStream()}
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

// grant adopts a cell spec holding grants, as apply would.
func (lab staticEnrollmentLab) grant(grants ...cellspec.HostGrant) {
	set := lab.enrollment.services.current
	set.Generation++
	set.HostGrants = grants
	lab.enrollment.services.adopt(set, set.Generation)
}

// launchController records a controller VM named node at ip; its host-setup
// derives the static descriptor from the controller's slot, as
// hostenroll.ReadControllerHostMetadata does.
func (lab staticEnrollmentLab) launchController(t *testing.T, id, node, ip string) hostenroll.InstanceMetadata {
	t.Helper()
	descriptor := hostboot.Static("gru", "GRU", node)
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	lab.fleet.instances[id] = oci.CloudInstance{ID: id, DisplayName: node, PrivateIP: ip, FaultDomain: "FAULT-DOMAIN-2",
		LifecycleState: "RUNNING"}
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
	verified, err := hostenroll.VerifyResponse(renewed, responseKey, renewRequest, renewal, metadata.Descriptor)
	if err != nil {
		t.Fatalf("static renewal response: %v", err)
	}
	// A member's response keeps its pre-grant wire form, which older hosts
	// decode strictly; signed roles must be valid.
	if bytes.Contains(renewed, []byte(`"roles"`)) {
		t.Fatalf("member response carries roles: %s", renewed)
	}
	verified.Roles = []string{"web", "api"}
	if err := verified.Sign(lab.enrollment.responseKey); err != nil {
		t.Fatal(err)
	}
	unsorted, err := protocol.EncodeJSON(verified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostenroll.VerifyResponse(unsorted, responseKey, renewRequest, renewal, metadata.Descriptor); err == nil {
		t.Fatal("accepted a response with unsorted roles")
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
