package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
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
	fleet := &staticHostFleet{instances: map[string]oci.CloudInstance{}}
	services, err := newSpecRegistry(Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{Workloads: workloads}}, "")
	if err != nil {
		t.Fatal(err)
	}
	return staticEnrollmentLab{enrollment: &managedHostEnrollment{cell: "gru", region: oci.RegionGRU,
		owner: "regional-owner", generation: 1, environment: "production", fleet: fleet,
		controller: hostController, grants: grants, issuer: issuer, responseKey: controllerPrivate,
		fencer: control, services: services},
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

// The cell spec's terrabase entry, which only a root signs, is the member
// list once adopted: a member it adds enrolls and one it drops is refused,
// on the running controller, without a restart or a re-found.
func TestStaticTerraBaseMembershipFollowsTheCellSpec(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	added := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db3", "gru-1-db-3", "10.251.0.23")
	if err := lab.setup(ctx, t.TempDir(), added, "10.251.0.23"); err == nil {
		t.Fatal("a host the signed peers do not list enrolled")
	}
	profile := staticTerraBaseWorkloads()[terrabase.Role]
	profile.Env = maps.Clone(profile.Env)
	profile.Env[terrabase.EnvPeers] = "gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443"
	spec := lab.enrollment.services.current
	spec.Generation++
	spec.Services = []cellspec.Service{{Role: terrabase.Role, Profile: profile}}
	if err := lab.enrollment.services.validate(spec); err != nil {
		t.Fatal(err)
	}
	lab.enrollment.services.adopt(spec, spec.Generation)
	if err := lab.setup(ctx, t.TempDir(), added, "10.251.0.23"); err != nil {
		t.Fatalf("member the cell spec adds: %v", err)
	}
	if registration := lab.registration(t, ctx, "gru-1-db-3"); !slices.Equal(registration.Roles, []string{terrabase.Role}) ||
		registration.Capacity != host.Capacity(profile.Resources) {
		t.Fatalf("spec member registration = %+v", registration)
	}
	dropped := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	if err := lab.setup(ctx, t.TempDir(), dropped, "10.251.0.21"); err == nil {
		t.Fatal("a member the cell spec drops enrolled")
	}
	// A spec that turns the member into a granted host while it enrolls
	// settles the request on the grant: the credential is released for a
	// registration with the grant's roles, which the last observation
	// authenticated with the granted-host checks.
	moved := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db2", "gru-1-db-2", "10.251.0.22")
	instance := lab.fleet.instances["ocid1.instance.oc1.sa-saopaulo-1.db2"]
	instance.DisplayName = "gru-1-db-2"
	lab.fleet.instances["ocid1.instance.oc1.sa-saopaulo-1.db2"] = instance
	member, granted := spec, spec
	member.Services = []cellspec.Service{{Role: terrabase.Role, Profile: profile}}
	member.Services[0].Profile.Env = maps.Clone(profile.Env)
	member.Services[0].Profile.Env[terrabase.EnvPeers] = "gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443"
	granted.Services = []cellspec.Service{{Role: terrabase.Role, Profile: profile}}
	granted.Services[0].Profile.Env = maps.Clone(profile.Env)
	granted.Services[0].Profile.Env[terrabase.EnvPeers] = "gru-1-db-3=10.251.0.23:9443"
	granted.HostGrants = []cellspec.HostGrant{{Node: "gru-1-db-2", PrivateIP: "10.251.0.22", Roles: []string{"worker"},
		Environment: "production"}}
	generation := spec.Generation
	adopt := func(next cellspec.Spec) {
		generation++
		next.Generation = generation
		lab.enrollment.services.adopt(next, generation)
	}
	lab.fleet.observed = func() {
		lab.fleet.observed = nil
		adopt(granted)
	}
	if err := lab.setup(ctx, t.TempDir(), moved, "10.251.0.22"); err != nil {
		t.Fatalf("host whose admission changed mid-request: %v", err)
	}
	if roles := lab.registration(t, ctx, "gru-1-db-2").Roles; !slices.Equal(roles, []string{"worker"}) {
		t.Fatalf("settled host roles = %v", roles)
	}
	// A spec that changes the admission at every observation is refused.
	flapping := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db2b", "gru-1-db-2", "10.251.0.22")
	instance = lab.fleet.instances["ocid1.instance.oc1.sa-saopaulo-1.db2b"]
	instance.DisplayName = "gru-1-db-2"
	lab.fleet.instances["ocid1.instance.oc1.sa-saopaulo-1.db2b"] = instance
	delete(lab.fleet.instances, "ocid1.instance.oc1.sa-saopaulo-1.db2")
	asMember := true
	lab.fleet.observed = func() {
		if asMember {
			adopt(member)
		} else {
			adopt(granted)
		}
		asMember = !asMember
	}
	if err := lab.setup(ctx, t.TempDir(), flapping, "10.251.0.22"); err == nil {
		t.Fatal("a host enrolled while the cell spec kept changing its admission")
	}
	lab.fleet.observed = nil

	// A host grant names a member of the spec's own peer list only with
	// role terrabase, at the member's peer address.
	overlapping := spec
	for _, grant := range []cellspec.HostGrant{
		{Node: "gru-1-db-3", PrivateIP: "10.251.0.23", Roles: []string{"worker"}, Environment: "production"},
		{Node: "gru-1-db-3", PrivateIP: "10.251.0.24", Roles: []string{terrabase.Role}, Environment: "production"},
	} {
		overlapping.HostGrants = []cellspec.HostGrant{grant}
		if err := lab.enrollment.services.validate(overlapping); err == nil || !strings.Contains(err.Error(), terrabase.EnvPeers) {
			t.Fatalf("grant %+v naming a spec member = %v", grant, err)
		}
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

func controllerHostWorkloads() map[string]WorkloadProfile {
	workloads := staticTerraBaseWorkloads()
	workloads[tsauth.Role] = WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 2 << 30}}
	return workloads
}

func controllerGrant(node, ip string) cellspec.HostGrant {
	return cellspec.HostGrant{Node: node, PrivateIP: ip, Roles: []string{tsauth.Role}, Environment: "canary"}
}

// A controller VM's host agent enrolls through its cell spec host grant, from
// the granted address under the controller's name, with the grant's roles.
func TestGrantedControllerHostEnrollsWithItsGrantRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.grant(controllerGrant("gru-1-ctl-1", "10.251.0.11"), controllerGrant("gru-1-ctl-2", "10.251.0.12"))
	metadata := lab.launchController(t, "ocid1.instance.oc1.sa-saopaulo-1.ctl2", "gru-1-ctl-2", "10.251.0.12")
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, "10.251.0.12"); err != nil {
		t.Fatalf("granted host setup: %v", err)
	}
	var installed Config
	wire, err := os.ReadFile(filepath.Join(root, "host.json"))
	if err != nil || json.Unmarshal(wire, &installed) != nil {
		t.Fatalf("installed host config: %v", err)
	}
	if installed.Host.Node != "gru-1-ctl-2" || !slices.Equal(installed.Host.Roles, []string{tsauth.Role}) ||
		installed.Host.TSAuthRoot != filepath.Join(lab.bundle.ManagedRuntimeRoot, "ts-auth") || installed.Host.TerraBaseRoot != "" ||
		installed.Observability.ListenAddress != controllerHostObservability {
		t.Fatalf("granted host config = %+v, observability %+v", installed.Host, installed.Observability)
	}
	registration := lab.registration(t, ctx, "gru-1-ctl-2")
	if !slices.Equal(registration.Roles, []string{tsauth.Role}) || registration.FailureDomain != "fault-domain-2" ||
		registration.Environment != "canary" ||
		registration.Capacity != (host.Capacity{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 2 << 30}) ||
		registration.ManagedOCI != nil || registration.ManagedPlacement != nil || registration.ManagedMember != nil {
		t.Fatalf("granted host registration = %+v", registration)
	}
	// A listed TerraBase member still enrolls as a member, without roles in
	// its response.
	member := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	memberRoot := t.TempDir()
	if err := lab.setup(ctx, memberRoot, member, "10.251.0.21"); err != nil {
		t.Fatalf("member setup beside grants: %v", err)
	}
	if roles := lab.registration(t, ctx, "gru-1-db-1").Roles; !slices.Equal(roles, []string{terrabase.Role}) {
		t.Fatalf("member roles = %v", roles)
	}
}

// A controller whose grant lists role terrabase colocates the member that
// TERRABASE_PEERS lists at its address (TS-578). It enrolls through its
// grant, since a controller VM carries no host descriptor for the member
// checks, with both roles' capacity, and host-setup gives it both roots.
func TestGrantedControllerHostColocatesATerraBaseMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	workloads := controllerHostWorkloads()
	profile := workloads[terrabase.Role]
	profile.Env = maps.Clone(profile.Env)
	profile.Env[terrabase.EnvPeers] = "gru-1-ctl-1=10.251.0.11:9443,gru-1-db-1=10.251.0.21:9443"
	workloads[terrabase.Role] = profile
	lab := startStaticEnrollmentLab(t, ctx, workloads)
	spec := lab.enrollment.services.current
	spec.Generation++
	spec.HostGrants = []cellspec.HostGrant{{Node: "gru-1-ctl-1", PrivateIP: "10.251.0.11",
		Roles: []string{terrabase.Role, tsauth.Role}, Environment: "canary"}}
	if err := lab.enrollment.services.validateHostGrants(spec.HostGrants, workloads); err != nil {
		t.Fatalf("grant colocating a member: %v", err)
	}
	lab.enrollment.services.adopt(spec, spec.Generation)
	metadata := lab.launchController(t, "ocid1.instance.oc1.sa-saopaulo-1.ctl1", "gru-1-ctl-1", "10.251.0.11")
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, "10.251.0.11"); err != nil {
		t.Fatalf("colocated controller host setup: %v", err)
	}
	var installed Config
	wire, err := os.ReadFile(filepath.Join(root, "host.json"))
	if err != nil || json.Unmarshal(wire, &installed) != nil {
		t.Fatalf("installed host config: %v", err)
	}
	if !slices.Equal(installed.Host.Roles, []string{terrabase.Role, tsauth.Role}) ||
		installed.Host.TerraBaseRoot != filepath.Join(lab.bundle.ManagedRuntimeRoot, "terrabase") ||
		installed.Host.TSAuthRoot != filepath.Join(lab.bundle.ManagedRuntimeRoot, "ts-auth") ||
		installed.Observability.ListenAddress != controllerHostObservability {
		t.Fatalf("colocated host config = %+v, observability %+v", installed.Host, installed.Observability)
	}
	registration := lab.registration(t, ctx, "gru-1-ctl-1")
	if !slices.Equal(registration.Roles, []string{terrabase.Role, tsauth.Role}) || registration.Environment != "canary" ||
		registration.Capacity != (host.Capacity{CPU: 2, MemoryBytes: 5 << 30, DiskBytes: 22 << 30}) || registration.ManagedOCI != nil {
		t.Fatalf("colocated host registration = %+v", registration)
	}
	// ts-orch node rename (TS-609): the spec grants ts-gru-1 at the address
	// and the leader forgets the instance's enrollment and renames it. Its
	// host-setup then enrolls the node afresh under the new name, keeping
	// host.json's host-local options and the member at its address.
	installed.Host.SelfUpdateRoot = "/var/lib/terrascale-orchestrator"
	if wire, err = protocol.EncodeJSON(installed); err != nil || os.WriteFile(filepath.Join(root, "host.json"), wire, 0o600) != nil {
		t.Fatalf("write a host-local option: %v", err)
	}
	renamed := lab.enrollment.services.current
	renamed.Generation++
	renamed.HostGrants = []cellspec.HostGrant{{Node: "ts-gru-1", PrivateIP: "10.251.0.11",
		Roles: []string{terrabase.Role, tsauth.Role}, Environment: "canary", Controller: "controller-a"}}
	if err := lab.enrollment.services.validateHostGrants(renamed.HostGrants, workloads); err != nil {
		t.Fatalf("grant renaming a colocated member's node: %v", err)
	}
	lab.enrollment.services.adopt(renamed, renamed.Generation)
	renamedMetadata := lab.launchController(t, "ocid1.instance.oc1.sa-saopaulo-1.ctl1", "ts-gru-1", "10.251.0.11")
	if err := lab.setup(ctx, root, renamedMetadata, "10.251.0.11"); err == nil {
		t.Fatal("a renamed host enrolled while its instance's first enrollment stands")
	}
	if err := lab.enrollment.grants.Forget(ctx, "ocid1.instance.oc1.sa-saopaulo-1.ctl1"); err != nil {
		t.Fatal(err)
	}
	if err := lab.setup(ctx, root, renamedMetadata, "10.251.0.11"); err != nil {
		t.Fatalf("renamed controller host setup: %v", err)
	}
	if wire, err = os.ReadFile(filepath.Join(root, "host.json")); err != nil || json.Unmarshal(wire, &installed) != nil {
		t.Fatalf("renamed host config: %v", err)
	}
	if installed.Host.Node != "ts-gru-1" || installed.Host.SelfUpdateRoot != "/var/lib/terrascale-orchestrator" ||
		installed.Observability.ListenAddress != controllerHostObservability {
		t.Fatalf("renamed host config = %+v, observability %+v", installed.Host, installed.Observability)
	}
	if roles := lab.registration(t, ctx, "ts-gru-1").Roles; !slices.Equal(roles, []string{terrabase.Role, tsauth.Role}) {
		t.Fatalf("renamed host roles = %v", roles)
	}
	// A listed member without a grant still enrolls through the member
	// checks.
	member := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	if err := lab.setup(ctx, t.TempDir(), member, "10.251.0.21"); err != nil {
		t.Fatalf("member setup beside a colocated member: %v", err)
	}
	if roles := lab.registration(t, ctx, "gru-1-db-1").Roles; !slices.Equal(roles, []string{terrabase.Role}) {
		t.Fatalf("member roles = %v", roles)
	}
}

func TestHostGrantEnrollmentRefusesOtherAddressesNamesAndUngrantedHosts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.grant(controllerGrant("gru-1-ctl-1", "10.251.0.11"))
	for _, test := range []struct {
		name, id, node, ip, peer string
		mutate                   func(*oci.CloudInstance)
	}{
		{name: "no grant for the node", id: "ocid1.instance.oc1.sa-saopaulo-1.ctl3", node: "gru-1-ctl-3", ip: "10.251.0.13", peer: "10.251.0.13"},
		{name: "peer is not the granted address", id: "ocid1.instance.oc1.sa-saopaulo-1.ctl1a", node: "gru-1-ctl-1", ip: "10.251.0.11", peer: "10.251.0.12"},
		{name: "instance holds another address", id: "ocid1.instance.oc1.sa-saopaulo-1.ctl1b", node: "gru-1-ctl-1", ip: "10.251.0.99", peer: "10.251.0.11"},
		{name: "instance has another name", id: "ocid1.instance.oc1.sa-saopaulo-1.ctl1c", node: "gru-1-ctl-1", ip: "10.251.0.11", peer: "10.251.0.11",
			mutate: func(instance *oci.CloudInstance) { instance.DisplayName = "gru-1-ctl-3" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := lab.launchController(t, test.id, test.node, test.ip)
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
				t.Fatal("a refused host left an enrollment grant")
			}
		})
	}
	if statuses, err := lab.controller.ListHosts(ctx); err != nil || len(statuses) != 0 {
		t.Fatalf("refused hosts registered: %+v, %v", statuses, err)
	}
}
