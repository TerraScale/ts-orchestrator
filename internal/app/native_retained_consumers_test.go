package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

type retainedConsumerFixture struct {
	history *nativeHistory
	keys    testSpecTrust
	codec   delivery.Ed25519Codec
	state   jetstream.KeyValue
}

func newRetainedConsumerFixture(t *testing.T) *retainedConsumerFixture {
	t.Helper()
	ctx, js := t.Context(), testRolloutJetStream(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "gru", Actor: servicePinsActor, PrivateKey: private,
		Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: servicePinsActor, PublicKey: public}}, Lifetime: time.Minute, MaxLifetime: time.Minute}
	service, err := delivery.Open(ctx, delivery.Config{Conn: js.Conn(), JS: js, Cell: "gru", Replicas: 1,
		ArtifactVerifier: codec, AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{Name: authority.ControlStreamName, Subjects: []string{protocol.ControlStreamSubject()},
		Storage: jetstream.FileStorage, Replicas: 1, MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		DenyDelete: true, DenyPurge: true, Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := authority.OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	fencer := rolloutTestFence{epoch: 7}
	controller, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: js.Conn(), JS: js,
		Artifacts: service.Artifacts(), HostMutations: nativeReadOnlyMutations{Reader: reader}, ResponseKey: private, StateReplicas: 1,
		AuthorityEpoch: func() uint64 { return 7 }, AuthorityGuard: fencer.Guard})
	if err != nil {
		t.Fatal(err)
	}
	state, err := js.KeyValue(ctx, "TS_HOST_STATE")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := openNativeHistory(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	keys := nativeTestTrust(t, t.TempDir())
	registry := &specRegistry{cell: "gru", identity: keys.identity, terraBaseCA: true, fixed: map[string]WorkloadProfile{},
		roots: &rootRegistry{genesis: keys.roots, verified: trust.VerifiedRoots{Current: keys.roots, Historical: keys.roots}}}
	return &retainedConsumerFixture{history: &nativeHistory{kv: kv, js: js, services: registry, deliveries: service, hosts: controller, fencer: fencer},
		keys: keys, codec: codec, state: state}
}

func (f *retainedConsumerFixture) adopt(t *testing.T, profiles map[string]WorkloadProfile, generation uint64) nativeProfileProvenance {
	t.Helper()
	var services []cellspec.Service
	for _, role := range slices.Sorted(maps.Keys(profiles)) {
		services = append(services, cellspec.Service{Role: role, Profile: profiles[role]})
	}
	spec := cellspec.Spec{Schema: cellspec.Schema, Identity: f.keys.identity, Generation: generation,
		RequiresBinary: cellspec.BinaryLevel, Services: services}
	wire, err := cellspec.Sign(spec, nil, f.keys.roots, time.Now(), time.Hour, f.keys.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cellspec.VerifyCurrent(wire, f.keys.roots, f.keys.identity, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.history.services.validate(spec); err != nil {
		t.Fatal(err)
	}
	f.history.services.adopt(spec, generation)
	return nativeProfileProvenance{Spec: wire}
}

func (f *retainedConsumerFixture) binding(t *testing.T, role string, profile WorkloadProfile, provenance nativeProfileProvenance, generation uint64) nativeReleaseBinding {
	t.Helper()
	data := fmt.Sprintf("%s release %d", role, generation)
	repository := terrabase.Repository
	if role == tsauth.Role {
		repository = tsauth.Repository
	}
	record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Cell: "gru", Role: role, Environment: "test",
		Source: delivery.ArtifactSource{Repository: repository, Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}}, controllerSHA256([]byte(data)), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := f.codec.SignArtifact(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.history.deliveries.AdmitClaim(t.Context(), strings.NewReader(data), wire); err != nil {
		t.Fatal(err)
	}
	intent := nativeIntent(record, nativeRelease{Role: role, Replicas: 1, Profile: profile}, generation)
	intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, entityid.New(), 7
	binding, err := nativeBinding(intent, record, profile, provenance)
	if err != nil {
		t.Fatal(err)
	}
	binding.Deadline = time.Now().Add(time.Minute)
	return binding
}

// Publish only test fixtures; production admission remains the real history/host reader.
func (f *retainedConsumerFixture) mutation(t *testing.T, kind authority.HostMutationKind, key string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(struct {
		Version     int                        `json:"version"`
		Kind        authority.HostMutationKind `json:"kind"`
		Scope       string                     `json:"scope"`
		SubjectKey  string                     `json:"subject_key"`
		OperationID string                     `json:"operation_id"`
		Epoch       uint64                     `json:"epoch"`
		Payload     []byte                     `json:"payload"`
	}{1, kind, "gru", key, entityid.New(), 7, payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.history.js.Publish(t.Context(), protocol.Control("gru", "host", string(kind), key), wire); err != nil {
		t.Fatal(err)
	}
}

func (f *retainedConsumerFixture) host(t *testing.T, resources placement.Resources) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	natsPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{ID: entityid.Derive("host", "gru", "ctl-1"), Cell: "gru", Node: "ctl-1", Environment: "test",
		Generation: 1, Roles: []string{terrabase.Role, tsauth.Role, "web"}, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: natsPublic,
		Capacity: host.Capacity{CPU: resources.CPU, MemoryBytes: resources.MemoryBytes, DiskBytes: resources.DiskBytes}}
	f.mutation(t, authority.MutationRegistration, "gru.ctl-1", registration)
	wire, err := json.Marshal(struct {
		Generation uint64    `json:"registration_generation"`
		SessionID  string    `json:"session_id"`
		Epoch      uint64    `json:"epoch"`
		ExpiresAt  time.Time `json:"expires_at"`
	}{1, entityid.New(), 7, time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.Put(t.Context(), "session.gru.ctl-1", wire); err != nil {
		t.Fatal(err)
	}
}

func (f *retainedConsumerFixture) desired(t *testing.T, binding nativeReleaseBinding) {
	t.Helper()
	i, p := binding.Intent, binding.Profile
	f.mutation(t, authority.MutationDesired, "gru.ctl-1."+i.Role, host.Desired{Cell: "gru", Node: "ctl-1", Role: i.Role, Environment: "test",
		AuthorityEpoch: 7, Generation: i.Generation, Digest: i.ArtifactDigest, Args: p.Args, Env: p.Env, Secrets: p.Secrets})
}

func (f *retainedConsumerFixture) save(t *testing.T, role string, state nativeReleaseHistory) {
	t.Helper()
	_, revision, err := f.history.load(t.Context(), role)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.history.save(t.Context(), 7, role, state, revision); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRetainedColocatedReleaseCapacity(t *testing.T) {
	for _, dimension := range []string{"cpu", "memory", "disk"} {
		t.Run(dimension, func(t *testing.T) {
			f := newRetainedConsumerFixture(t)
			auth, _ := tsAuthGRUConfig(t)
			auth.Resources = placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
			retained := cloneNativeProfile(auth)
			capacity := placement.Resources{CPU: 4, MemoryBytes: 4 << 30, DiskBytes: 4 << 30}
			switch dimension {
			case "cpu":
				retained.Resources.CPU, capacity.CPU = 2, 2
			case "memory":
				retained.Resources.MemoryBytes, capacity.MemoryBytes = 2<<30, 2<<30
			case "disk":
				retained.Resources.DiskBytes, capacity.DiskBytes = 2<<30, 2<<30
			}
			tb := WorkloadProfile{Resources: auth.Resources}
			profiles := map[string]WorkloadProfile{tsauth.Role: retained, terrabase.Role: tb, "web": tb}
			provenance := f.adopt(t, profiles, 1)
			a := f.binding(t, tsauth.Role, retained, provenance, 1)
			good := nativeGoodRelease{Binding: a, Nodes: []string{"ctl-1"}, GoodAt: time.Now()}
			f.save(t, tsauth.Role, nativeReleaseHistory{Schema: 1, Good: []nativeGoodRelease{good}, Pending: &a})
			f.host(t, capacity)
			f.desired(t, a)
			profiles[tsauth.Role] = auth
			provenance = f.adopt(t, profiles, 2)
			candidate := f.binding(t, terrabase.Role, tb, provenance, 1)
			f.save(t, terrabase.Role, nativeReleaseHistory{Schema: 1, Pending: &candidate})
			planner := &regionalDeliveryPlanner{hosts: f.history.hosts, profiles: f.history.services.profiles, nativeHistory: f.history}
			for _, role := range []string{terrabase.Role, "web"} {
				intent := candidate.Intent
				intent.Role = role
				if _, err := planner.Plan(t.Context(), intent); !errors.Is(err, placement.ErrInsufficientCapacity) {
					t.Fatalf("%s undercharged retained %s: %v", role, dimension, err)
				}
			}
			// The reverse size change must not falsely refuse available capacity.
			profiles[tsauth.Role] = retained
			authBinding := f.binding(t, tsauth.Role, auth, f.adopt(t, map[string]WorkloadProfile{tsauth.Role: auth, terrabase.Role: tb, "web": tb}, 3), 2)
			f.save(t, tsauth.Role, nativeReleaseHistory{Schema: 1, Pending: &authBinding})
			f.desired(t, authBinding)
			f.adopt(t, profiles, 4)
			for _, role := range []string{terrabase.Role, "web"} {
				intent := candidate.Intent
				intent.Role = role
				if plan, err := planner.Plan(t.Context(), intent); err != nil || len(plan) != 1 || plan[0].Node != "ctl-1" {
					t.Fatalf("%s refused retained free %s: %+v, %v", role, dimension, plan, err)
				}
			}
		})
	}
}

func TestHostTelemetryAdoptionAndRecoveryUseCommittedResources(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	auth, _ := tsAuthGRUConfig(t)
	auth.Resources = placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	tb := WorkloadProfile{Resources: auth.Resources}
	profiles := map[string]WorkloadProfile{tsauth.Role: auth, terrabase.Role: tb}
	a := f.binding(t, tsauth.Role, auth, f.adopt(t, profiles, 1), 1)
	good := nativeGoodRelease{Binding: a, Nodes: []string{"ctl-1"}, GoodAt: time.Now()}
	f.save(t, tsauth.Role, nativeReleaseHistory{Schema: 1, Pending: &a, Good: []nativeGoodRelease{good}})
	f.desired(t, a)
	specs := []workload.ServiceSpec{{Role: tsauth.Role, Environment: "test", Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 1}}}
	reconciler, telemetry, err := startWorkloadAutoscale("gru", nil, profiles, specs, f.history.hosts, f.history.fencer, f.history)
	if err != nil {
		t.Fatal(err)
	}
	f.history.services.changed = func(profiles map[string]WorkloadProfile, specs []workload.ServiceSpec) {
		if err := reconciler.SetServices(specs, profileResources(profiles)); err != nil {
			t.Fatal(err)
		}
	}
	usage := &runtimeObservability{usage: capacity.NewStore("gru")}
	at := time.Now()
	telemetry.load = hostload.NewAggregator(hostload.AggregatorConfig{Requests: loadRequests(profileResources(profiles)), Now: func() time.Time { return at }})
	check := func(node string, request placement.Resources, reset bool) {
		t.Helper()
		before := len(telemetry.load.Nodes())
		cpu, memory := .5, uint64(512<<20)
		start := time.Now().Add(-time.Second)
		if err := telemetry.recordCommitted(t.Context(), f.history, usage, hostload.Origin{Cell: "gru", Node: node, Environment: "test"},
			hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: tsauth.Role, CPUCores: &cpu, MemoryBytes: &memory}}}); err != nil {
			t.Fatal(err)
		}
		if reset && len(telemetry.load.Nodes()) != 1 || !reset && len(telemetry.load.Nodes()) != before+1 {
			t.Fatalf("normalized window reset=%v, nodes=%d before=%d", reset, len(telemetry.load.Nodes()), before)
		}
		for _, metric := range []struct {
			name string
			want float64
		}{{"capacity_cpu_request", float64(request.CPU)}, {"capacity_memory_request", float64(request.MemoryBytes)}} {
			result := usage.usage.History.Range(observability.HistoryQuery{Metric: metric.name,
				Labels: map[string]string{"node": node, "service": tsauth.Role}, Start: start, End: time.Now().Add(time.Second)})
			if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != metric.want {
				t.Fatalf("durable %s used latest spec instead of committed requests: %+v", metric.name, result)
			}
		}
		for _, signal := range []struct {
			name autoscale.SignalName
			want float64
		}{{autoscale.SignalCPUUtilization, cpu / float64(request.CPU)}, {autoscale.SignalMemoryUtilization, float64(memory) / float64(request.MemoryBytes)}} {
			reading, err := telemetry.load.Read(t.Context(), autoscale.Target{Cell: "gru", Environment: "test", Role: tsauth.Role},
				autoscale.Signal{Name: signal.name, WindowSeconds: 10}, at.Add(5*time.Second))
			if err != nil || reading.Samples == 0 || reading.Value != signal.want {
				t.Fatalf("normalized %s=%+v, want %v: %v", signal.name, reading, signal.want, err)
			}
		}
	}
	check("report-a", auth.Resources, false)
	bProfile := cloneNativeProfile(auth)
	bProfile.Resources = placement.Resources{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 2 << 30}
	bProfile.Env["NONSECRET_SETTING"] = "B"
	profiles[tsauth.Role] = bProfile
	b := f.binding(t, tsauth.Role, bProfile, f.adopt(t, profiles, 2), 2)
	f.save(t, tsauth.Role, nativeReleaseHistory{Schema: 1, Good: []nativeGoodRelease{good}, Pending: &b, Previous: &good})
	check("adopted-b-serving-a", auth.Resources, false)
	f.desired(t, b)
	check("serving-b", bProfile.Resources, true)
	recovery := a
	recovery.Intent.OperationID, recovery.Intent.Generation = entityid.New(), 3
	recovery.Fingerprint, err = recovery.Intent.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	f.save(t, tsauth.Role, nativeReleaseHistory{Schema: 1, Good: []nativeGoodRelease{good}, Pending: &b, Previous: &good, Recovery: &recovery})
	f.desired(t, recovery)
	check("recovered-a", auth.Resources, true)
	if !maps.Equal(telemetry.requests, loadRequests(map[string]placement.Resources{terrabase.Role: tb.Resources, tsauth.Role: auth.Resources})) {
		t.Fatal("telemetry cache diverged from committed recovery")
	}
}
