package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
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
