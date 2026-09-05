package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestControlStreamAssignmentRequiresAdmittedDurableCurrentReplicas(t *testing.T) {
	wanted := ControlStreamAssignment{Name: "GLOBAL_SPEC", Replicas: 3, Servers: []string{"gru-1", "sfo-1", "fra-1"}}
	healthy := func() *jetstream.StreamInfo {
		return &jetstream.StreamInfo{Config: jetstream.StreamConfig{Name: wanted.Name, Replicas: 3, Storage: jetstream.FileStorage}, Cluster: &jetstream.ClusterInfo{Leader: "gru-1", Replicas: []*jetstream.PeerInfo{{Name: "sfo-1", Current: true}, {Name: "fra-1", Current: true}}}}
	}
	if err := verifyControlStreamAssignment(healthy(), wanted); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*jetstream.StreamInfo){
		"memory":     func(i *jetstream.StreamInfo) { i.Config.Storage = jetstream.MemoryStorage },
		"wrong peer": func(i *jetstream.StreamInfo) { i.Cluster.Replicas[0].Name = "unadmitted" },
		"duplicate":  func(i *jetstream.StreamInfo) { i.Cluster.Replicas[0].Name = "gru-1" },
		"lag":        func(i *jetstream.StreamInfo) { i.Cluster.Replicas[0].Lag = 1 },
		"offline":    func(i *jetstream.StreamInfo) { i.Cluster.Replicas[0].Offline = true },
		"no leader":  func(i *jetstream.StreamInfo) { i.Cluster.Leader = "" },
	} {
		t.Run(name, func(t *testing.T) {
			i := healthy()
			mutate(i)
			if verifyControlStreamAssignment(i, wanted) == nil {
				t.Fatal("accepted invalid replica evidence")
			}
		})
	}
	degraded := healthy()
	degraded.Cluster.Replicas[0].Offline = true
	if verifyControlStreamAssignment(degraded, wanted) == nil {
		t.Fatal("degraded quorum admitted for promotion")
	}
	if err := verifyControlStreamAssignmentMode(degraded, wanted, true); err != nil {
		t.Fatal(err)
	}
	degraded.Cluster.Replicas[1].Offline = true
	if verifyControlStreamAssignmentMode(degraded, wanted, true) == nil {
		t.Fatal("minority counted as available")
	}
}

func TestControlMembershipReadVerifiesLivePinnedSignedRecord(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bucket, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "ORCH_RUNTIME", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	leases, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leases.Put(ctx, "authority.regional", []byte("first")); err != nil {
		t.Fatal(err)
	}
	revision, err := leases.Put(ctx, "authority.regional", []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	leaseMessage, err := readControlLeaseFromLeader(ctx, conn, "authority.regional")
	if err != nil || leaseMessage.Sequence != revision || string(leaseMessage.Data) != "second" {
		t.Fatalf("leader lease read: %+v %v", leaseMessage, err)
	}
	if err := leases.Delete(ctx, "authority.regional"); err != nil {
		t.Fatal(err)
	}
	if _, err := readControlLeaseFromLeader(ctx, conn, "authority.regional"); err == nil {
		t.Fatal("deleted authority lease accepted")
	}
	identity, err := directory.RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Dispose()
	now := time.Now().UTC()
	record := directory.RegionalRuntimeMember{SchemaVersion: protocol.ProtocolVersion.Current(), Cell: "gru", Cluster: "orchestrator-control-gru", Instance: "gru-1", SessionId: strings.Repeat("a", 32), Build: "test", Capabilities: []string{"control"}, StartedAt: now.Add(-time.Minute), ObservedAt: now, LeaseExpiresAt: now.Add(30 * time.Second), AuthorityState: "leader", IsAuthorityLeader: true, AuthorityEpoch: 1, AuthorityRevision: 1, IdentityKeyId: identity.KeyId, IdentityPublicKey: identity.PublicKey}
	pin := ControlRuntimeMember{Region: "gru", Instance: "gru-1", IdentityPublicKey: identity.PublicKey}
	put := func(r directory.RegionalRuntimeMember) {
		t.Helper()
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = bucket.Put(ctx, "controller.gru-1", raw); err != nil {
			t.Fatal(err)
		}
	}
	record.IdentitySignature = identity.Sign(record)
	put(record)
	if _, err := readControlMember(ctx, js, pin); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*directory.RegionalRuntimeMember){
		"stale": func(r *directory.RegionalRuntimeMember) {
			r.ObservedAt = now.Add(-40 * time.Second)
			r.LeaseExpiresAt = now.Add(10 * time.Second)
		},
		"future": func(r *directory.RegionalRuntimeMember) {
			r.ObservedAt = now.Add(20 * time.Second)
			r.LeaseExpiresAt = now.Add(40 * time.Second)
		},
		"expired": func(r *directory.RegionalRuntimeMember) {
			r.ObservedAt = now.Add(-20 * time.Second)
			r.LeaseExpiresAt = now.Add(-time.Second)
		},
		"wrong instance": func(r *directory.RegionalRuntimeMember) { r.Instance = "gru-2" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := record
			mutate(&bad)
			bad.IdentitySignature = identity.Sign(bad)
			put(bad)
			if _, err := readControlMember(ctx, js, pin); err == nil {
				t.Fatal("accepted invalid signed membership")
			}
		})
	}
	tampered := record
	tampered.Build = "tampered"
	put(tampered)
	if _, err := readControlMember(ctx, js, pin); err == nil {
		t.Fatal("accepted tampered signature")
	}
	put(record)
	pin.IdentityPublicKey = "unadmitted"
	if _, err := readControlMember(ctx, js, pin); err == nil {
		t.Fatal("accepted unpinned identity")
	}
}

func TestControlLaunchManifestPreservesArtifactAndVersionsConfiguration(t *testing.T) {
	input := hostagent.HostManifest{Components: []hostagent.ComponentSpec{{Name: "orchestrator", Version: "1.2.3", ArtifactURL: "https://releases.terrascale.tech/orchestrator/1.2.3/orchestrator", SignatureURL: "https://releases.terrascale.tech/orchestrator/1.2.3/orchestrator.sig", Sha256: strings.Repeat("ab", 32), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 200, MemoryMaxBytes: 1 << 30, IOWeight: 300, Arguments: "--config @config", Configuration: "revision = 1\n"}}}
	first, err := PlanControlLaunchManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PlanControlLaunchManifest(first)
	if err != nil {
		t.Fatal(err)
	}
	if first.Components[0].Version != again.Components[0].Version {
		t.Fatal("launch revision is not stable")
	}
	input.Components[0].Configuration = "revision = 2\n"
	second, err := PlanControlLaunchManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Components[0].Version == second.Components[0].Version {
		t.Fatal("configuration update reused immutable slot")
	}
	for _, component := range []hostagent.ComponentSpec{first.Components[0], second.Components[0]} {
		original := input.Components[0]
		if component.ArtifactURL != original.ArtifactURL || component.SignatureURL != original.SignatureURL || component.Sha256 != original.Sha256 {
			t.Fatal("artifact identity changed")
		}
	}
}

func TestControlNATSRejectsWeakTransportBeforeDial(t *testing.T) {
	for _, config := range []*tls.Config{{MinVersion: tls.VersionTLS12}, {MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, {MinVersion: tls.VersionTLS13, ServerName: "other.example"}} {
		_, err := openControlNATS(context.Background(), ControlNATSStore{URL: "tls://127.0.0.1:1", Options: []nats.Option{nats.Secure(config)}})
		if !errors.Is(err, ErrControlRuntimeUnavailable) {
			t.Fatalf("weak transport reached dial: %v", err)
		}
	}
}

func TestControlPlanRequiresWholeTopologyAndPinnedMemberProofs(t *testing.T) {
	r := &NATSControlRuntime{config: NATSControlRuntimeConfig{Stores: map[string]ControlNATSStore{"global": {}, "regional": {}}}, members: map[string]ControlRuntimeMember{}}
	servers := []string{"gru-1", "sfo-1", "fra-1"}
	ids := []string{"one", "two", "three"}
	for i, id := range ids {
		r.members[id] = ControlRuntimeMember{MemberID: id, ServerName: servers[i], Region: []string{"gru", "sfo", "fra"}[i], Store: "regional"}
	}
	makePlan := func() ControlRuntimeActionPlan {
		global := ControlStoreCheck{Store: "global", Region: "gru", AuthorityID: "global", LeaseKey: "authority.global", AuthorityTerm: 1}
		for _, name := range globalControlStreamNames() {
			global.Streams = append(global.Streams, ControlStreamAssignment{Name: name, Replicas: 3, Servers: append([]string(nil), servers...)})
		}
		checks := []ControlStoreCheck{global}
		for i, id := range ids {
			checks = append(checks, ControlStoreCheck{Store: "regional", Region: []string{"gru", "sfo", "fra"}[i], AuthorityID: []string{"gru", "sfo", "fra"}[i] + "-regional", LeaseKey: "authority.regional", AuthorityTerm: 1, Members: []string{id}, Streams: []ControlStreamAssignment{{Name: "KV_ORCH_LEADERS", Replicas: 1, Servers: servers[i : i+1]}, {Name: "KV_ORCH_RUNTIME", Replicas: 1, Servers: servers[i : i+1]}}})
		}
		return ControlRuntimeActionPlan{Kind: ControlActionVerifyQuorum, Region: "gru", ExpectedEpoch: 2, TargetEpoch: 2, Checks: checks}
	}
	if err := r.validatePlan(makePlan()); err != nil {
		t.Fatalf("full proof rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ControlRuntimeActionPlan){
		"partial topology":     func(p *ControlRuntimeActionPlan) { p.Checks[0].Streams = p.Checks[0].Streams[:1] },
		"unadmitted server":    func(p *ControlRuntimeActionPlan) { p.Checks[0].Streams[0].Servers[0] = "other" },
		"missing member proof": func(p *ControlRuntimeActionPlan) { p.Checks = p.Checks[:1] },
		"wrong replicas": func(p *ControlRuntimeActionPlan) {
			p.Checks[0].Streams[0].Replicas = 1
			p.Checks[0].Streams[0].Servers = p.Checks[0].Streams[0].Servers[:1]
		},
		"unproved update": func(p *ControlRuntimeActionPlan) {
			p.ReplicaUpdates = []ControlReplicaPlan{{Store: "global", Streams: []string{"OTHER"}, Replicas: 3}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := makePlan()
			mutate(&p)
			if r.validatePlan(p) == nil {
				t.Fatal("incomplete proof admitted")
			}
		})
	}
}

func TestControlCandidateSynchronizationRequiresExactFullTopology(t *testing.T) {
	r := &NATSControlRuntime{config: NATSControlRuntimeConfig{Stores: map[string]ControlNATSStore{"source": {}, "candidate": {}}}, members: map[string]ControlRuntimeMember{"candidate": {Region: "sfo", Store: "candidate", ServerName: "sfo-1"}}}
	makePlan := func() ControlRuntimeActionPlan {
		check := ControlStoreCheck{Store: "candidate", Region: "sfo", AuthorityID: "sfo-regional", LeaseKey: "authority.regional", AuthorityTerm: 1, Members: []string{"candidate"}, Streams: []ControlStreamAssignment{{Name: "KV_ORCH_LEADERS", Replicas: 1, Servers: []string{"sfo-1"}}, {Name: "KV_ORCH_RUNTIME", Replicas: 1, Servers: []string{"sfo-1"}}}}
		for _, name := range globalControlStreamNames() {
			check.Mirrors = append(check.Mirrors, ControlMirrorPlan{Store: "candidate", Name: "MIRROR_" + name, SourceStore: "source", SourceStream: name, ExternalAPIPrefix: "$JS.global.API"})
		}
		return ControlRuntimeActionPlan{Kind: ControlActionSyncCandidate, Region: "sfo", ExpectedEpoch: 1, TargetEpoch: 1, Checks: []ControlStoreCheck{check}}
	}
	if err := r.validatePlan(makePlan()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ControlRuntimeActionPlan){
		"missing":          func(p *ControlRuntimeActionPlan) { p.Checks[0].Mirrors = p.Checks[0].Mirrors[1:] },
		"duplicate":        func(p *ControlRuntimeActionPlan) { p.Checks[0].Mirrors[1] = p.Checks[0].Mirrors[0] },
		"unexpected":       func(p *ControlRuntimeActionPlan) { p.Checks[0].Mirrors[0].SourceStream = "OTHER" },
		"different source": func(p *ControlRuntimeActionPlan) { p.Checks[0].Mirrors[0].SourceStore = "candidate" },
	} {
		t.Run(name, func(t *testing.T) {
			p := makePlan()
			mutate(&p)
			if r.validatePlan(p) == nil {
				t.Fatal("incomplete synchronization accepted")
			}
		})
	}
}

func TestEmptyControlMirrorRequiresStableDurableMetadata(t *testing.T) {
	source := jetstream.StreamInfo{Config: jetstream.StreamConfig{Name: "GLOBAL_SPEC", Storage: jetstream.FileStorage, Replicas: 1}, State: jetstream.StreamState{FirstSeq: 1}}
	mirror := jetstream.StreamInfo{Config: jetstream.StreamConfig{Name: "MIRROR_GLOBAL_SPEC", Storage: jetstream.FileStorage, Replicas: 1, Mirror: &jetstream.StreamSource{Name: "GLOBAL_SPEC"}}, State: source.State}
	digest, err := verifyEmptyControlMirror(&source, &source, &mirror)
	if err != nil || !canonicalControlDigest(digest) {
		t.Fatalf("empty store metadata not proved: %s %v", digest, err)
	}
	for name, mutate := range map[string]func(*jetstream.StreamInfo){
		"source advanced":  func(i *jetstream.StreamInfo) { i.State.LastSeq = 1 },
		"message appeared": func(i *jetstream.StreamInfo) { i.State.Msgs = 1 },
		"config changed":   func(i *jetstream.StreamInfo) { i.Config.MaxMsgs = 100 },
		"memory":           func(i *jetstream.StreamInfo) { i.Config.Storage = jetstream.MemoryStorage },
	} {
		t.Run(name, func(t *testing.T) {
			after := source
			mutate(&after)
			if _, err := verifyEmptyControlMirror(&source, &after, &mirror); err == nil {
				t.Fatal("unstable empty state proved")
			}
		})
	}
	mirror.State.LastSeq = 10
	if _, err := verifyEmptyControlMirror(&source, &source, &mirror); err == nil {
		t.Fatal("different mirror watermark accepted")
	}
}

func TestGlobalControlInventoryContainsOnlyCurrentControlAndDeliveryStores(t *testing.T) {
	expected := []string{"GLOBAL_SPEC", "KV_GLOBAL_CELLS", "KV_GLOBAL_DELIVERIES", "KV_ORCH_LEADERS"}
	actual := globalControlStreamNames()
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("bootstrap global inventory=%v", actual)
	}
}
