package authority_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func identityHostDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func identityHostStateFixture(t *testing.T, cell string) (identityrekey.HostStateObservation, ed25519.PrivateKey, trust.Keyring, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, _, _ := ed25519.GenerateKey(rand.Reader)
	newSigner, _, _ := ed25519.GenerateKey(rand.Reader)
	o := identityrekey.HostStateObservation{OperationID: entityid.Derive("handoff", cell), DeploymentID: entityid.Derive("deployment", cell),
		ClusterID: entityid.Derive("cluster", cell), Cell: cell, Environment: "production", CheckpointSHA256: strings.Repeat("a", 64),
		EpochFloor: 9, Epoch: 10, PreviousResponseKey: base64.StdEncoding.EncodeToString(oldSigner), ResponseKey: base64.StdEncoding.EncodeToString(newSigner),
		AgentsStoppedAt: now.Add(-identityrekey.HostStateQuiescence), ObservedAt: now}
	nodes := []string{"gru-1-ctl-1", "ts-gru-2", "gru-1-ctl-3", "gru-1-ctl-2"}
	if cell == "SFO" {
		nodes = []string{"ts-sfo-1", "ts-sfo-2", "ts-sfo-3"}
	}
	token := strings.ToLower(cell)
	for i, node := range nodes {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		user, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		nkey, err := user.PublicKey()
		user.Wipe()
		if err != nil {
			t.Fatal(err)
		}
		csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := hostboot.Static(token, cell, node).CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		instance := fmt.Sprintf("ocid1.instance.oc1.%s.instance%d", catalog.OCIRegion(cell), i+1)
		volume := fmt.Sprintf("ocid1.volume.oc1.%s.volume%d", catalog.OCIRegion(cell), i+1)
		request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: instance, Descriptor: string(descriptor),
			IdentityPublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
			CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
			Nonce:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32)), IssuedAt: now}
		if err := request.Sign(private); err != nil {
			t.Fatal(err)
		}
		requestWire, err := protocol.EncodeJSON(request)
		if err != nil {
			t.Fatal(err)
		}
		r := host.Registration{ID: entityid.Derive("host", token, node), Cell: token, Node: node, Environment: o.Environment,
			Roles: []string{terrabase.Role}, PublicKey: request.IdentityPublicKey, NATSUserPublicKey: nkey, Generation: 7,
			Capacity: host.Capacity{CPU: 2, MemoryBytes: 8 << 30, DiskBytes: 50 << 30}, TerraBaseDataVolumeID: volume}
		d := host.Desired{Cell: token, Node: node, Environment: o.Environment, Role: terrabase.Role, Digest: identityHostDigest([]byte("native binary")),
			Generation: 12, AuthorityEpoch: 8, Args: []string{"member"},
			Env: map[string]string{terrabase.EnvPeerPort: "7000", terrabase.EnvPeers: node + "=10.0.0.1:7000", "TERRABASE_CLUSTER_ID": strings.Repeat("b", 32)}}
		retired := i == 3
		if retired {
			d.Withdrawn, d.Digest, d.Args, d.Env = true, "", nil, nil
		}
		o.Hosts = append(o.Hosts, identityrekey.HostStateHost{InstanceOCID: instance, Registration: r, RegistrationGenerationFloor: 11,
			Retired: retired, EnrollmentRequest: requestWire, Desired: []identityrekey.HostStateDesired{{Target: d, GenerationFloor: 15, AuthorityEpochFloor: 9}},
			Volume: &identityrekey.HostStateVolume{VolumeID: volume, UUID: fmt.Sprintf("12345678-1234-1234-1234-%012d", i+1),
				FileSystemType: "ext4", DataPath: "/srv/terrabase/data", NativeClusterID: strings.Repeat("b", 32),
				StateRoot: "/var/lib/terrascale-orchestrator-host/state", ConsumedMarkerSHA256: strings.Repeat("c", 64), Mounted: true}})
		predecessor := func(bucket, key string, present bool) {
			p := identityrekey.HostStatePrecondition{Bucket: bucket, Key: key}
			if present {
				p.Revision, p.SHA256 = uint64(len(o.Preconditions)+1), identityHostDigest([]byte("obsolete bytes; deliberately not JSON"))
			}
			o.Preconditions = append(o.Preconditions, p)
		}
		for _, kind := range []string{"registration", "retirement", "desired"} {
			key := token + "." + node
			if kind == "desired" {
				key += ".terrabase"
			}
			predecessor(authority.ControlStreamName, protocol.Control(token, "host", kind, key), kind != "retirement")
		}
		predecessor("TS_HOST_STATE", "session."+token+"."+node, true)
		predecessor("TS_HOST_STATE", "retired."+token+"."+node, retired)
		predecessor("TS_HOST_STATE", "retirement-quarantine."+token+"."+node, false)
		for _, prefix := range []string{"cycle", "report", "desired"} {
			predecessor("TS_HOST_STATE", prefix+"."+token+"."+node+".terrabase", true)
		}
		predecessor(hostenroll.GrantBucket, identityHostDigest([]byte(instance)), true)
		predecessor(hostenroll.GrantBucket, entityid.Derive("host-enrollment", instance), false)
		predecessor("TS_HOST_STATE", "terrabase-format."+token+"."+node+"."+identityHostDigest([]byte(volume)), true)
		predecessor("TS_HOST_STATE", entityid.Derive("terrabase-format", token, node, volume), false)
	}
	o.Preconditions = append(o.Preconditions, identityrekey.HostStatePrecondition{Bucket: "TS_HOST_STATE", Key: "retirement-cutover." + token})
	return o, root, roots, now
}

func TestHeldIdentityHostRecordsVerifiedStaticGRUSFOAndRetiredHeads(t *testing.T) {
	for _, cell := range []string{"GRU", "SFO"} {
		t.Run(cell, func(t *testing.T) {
			observed, root, roots, now := identityHostStateFixture(t, cell)
			lower := strings.ToLower(cell)
			broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			go broker.Start()
			t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
			if !broker.ReadyForConnections(5 * time.Second) {
				t.Fatal("test NATS did not start")
			}
			conn, err := nats.Connect(broker.ClientURL())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(conn.Close)
			js, err := jetstream.New(conn)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName, Subjects: []string{protocol.ControlStreamSubject()}, Retention: jetstream.LimitsPolicy, Storage: jetstream.FileStorage, Replicas: 1, MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1, DenyDelete: true, DenyPurge: true, Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
			if err != nil {
				t.Fatal(err)
			}
			buckets := map[string]jetstream.KeyValue{}
			for _, name := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE", "TS_HOST_ENROLLMENT"} {
				kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: name, Replicas: 1, History: 8, Storage: jetstream.FileStorage})
				if err != nil {
					t.Fatal(err)
				}
				buckets[name] = kv
			}
			old := []byte("obsolete retired and active identity, deliberately undecodable")
			for i, p := range observed.Preconditions {
				if p.Revision == 0 {
					continue
				}
				var revision uint64
				if p.Bucket == authority.ControlStreamName {
					ack, err := js.Publish(t.Context(), p.Key, old)
					if err != nil {
						t.Fatal(err)
					}
					revision = ack.Sequence
				} else {
					revision, err = buckets[p.Bucket].Put(t.Context(), p.Key, old)
					if err != nil {
						t.Fatal(err)
					}
				}
				observed.Preconditions[i].Revision = revision
				observed.Preconditions[i].SHA256 = identityHostDigest(old)
			}
			leaseSubject := protocol.Control(lower, "lease")
			oldLease, err := js.Publish(t.Context(), leaseSubject, old)
			if err != nil {
				t.Fatal(err)
			}
			mutations, err := authority.OpenReader(t.Context(), js, lower)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := host.NewReader(t.Context(), host.ReaderConfig{Cell: lower, Conn: conn, JS: js, State: buckets["TS_HOST_STATE"], StateReplicas: 1, HostMutations: mutations, ControlLog: stream})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ListHosts(t.Context()); err == nil {
				t.Fatal("obsolete registration fixture is readable")
			}
			plan, err := identityrekey.BuildHostStateHandoffPlan(observed, now)
			if err != nil {
				t.Fatal(err)
			}
			signedPlan, err := identityrekey.SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := identityrekey.VerifyHostStateHandoffPlan(signedPlan, roots, observed, now)
			if err != nil {
				t.Fatal(err)
			}
			reset := authority.IdentityReset{Version: 1, OperationID: observed.OperationID, DeploymentID: observed.DeploymentID, ClusterID: observed.ClusterID, Scope: lower, Environment: observed.Environment, CheckpointSHA256: observed.CheckpointSHA256, HostStatePlanSHA256: verified.Fingerprint(), LastSequence: oldLease.Sequence, PreviousSequence: oldLease.Sequence, PreviousSHA256: identityHostDigest(old), EpochFloor: observed.EpochFloor, Epoch: observed.Epoch}
			values := [][]byte{[]byte("root-pinned spec"), []byte("root-pinned roots"), []byte("root-pinned material")}
			for i, key := range [][2]string{{"TS_SERVICE_SET", "current"}, {"TS_TRUST_ROOTS", "chain"}, {"TS_TRUST_ROOTS", "material-generations"}} {
				reset.Records = append(reset.Records, authority.IdentityResetRecord{Action: authority.IdentityResetReplaceKV, Bucket: key[0], Key: key[1], SHA256: identityHostDigest(values[i])})
			}
			reset.Records = append(reset.Records, verified.IdentityResetRecords()...)
			values = append(values, verified.Values()...)
			if err := verified.MatchIdentityReset(reset); err != nil {
				t.Fatal(err)
			}
			envelope, err := authority.SignIdentityReset(reset, now, now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			target := authority.IdentityResetTarget{OperationID: reset.OperationID, DeploymentID: reset.DeploymentID, ClusterID: reset.ClusterID, Scope: reset.Scope, Environment: reset.Environment, CheckpointSHA256: reset.CheckpointSHA256, HostStatePlanSHA256: verified.Fingerprint(), Replicas: 1}
			if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, roots, target, now); err != nil {
				t.Fatal(err)
			}
			revisions, err := authority.ReplaceIdentityRecords(t.Context(), js, envelope, roots, target, values, now)
			if err != nil || len(revisions) != len(reset.Records) {
				t.Fatalf("execute verified plan: %v, %v", revisions, err)
			}
			statuses, err := reader.ListHosts(t.Context())
			if err != nil || len(statuses) != len(observed.Hosts) {
				t.Fatalf("canonical host discovery: %d, %v", len(statuses), err)
			}
			active, retired := 0, 0
			for _, status := range statuses {
				reg := status.Registration
				if reg.ID != entityid.Derive("host", lower, reg.Node) || reg.Generation != 12 {
					t.Fatalf("noncanonical registration: %+v", reg)
				}
				if status.Retired {
					retired++
					if reg.Node != "gru-1-ctl-2" {
						t.Fatalf("unexpected inactive host: %s", reg.Node)
					}
				} else {
					active++
				}
			}
			if active != 3 || cell == "GRU" && retired != 1 || cell == "SFO" && retired != 0 {
				t.Fatalf("active=%d retired=%d", active, retired)
			}
			for _, facts := range observed.Hosts {
				entry, err := buckets["TS_HOST_ENROLLMENT"].Get(t.Context(), entityid.Derive("host-enrollment", facts.InstanceOCID))
				if err != nil {
					t.Fatal(err)
				}
				var grant hostenroll.Grant
				if err := protocol.DecodeStrict(entry.Value(), &grant, 512<<10); err != nil {
					t.Fatal(err)
				}
				if grant.Disabled != facts.Retired || facts.Retired && grant.TerminalOperationID != observed.OperationID {
					t.Fatalf("retired grant reactivated: %+v", grant)
				}
				if _, err := buckets["TS_HOST_ENROLLMENT"].Get(t.Context(), identityHostDigest([]byte(facts.InstanceOCID))); !errors.Is(err, jetstream.ErrKeyNotFound) {
					t.Fatalf("old grant not removed: %v", err)
				}
				volume := facts.Volume
				entry, err = buckets["TS_HOST_STATE"].Get(t.Context(), entityid.Derive("terrabase-format", lower, facts.Registration.Node, volume.VolumeID))
				if err != nil {
					t.Fatal(err)
				}
				expected := fmt.Sprintf(`{"uuid":%q}`, volume.UUID)
				if string(entry.Value()) != expected {
					t.Fatalf("format confirmation reopened: %s", entry.Value())
				}
			}
			if _, err := authority.CompleteIdentityReset(t.Context(), js, envelope, roots, target, now); err != nil {
				t.Fatal(err)
			}
			keys, err := buckets["TS_HOST_STATE"].ListKeysFiltered(t.Context(), "retired."+lower+".>", "retirement-quarantine."+lower+".>", "retirement-cutover."+lower)
			if err != nil {
				t.Fatal(err)
			}
			defer keys.Stop()
			for key := range keys.Keys() {
				t.Errorf("completed rekey left obsolete retirement key %s", key)
			}
		})
	}
}
