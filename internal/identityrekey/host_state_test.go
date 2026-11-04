package identityrekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

func hostStateFixture(t *testing.T, cell string) (HostStateObservation, ed25519.PrivateKey, trust.Keyring, time.Time) {
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
	o := HostStateObservation{OperationID: entityid.Derive("handoff", cell), DeploymentID: entityid.Derive("deployment", cell),
		ClusterID: entityid.Derive("cluster", cell), Cell: cell, Environment: "production", CheckpointSHA256: strings.Repeat("a", 64),
		EpochFloor: 9, Epoch: 10, PreviousResponseKey: base64.StdEncoding.EncodeToString(oldSigner), ResponseKey: base64.StdEncoding.EncodeToString(newSigner),
		AgentsStoppedAt: now.Add(-HostStateQuiescence), ObservedAt: now}
	nodes := []string{"gru-1-ctl-1", "ts-gru-2", "gru-1-ctl-3", "gru-1-ctl-2"}
	if cell == "SJC" {
		nodes = []string{"ts-sjc-1", "ts-sjc-2", "ts-sjc-3"}
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
		if i == 3 {
			request.IssuedAt = now.Add(-90 * 24 * time.Hour)
		}
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
		d := host.Desired{Cell: token, Node: node, Environment: o.Environment, Role: terrabase.Role, Digest: sha256Hex([]byte("native binary")),
			Generation: 12, AuthorityEpoch: 8, Args: []string{"member"},
			Env: map[string]string{terrabase.EnvPeerPort: "7000", terrabase.EnvPeers: node + "=10.0.0.1:7000", "TERRABASE_CLUSTER_ID": strings.Repeat("b", 32)}}
		retired := i == 3
		if retired {
			d.Withdrawn, d.Digest, d.Args, d.Env = true, "", nil, nil
		}
		o.Hosts = append(o.Hosts, HostStateHost{InstanceOCID: instance, Registration: r, RegistrationGenerationFloor: 11,
			Retired: retired, EnrollmentRequest: requestWire, Desired: []HostStateDesired{{Target: d, GenerationFloor: 15, AuthorityEpochFloor: 9}},
			Volume: &HostStateVolume{VolumeID: volume, UUID: fmt.Sprintf("12345678-1234-1234-1234-%012d", i+1),
				FileSystemType: "ext4", DataPath: "/srv/terrabase/data", NativeClusterID: strings.Repeat("b", 32),
				StateRoot: "/var/lib/terrascale-orchestrator-host/state", ConsumedMarkerSHA256: strings.Repeat("c", 64), Mounted: true}})
		predecessor := func(bucket, key string, present bool) {
			p := HostStatePrecondition{Bucket: bucket, Key: key}
			if present {
				p.Revision, p.SHA256 = uint64(len(o.Preconditions)+1), sha256Hex([]byte("obsolete bytes; deliberately not JSON"))
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
		predecessor(hostStateBucket, "session."+token+"."+node, true)
		predecessor(hostStateBucket, "retired."+token+"."+node, retired)
		predecessor(hostStateBucket, "retirement-quarantine."+token+"."+node, false)
		for _, prefix := range []string{"cycle", "report", "desired"} {
			predecessor(hostStateBucket, prefix+"."+token+"."+node+".terrabase", true)
		}
		predecessor(hostenroll.GrantBucket, sha256Hex([]byte(instance)), true)
		predecessor(hostenroll.GrantBucket, entityid.Derive("host-enrollment", instance), false)
		predecessor(hostStateBucket, "terrabase-format."+token+"."+node+"."+sha256Hex([]byte(volume)), true)
		predecessor(hostStateBucket, entityid.Derive("terrabase-format", token, node, volume), false)
	}
	o.Preconditions = append(o.Preconditions, HostStatePrecondition{Bucket: hostStateBucket, Key: "retirement-cutover." + token})
	return o, root, roots, now
}

func TestHostStateHandoffCanonicalRootPins(t *testing.T) {
	for _, cell := range []string{
		"GRU",
	} {
		t.Run(cell, func(t *testing.T) {
			o, root, roots, now := hostStateFixture(t, cell)
			plan, err := BuildHostStateHandoffPlan(o, now)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyHostStateHandoffPlan(envelope, roots, o, now)
			if err != nil || !verified.IsVerified() || verified.Fingerprint() != sha256Hex(envelope.Payload) {
				t.Fatalf("verify canonical handoff = %v", err)
			}
			pins, values := verified.IdentityResetRecords(), verified.Values()
			for i, record := range verified.Records() {
				if pins[i] != record.Pin || !bytes.Equal(values[i], record.Value) {
					t.Fatal("reset pins and replacement values lost ordering")
				}
				if record.Action == HostStateDelete {
					if len(record.Value) != 0 || record.Pin.SHA256 != "" {
						t.Fatal("delete carries replacement authority")
					}
				} else if sha256Hex(record.Value) != record.Pin.SHA256 {
					t.Fatal("replacement differs from root pin")
				}
				if record.Action == HostStateReplaceKV && record.Pin.Bucket == hostStateBucket {
					for _, facts := range o.Hosts {
						if record.Pin.Key == entityid.Derive("terrabase-format", strings.ToLower(cell), facts.Registration.Node, facts.Volume.VolumeID) &&
							string(record.Value) != fmt.Sprintf(`{"uuid":%q}`, facts.Volume.UUID) {
							t.Fatal("existing-volume confirmation changed UUID or grants formatting authority")
						}
					}
				}
			}
			copy := verified.Records()
			copy[0].Pin.Key = "foreign"
			for i, value := range verified.Values() {
				if len(value) != 0 {
					value[0] = '!'
					if bytes.Equal(value, verified.Values()[i]) {
						t.Fatal("verified values leaked mutation")
					}
					break
				}
			}
			if verified.Records()[0].Pin.Key == "foreign" {
				t.Fatal("verified pins leaked mutation")
			}
		})
	}
	if zero := (VerifiedHostStateHandoffPlan{}); zero.IsVerified() || len(zero.Records()) != 0 || len(zero.IdentityResetRecords()) != 0 || len(zero.Values()) != 0 {
		t.Fatal("zero handoff grants mutation authority")
	}
}
