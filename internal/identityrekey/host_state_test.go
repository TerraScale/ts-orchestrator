package identityrekey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
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

func cloneHostStateObservation(t *testing.T, o HostStateObservation) HostStateObservation {
	t.Helper()
	wire, err := protocol.EncodeJSON(o)
	if err != nil {
		t.Fatal(err)
	}
	var copy HostStateObservation
	if err := protocol.DecodeStrict(wire, &copy, MaxHostStatePlanBytes); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestHostStateHandoffCanonicalRootPins(t *testing.T) {
	for _, cell := range []string{"GRU", "SFO"} {
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

func TestHostStateHandoffRequiresRetirementPredecessorOrAbsence(t *testing.T) {
	observed, _, _, now := hostStateFixture(t, "GRU")
	for _, previous := range observed.Preconditions {
		if previous.Bucket != hostStateBucket || !(strings.HasPrefix(previous.Key, "retired.") || strings.HasPrefix(previous.Key, "retirement-quarantine.") || strings.HasPrefix(previous.Key, "retirement-cutover.")) {
			continue
		}
		t.Run(previous.Key, func(t *testing.T) {
			changed := cloneHostStateObservation(t, observed)
			changed.Preconditions = slices.DeleteFunc(changed.Preconditions, func(p HostStatePrecondition) bool { return p.Key == previous.Key && p.Bucket == previous.Bucket })
			if _, err := BuildHostStateHandoffPlan(changed, now); !errors.Is(err, ErrHostStateHandoff) {
				t.Fatalf("missing retirement observation admitted: %v", err)
			}
		})
	}
}

func TestHostStateHandoffStaticTerraBaseWithoutBlockVolume(t *testing.T) {
	for _, cell := range []string{"GRU", "SFO"} {
		t.Run(cell, func(t *testing.T) {
			observed, root, roots, now := hostStateFixture(t, cell)
			volumeKeys := map[string]bool{}
			for i := range observed.Hosts {
				facts := &observed.Hosts[i]
				volumeKeys["terrabase-format."+strings.ToLower(cell)+"."+facts.Registration.Node+"."+sha256Hex([]byte(facts.Volume.VolumeID))] = true
				volumeKeys[entityid.Derive("terrabase-format", strings.ToLower(cell), facts.Registration.Node, facts.Volume.VolumeID)] = true
				facts.Registration.TerraBaseDataVolumeID, facts.Volume = "", nil
			}
			observed.Preconditions = slices.DeleteFunc(observed.Preconditions, func(p HostStatePrecondition) bool {
				return p.Bucket == hostStateBucket && volumeKeys[p.Key]
			})
			plan, err := BuildHostStateHandoffPlan(observed, now)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyHostStateHandoffPlan(envelope, roots, observed, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range verified.Records() {
				if record.Pin.Bucket == hostStateBucket && record.Action == HostStateReplaceKV || volumeKeys[record.Pin.Key] {
					t.Fatal("host without a block volume received format authority")
				}
			}
		})
	}
}

func TestHostStateHandoffRejectsUnsafeFacts(t *testing.T) {
	o, _, _, now := hostStateFixture(t, "GRU")
	for _, test := range []struct {
		name   string
		mutate func(*HostStateObservation)
	}{
		{"unknown bucket", func(o *HostStateObservation) { o.Preconditions[0].Bucket = "TS_STORAGE_USAGE" }},
		{"unknown key", func(o *HostStateObservation) { o.Preconditions[0].Key += ".foreign" }},
		{"format marker mutation", func(o *HostStateObservation) {
			o.Preconditions[0] = HostStatePrecondition{Bucket: hostStateBucket, Key: "terrabase-data-format"}
		}},
		{"missing predecessor", func(o *HostStateObservation) { o.Preconditions = o.Preconditions[1:] }},
		{"duplicate predecessor", func(o *HostStateObservation) { o.Preconditions = append(o.Preconditions, o.Preconditions[0]) }},
		{"absent predecessor bytes", func(o *HostStateObservation) { o.Preconditions[0].Revision = 0 }},
		{"wrong host", func(o *HostStateObservation) { o.Hosts[0].Registration.Node = "ts-gru-9" }},
		{"wrong host ID", func(o *HostStateObservation) { o.Hosts[0].Registration.ID = entityid.New() }},
		{"wrong instance", func(o *HostStateObservation) { o.Hosts[0].InstanceOCID += "foreign" }},
		{"wrong role", func(o *HostStateObservation) { o.Hosts[0].Desired[0].Target.Role = "ts-auth" }},
		{"wrong environment", func(o *HostStateObservation) { o.Hosts[0].Desired[0].Target.Environment = "canary" }},
		{"wrong volume", func(o *HostStateObservation) { o.Hosts[0].Volume.VolumeID += "foreign" }},
		{"missing volume", func(o *HostStateObservation) { o.Hosts[0].Volume = nil }},
		{"unregistered volume", func(o *HostStateObservation) { o.Hosts[0].Registration.TerraBaseDataVolumeID = "" }},
		{"blank device", func(o *HostStateObservation) { o.Hosts[0].Volume.Mounted = false }},
		{"invalid UUID", func(o *HostStateObservation) { o.Hosts[0].Volume.UUID = "reset" }},
		{"native identity mismatch", func(o *HostStateObservation) { o.Hosts[0].Volume.NativeClusterID = strings.Repeat("d", 32) }},
		{"missing consumed marker", func(o *HostStateObservation) { o.Hosts[0].Volume.ConsumedMarkerSHA256 = "" }},
		{"wrong filesystem", func(o *HostStateObservation) { o.Hosts[0].Volume.FileSystemType = "xfs" }},
		{"invalid path", func(o *HostStateObservation) { o.Hosts[0].Volume.DataPath = "/srv/../data" }},
		{"registration floor", func(o *HostStateObservation) { o.Hosts[0].RegistrationGenerationFloor = 6 }},
		{"exhausted generation", func(o *HostStateObservation) { o.Hosts[0].Desired[0].GenerationFloor = ^uint64(0) }},
		{"desired floor", func(o *HostStateObservation) { o.Hosts[0].Desired[0].GenerationFloor = 11 }},
		{"durable epoch floor", func(o *HostStateObservation) { o.Hosts[0].Desired[0].AuthorityEpochFloor = o.Epoch }},
		{"reset epoch floor", func(o *HostStateObservation) { o.Epoch = o.EpochFloor }},
		{"old sessions alive", func(o *HostStateObservation) { o.AgentsStoppedAt = now.Add(-30 * time.Second) }},
		{"signer unchanged", func(o *HostStateObservation) { o.ResponseKey = o.PreviousResponseKey }},
		{"managed shape", func(o *HostStateObservation) { o.Hosts[0].Registration.ManagedOCI = &host.ManagedOCIBinding{} }},
		{"retired active desired", func(o *HostStateObservation) { o.Hosts[0].Retired = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := cloneHostStateObservation(t, o)
			test.mutate(&copy)
			if _, err := BuildHostStateHandoffPlan(copy, now); err == nil {
				t.Fatal("unsafe facts authorized a handoff")
			}
		})
	}
}

func TestHostStateHandoffRejectsStaleOrUnpinnedAuthority(t *testing.T) {
	o, root, roots, now := hostStateFixture(t, "GRU")
	plan, err := BuildHostStateHandoffPlan(o, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*HostStateObservation)
	}{
		{"deployment", func(o *HostStateObservation) { o.DeploymentID = entityid.New() }},
		{"cluster", func(o *HostStateObservation) { o.ClusterID = entityid.New() }},
		{"checkpoint", func(o *HostStateObservation) { o.CheckpointSHA256 = strings.Repeat("e", 64) }},
		{"stale revision", func(o *HostStateObservation) { o.Preconditions[0].Revision++ }},
		{"stale opaque digest", func(o *HostStateObservation) { o.Preconditions[0].SHA256 = strings.Repeat("d", 64) }},
		{"new floor", func(o *HostStateObservation) { o.Hosts[0].RegistrationGenerationFloor++ }},
		{"data path", func(o *HostStateObservation) { o.Hosts[0].Volume.DataPath = "/srv/foreign/data" }},
		{"native cluster", func(o *HostStateObservation) { o.Hosts[0].Volume.NativeClusterID = strings.Repeat("c", 32) }},
		{"artifact", func(o *HostStateObservation) { o.Hosts[0].Desired[0].Target.Digest = strings.Repeat("d", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := cloneHostStateObservation(t, o)
			test.mutate(&copy)
			if _, err := VerifyHostStateHandoffPlan(envelope, roots, copy, now); err == nil {
				t.Fatal("signed plan admitted different independent facts")
			}
		})
	}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHostStateHandoffPlan(forged, roots, o, now); err == nil {
		t.Fatal("foreign root admitted")
	}
	if _, err := VerifyHostStateHandoffPlan(envelope, roots, o, now.Add(time.Hour)); err == nil {
		t.Fatal("expired root admitted")
	}
	for _, mutate := range []func(*HostStateHandoffPlan){
		func(p *HostStateHandoffPlan) { p.Version = 2 },
		func(p *HostStateHandoffPlan) { p.Records[0].Pin.Key = "unrestricted" },
		func(p *HostStateHandoffPlan) { p.Records[0].Value = []byte(`{"granted":true}`) },
		func(p *HostStateHandoffPlan) { p.Records[0].Action = HostStateReplaceKV },
		func(p *HostStateHandoffPlan) { p.Records = p.Records[1:] },
		func(p *HostStateHandoffPlan) {
			for i, record := range p.Records {
				if record.Action == HostStateReplaceKV && record.Pin.Bucket == hostStateBucket {
					p.Records[i].Value = []byte(`{"uuid":"12345678-1234-1234-1234-000000000001","attempt_id":"0000000000KN642MZ7NB6BSMTV"}`)
					p.Records[i].Pin.SHA256 = sha256Hex(p.Records[i].Value)
					return
				}
			}
		},
	} {
		copy, err := BuildHostStateHandoffPlan(o, now)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&copy)
		if _, err := SignHostStateHandoffPlan(copy, now, now.Add(time.Hour), root); err == nil {
			t.Fatal("unchecked mutations were signed")
		}
	}
}

func TestHostStateHandoffPinsTombstoneOperation(t *testing.T) {
	base, root, roots, now := hostStateFixture(t, "GRU")
	for _, operation := range []string{"DEL", "PURGE"} {
		o := cloneHostStateObservation(t, base)
		o.Hosts = nil
		o.Preconditions = []HostStatePrecondition{{Bucket: hostStateBucket, Key: "retirement-cutover.gru",
			Revision: 71, SHA256: sha256Hex(nil), Operation: operation}}
		plan, err := BuildHostStateHandoffPlan(o, now)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyHostStateHandoffPlan(envelope, roots, o, now)
		if err != nil || len(verified.IdentityResetRecords()) != 1 || verified.IdentityResetRecords()[0].PreviousOperation != operation {
			t.Fatalf("signed %s predecessor not retained: %v", operation, err)
		}
		o.Preconditions[0].Operation = ""
		if _, err := VerifyHostStateHandoffPlan(envelope, roots, o, now); err == nil {
			t.Fatal("changed independently observed operation matched signed plan")
		}
	}
	for _, fault := range []string{"unknown operation", "nonempty data", "absent revision", "control head"} {
		o := cloneHostStateObservation(t, base)
		index := slices.IndexFunc(o.Preconditions, func(p HostStatePrecondition) bool { return p.Bucket == hostStateBucket })
		if fault == "control head" {
			index = 0
		}
		p := &o.Preconditions[index]
		p.Operation, p.SHA256 = "PURGE", sha256Hex(nil)
		switch fault {
		case "unknown operation":
			p.Operation = "PUT"
		case "nonempty data":
			p.SHA256 = sha256Hex([]byte("not a tombstone"))
		case "absent revision":
			p.Revision, p.SHA256 = 0, ""
		}
		if _, err := BuildHostStateHandoffPlan(o, now); err == nil {
			t.Fatalf("invalid %s predecessor admitted", fault)
		}
	}
}

func TestHostStateHandoffMatchesIdentityResetTransaction(t *testing.T) {
	o, root, roots, now := hostStateFixture(t, "GRU")
	plan, err := BuildHostStateHandoffPlan(o, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHostStateHandoffPlan(envelope, roots, o, now)
	if err != nil {
		t.Fatal(err)
	}
	reset := authority.IdentityReset{Version: 1, OperationID: o.OperationID, DeploymentID: o.DeploymentID,
		ClusterID: o.ClusterID, Scope: "gru", Environment: o.Environment, CheckpointSHA256: o.CheckpointSHA256,
		HostStatePlanSHA256: verified.Fingerprint(), EpochFloor: o.EpochFloor, Epoch: o.Epoch,
		LastSequence: 1024, PreviousSequence: 1, PreviousSHA256: strings.Repeat("a", 64),
		Records: []authority.IdentityResetRecord{
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_SERVICE_SET", Key: "current", SHA256: strings.Repeat("a", 64)},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "chain", SHA256: strings.Repeat("a", 64)},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "material-generations", SHA256: strings.Repeat("a", 64)},
		}}
	reset.Records = append(reset.Records, verified.IdentityResetRecords()...)
	if err := verified.MatchIdentityReset(reset); err != nil {
		t.Fatal(err)
	}
	reset.HostStatePlanSHA256 = ""
	if err := verified.MatchIdentityReset(reset); err == nil {
		t.Fatal("missing verified plan fingerprint admitted")
	}
	reset.HostStatePlanSHA256 = strings.Repeat("b", 64)
	if err := verified.MatchIdentityReset(reset); err == nil {
		t.Fatal("different verified plan fingerprint admitted")
	}
	reset.HostStatePlanSHA256 = verified.Fingerprint()
	reset.Records[3].Action = ""
	if err := verified.MatchIdentityReset(reset); err == nil {
		t.Fatal("missing typed action admitted")
	}
	reset.Records[3].Action = verified.IdentityResetRecords()[0].Action
	reset.Records[3].PreviousRevision++
	if err := verified.MatchIdentityReset(reset); err == nil {
		t.Fatal("different transaction predecessor admitted")
	}
	reset.Records[3].PreviousRevision--
	reset.Epoch++
	if err := verified.MatchIdentityReset(reset); err == nil {
		t.Fatal("different transaction epoch admitted")
	}
	if err := (VerifiedHostStateHandoffPlan{}).MatchIdentityReset(reset); err == nil {
		t.Fatal("unverified plan matched transaction")
	}
}

func TestHostStateHandoffNoHostsStillRequiresRegionalRetirementCoverage(t *testing.T) {
	o, root, roots, now := hostStateFixture(t, "GRU")
	o.Hosts = nil
	o.Preconditions = []HostStatePrecondition{{Bucket: hostStateBucket, Key: "retirement-cutover.gru"}}
	plan, err := BuildHostStateHandoffPlan(o, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHostStateHandoffPlan(envelope, roots, o, now)
	if err != nil || !verified.IsVerified() || len(verified.IdentityResetRecords()) != 1 {
		t.Fatalf("verified host-free retirement plan: %+v, %v", verified, err)
	}
	reset := authority.IdentityReset{Version: 1, OperationID: o.OperationID, DeploymentID: o.DeploymentID,
		ClusterID: o.ClusterID, Scope: "gru", Environment: o.Environment, CheckpointSHA256: o.CheckpointSHA256,
		HostStatePlanSHA256: verified.Fingerprint(), EpochFloor: o.EpochFloor, Epoch: o.Epoch,
		LastSequence: 1, PreviousSequence: 1, PreviousSHA256: strings.Repeat("a", 64),
		Records: []authority.IdentityResetRecord{
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_SERVICE_SET", Key: "current", SHA256: strings.Repeat("a", 64)},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "chain", SHA256: strings.Repeat("a", 64)},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "material-generations", SHA256: strings.Repeat("a", 64)},
		}}
	reset.Records = append(reset.Records, verified.IdentityResetRecords()...)
	if err := verified.MatchIdentityReset(reset); err != nil {
		t.Fatal(err)
	}
	if err := reset.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHostStateHandoffHeadsWorkWithHostValidators(t *testing.T) {
	o, _, _, now := hostStateFixture(t, "GRU")
	plan, err := BuildHostStateHandoffPlan(o, now)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		broker.Shutdown()
		t.Fatal("local test broker failed to start")
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName, Subjects: []string{protocol.ControlStreamSubject()},
		Retention: jetstream.LimitsPolicy, Storage: jetstream.FileStorage, Replicas: 1, MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1,
		MaxMsgsPerSubject: -1, DenyDelete: true, DenyPurge: true, Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	state, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: hostStateBucket, History: 2, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "handoff_artifacts", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.PutBytes(t.Context(), "sha256-"+sha256Hex([]byte("native binary")), []byte("native binary")); err != nil {
		t.Fatal(err)
	}
	// The old retired head is intentionally unreadable to the current reader.
	oldSubject := protocol.Control("gru", "host", "registration", "gru.gru-1-ctl-2")
	if _, err := js.Publish(t.Context(), oldSubject, []byte(`{"old_host_id":"sha256:obsolete"}`)); err != nil {
		t.Fatal(err)
	}
	mutations, err := authority.OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := host.NewReader(t.Context(), host.ReaderConfig{Cell: "gru", Conn: conn, JS: js, State: state, StateReplicas: 1, HostMutations: mutations, ControlLog: stream})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ListHosts(t.Context()); err == nil {
		t.Fatal("test did not establish obsolete retired registration failure")
	}
	for _, record := range plan.Records {
		if record.Action == HostStateAppendHead {
			if _, err := js.Publish(t.Context(), record.Pin.Key, record.Value); err != nil {
				t.Fatal(err)
			}
		}
	}
	statuses, err := reader.ListHosts(t.Context())
	if err != nil || len(statuses) != len(o.Hosts) {
		t.Fatalf("canonical host discovery = %d hosts, %v", len(statuses), err)
	}
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	controller, err := host.NewController(t.Context(), host.ControllerConfig{Cell: "gru", Conn: conn, JS: js, State: state,
		StateReplicas: 1, Artifacts: artifacts, HostMutations: mutations, ControlLog: stream, ResponseKey: signer,
		AuthorityEpoch: func() uint64 { return o.Epoch }, AuthorityGuard: func(context.Context, uint64) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Registration.Generation != 12 {
			t.Fatal("registration did not advance beyond durable floor")
		}
		if _, err := controller.Register(t.Context(), status.Registration); err != nil {
			t.Fatalf("existing host registration validator: %v", err)
		}
		if status.Registration.Node == "gru-1-ctl-2" && !status.Retired {
			t.Fatal("inactive registration was reactivated")
		}
	}
	desired, err := reader.ListDesired(t.Context(), "terrabase")
	if err != nil || len(desired) != len(o.Hosts) {
		t.Fatalf("canonical desired discovery = %d targets, %v", len(desired), err)
	}
	for _, d := range desired {
		if d.Generation != 16 || d.AuthorityEpoch != o.Epoch {
			t.Fatal("desired did not advance beyond durable floors")
		}
		if _, err := controller.ApplyDesired(t.Context(), d); err != nil {
			t.Fatalf("existing host desired validator: %v", err)
		}
		for _, facts := range o.Hosts {
			if facts.Registration.Node != d.Node {
				continue
			}
			original := facts.Desired[0].Target
			d.Generation, d.AuthorityEpoch = original.Generation, original.AuthorityEpoch
			got, err := protocol.EncodeJSON(d)
			if err != nil {
				t.Fatal(err)
			}
			want, err := protocol.EncodeJSON(original)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("handoff changed desired digest, execution environment or native identity")
			}
		}
	}
	grants, err := hostenroll.OpenGrantStore(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	grantKV, err := js.KeyValue(t.Context(), hostenroll.GrantBucket)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range plan.Records {
		if record.Action != HostStateReplaceKV || record.Pin.Bucket != hostenroll.GrantBucket {
			continue
		}
		var grant hostenroll.Grant
		if err := protocol.DecodeStrict(record.Value, &grant, 64<<10); err != nil {
			t.Fatal(err)
		}
		if _, err := grantKV.Put(t.Context(), record.Pin.Key, record.Value); err != nil {
			t.Fatal(err)
		}
		if !entityid.Valid(grant.CreateKey) || len(grant.Response)+len(grant.RenewalResponse) != 0 {
			t.Fatal("fresh grant carries obsolete response or create key")
		}
		if grant.Disabled {
			if _, _, err := grants.ClaimRenew(t.Context(), grant.InstanceID, []byte("renewal request"), now); err == nil {
				t.Fatal("retired handoff grant admitted renewal")
			}
			continue
		}
		if grant.IdentityResetOperationID != o.OperationID {
			t.Fatal("active grant lost root reset provenance")
		}
		renewal := []byte("normal renewal after independently verified host request")
		claimed, revision, err := grants.ClaimRenew(t.Context(), grant.InstanceID, renewal, now)
		if err != nil {
			t.Fatalf("active host cannot renew after root handoff: %v", err)
		}
		if _, _, err := grants.ClaimRenew(t.Context(), grant.InstanceID, renewal, now); !errors.Is(err, hostenroll.ErrGrantInProgress) {
			t.Fatalf("handoff renewal is not serialized: %v", err)
		}
		response := []byte("fresh response signed by the replacement authority")
		if err := grants.FinishRenew(t.Context(), claimed, revision, response, now); err != nil {
			t.Fatal(err)
		}
		cached, _, err := grants.ClaimRenew(t.Context(), grant.InstanceID, renewal, now)
		if err != nil || !bytes.Equal(cached.RenewalResponse, response) {
			t.Fatalf("lost renewal reply cannot be recovered: %v", err)
		}
	}
}

func TestHostStateHandoffRetainsHistoricalEnrollmentEvidence(t *testing.T) {
	o, root, roots, now := hostStateFixture(t, "GRU")
	retired := o.Hosts[len(o.Hosts)-1]
	if !retired.Retired {
		t.Fatal("fixture needs retained retired host")
	}
	if _, _, err := hostenroll.ParseRequest(retired.EnrollmentRequest, now); err == nil {
		t.Fatal("live enrollment accepted a 90-day-old request")
	}
	plan, err := BuildHostStateHandoffPlan(o, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignHostStateHandoffPlan(plan, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHostStateHandoffPlan(envelope, roots, o, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range verified.Records() {
		if record.Pin.Bucket != hostenroll.GrantBucket || record.Pin.Key != entityid.Derive("host-enrollment", retired.InstanceOCID) {
			continue
		}
		var grant hostenroll.Grant
		if err := protocol.DecodeStrict(record.Value, &grant, hostenroll.MaxRequestBytes); err != nil {
			t.Fatal(err)
		}
		if !grant.Disabled || grant.InstanceID != retired.InstanceOCID || !bytes.Equal(grant.Request, retired.EnrollmentRequest) {
			t.Fatal("historical grant lost exact evidence or retired fence")
		}
		found = true
	}
	if !found {
		t.Fatal("retired host grant absent")
	}
	for _, fault := range []string{"signature", "registration key", "NATS key", "instance", "future issuance"} {
		t.Run(fault, func(t *testing.T) {
			copy := cloneHostStateObservation(t, o)
			facts := &copy.Hosts[len(copy.Hosts)-1]
			var request hostenroll.Request
			if err := protocol.DecodeStrict(facts.EnrollmentRequest, &request, hostenroll.MaxRequestBytes); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "signature":
				request.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "registration key":
				facts.Registration.PublicKey = o.Hosts[0].Registration.PublicKey
			case "NATS key":
				facts.Registration.NATSUserPublicKey = o.Hosts[0].Registration.NATSUserPublicKey
			case "instance":
				facts.InstanceOCID += "foreign"
			case "future issuance":
				request.IssuedAt = now.Add(time.Hour)
			}
			facts.EnrollmentRequest, err = protocol.EncodeJSON(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildHostStateHandoffPlan(copy, now); err == nil {
				t.Fatal("historical evidence lost identity/signature binding")
			}
		})
	}
}
