package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/brokeradmission"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func brokerEnrollmentTestMember(t *testing.T, id string, generation uint64) (brokeradmission.Member, map[string]nkeys.KeyPair) {
	t.Helper()
	m := brokeradmission.Member{NodeID: "gru-3", MemberID: id, Region: "gru", Slot: 3, Generation: generation, OperationID: "enroll-" + id, PublicKeys: map[string]string{}}
	keys := map[string]nkeys.KeyPair{}
	for _, role := range brokeradmission.Roles {
		key, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Wipe)
		keys[role] = key
		m.PublicKeys[role], _ = key.PublicKey()
	}
	return m, keys
}
func TestNativeBrokerEnrollmentRevokesConnectedKeysAndPersistsAcrossRestart(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := brokeradmission.NewVerifier(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), signer.PublicKeyID())
	if err != nil {
		t.Fatal(err)
	}
	first, oldKeys := brokerEnrollmentTestMember(t, "01ARZ3NDEKTSV4RRFFQ69G5FAB", 7)
	second, newKeys := brokerEnrollmentTestMember(t, "01ARZ3NDEKTSV4RRFFQ69G5FAC", 8)
	desired := brokeradmission.Desired{Version: 1, Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAA", Revision: 1, AuthorityEpoch: 2, LeaseID: "lease", Members: []brokeradmission.Member{first}}
	controller, _ := nkeys.CreateUser()
	defer controller.Wipe()
	controllerPublic, _ := controller.PublicKey()
	baseline := &server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true, Nkeys: []*server.NkeyUser{{Nkey: controllerPublic}}}
	authorityLost := false
	config := &EnrollmentBrokerConfig{AllowInitialBootstrap: true, Verifier: verifier, CheckpointPath: filepath.Join(t.TempDir(), "grants.json"), Policy: brokeradmission.Policy{Environment: desired.Environment, Cluster: desired.Cluster, Regions: map[string]brokeradmission.Accounts{"gru": {Global: "$G", Regional: "$G", Node: "$G"}}, RegionalPermissions: func(string, string) ([]string, []string, error) {
		return []string{"test.regional"}, []string{"_INBOX.>"}, nil
	}}, CheckAuthority: func(context.Context, brokeradmission.Desired) error {
		if authorityLost {
			return errors.New("authority lost")
		}
		return nil
	}}
	reader, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Wipe()
	readerPublic, _ := reader.PublicKey()
	config.ReaderGrants = []brokeradmission.ReaderGrant{{BrokerID: "broker-gru", PublicNKey: readerPublic, Account: "$G"}}
	config.BrokerIDs = []string{"broker-gru"}
	monitor, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Wipe()
	monitorPublic, _ := monitor.PublicKey()
	baseline.Nkeys = append(baseline.Nkeys, &server.NkeyUser{Nkey: monitorPublic, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: []string{"test.monitor"}}, Subscribe: &server.SubjectPermission{Allow: []string{"_INBOX.>"}}}})
	// Seed the old member's real role grants into the independent initial
	// baseline, then explicitly admit only those keys for enrollment renewal.
	baseline, err = brokeradmission.ApplyOptions(baseline, desired, config.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range brokeradmission.Roles {
		config.Policy.ManagedBaselineNKeys = append(config.Policy.ManagedBaselineNKeys, first.PublicKeys[role])
	}
	deniedBootstrap := *config
	deniedBootstrap.AllowInitialBootstrap = false
	if _, err := prepareEnrollmentBroker(t.Context(), baseline, &deniedBootstrap); err == nil {
		t.Fatal("missing checkpoint silently opened bootstrap grants")
	}
	fourth := first
	fourth.Region = "iad"
	fourth.NodeID = "iad-3"
	expanded := desired
	expanded.Members = []brokeradmission.Member{fourth}
	if err := brokeradmission.Validate(expanded); err != nil {
		t.Fatalf("canonical fourth Region refused: %v", err)
	}
	if _, err := brokeradmission.ApplyOptions(baseline, expanded, config.Policy); err == nil {
		t.Fatal("unadmitted fourth Region accepted")
	}
	expandedPolicy := config.Policy
	expandedPolicy.Regions = map[string]brokeradmission.Accounts{"iad": {Global: "$G", Regional: "$G", Node: "$G"}}
	if _, err := brokeradmission.ApplyOptions(baseline, expanded, expandedPolicy); err != nil {
		t.Fatalf("admitted fourth Region refused: %v", err)
	}
	state, err := prepareEnrollmentBroker(t.Context(), baseline, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareEnrollmentBroker(t.Context(), baseline, config); err == nil {
		t.Fatal("consumed initial bootstrap reused after checkpoint loss")
	}
	instance, err := server.NewServer(state.options)
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	defer instance.Shutdown()
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker not ready")
	}
	handle := &NatsServer{instance: instance, enrollment: state}
	firstWire, err := brokeradmission.Sign(desired, signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"ancestor symlink", "writable ancestor", "leaf symlink", "hardlink"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "state")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "grants.json")
			if err := brokeradmission.PersistCheckpoint(path, firstWire); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "ancestor symlink":
				link := filepath.Join(root, "alias")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "grants.json")
			case "writable ancestor":
				if err := os.Chmod(directory, 0777); err != nil {
					t.Fatal(err)
				}
			case "leaf symlink":
				link := filepath.Join(directory, "alias")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := brokeradmission.ReadCheckpoint(path, verifier); err == nil {
				t.Fatal("unsafe checkpoint read accepted")
			}
			if err := brokeradmission.PersistCheckpoint(path, firstWire); err == nil {
				t.Fatal("unsafe checkpoint write accepted")
			}
			if err := brokeradmission.ClaimInitialBootstrap(path); err == nil {
				t.Fatal("unsafe bootstrap marker accepted")
			}
		})
	}
	for _, role := range brokeradmission.Roles {
		for _, retired := range []bool{false, true} {
			protected := first
			protected.PublicKeys = maps.Clone(first.PublicKeys)
			protected.PublicKeys[role] = readerPublic
			hostile := desired
			hostile.Members = []brokeradmission.Member{protected}
			if retired {
				hostile.Members = nil
				hostile.Retired = []brokeradmission.Retired{{Member: protected, RemovalOperationID: "remove-reader", ResourceID: "ocid1.instance.reader"}}
			}
			hostileWire, err := brokeradmission.Sign(hostile, signer)
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.ApplyEnrollmentGrants(t.Context(), hostileWire); !errors.Is(err, brokeradmission.ErrInvalid) {
				t.Fatalf("delegated signer repurposed reader as %s (retired=%v): %v", role, retired, err)
			}
		}
	}
	for name, public := range map[string]string{"controller": controllerPublic, "monitor": monitorPublic} {
		for _, retire := range []bool{false, true} {
			badMember := first
			badMember.PublicKeys = maps.Clone(first.PublicKeys)
			badMember.PublicKeys["node"] = public
			badDesired := desired
			if retire {
				badDesired.Members = nil
				badDesired.Retired = []brokeradmission.Retired{{Member: badMember, RemovalOperationID: "remove-owner", ResourceID: "ocid1.instance.owner"}}
			} else {
				badDesired.Members = []brokeradmission.Member{badMember}
			}
			badWire, e := brokeradmission.Sign(badDesired, signer)
			if e != nil {
				t.Fatal(e)
			}
			if e := handle.ApplyEnrollmentGrants(t.Context(), badWire); e == nil {
				t.Fatalf("delegated signer changed unmanaged %s baseline key (retire=%v)", name, retire)
			}
		}
	}
	if err := handle.ApplyEnrollmentGrants(t.Context(), firstWire); err != nil {
		t.Fatal(err)
	}
	connect := func(instance *server.Server, key nkeys.KeyPair) (*nats.Conn, error) {
		pub, _ := key.PublicKey()
		return nats.Connect(instance.ClientURL(), nats.Nkey(pub, key.Sign), nats.NoReconnect(), nats.Timeout(time.Second))
	}
	connected := []*nats.Conn{}
	for _, role := range brokeradmission.Roles {
		c, err := connect(instance, oldKeys[role])
		if err != nil {
			t.Fatalf("initial %s: %v", role, err)
		}
		defer c.Close()
		connected = append(connected, c)
	}
	desired.Revision++
	desired.Members = []brokeradmission.Member{second}
	desired.Retired = []brokeradmission.Retired{{Member: first, RemovalOperationID: "remove-old", ResourceID: "ocid1.instance.old"}}
	for _, scenario := range []string{"missing retirement", "stale generation", "stale authority"} {
		bad := desired
		switch scenario {
		case "missing retirement":
			bad.Retired = nil
		case "stale generation":
			stale := second
			stale.Generation = first.Generation
			bad.Members = []brokeradmission.Member{stale}
		case "stale authority":
			bad.AuthorityEpoch = 1
		}
		badWire, e := brokeradmission.Sign(bad, signer)
		if e != nil {
			t.Fatal(e)
		}
		if e := handle.ApplyEnrollmentGrants(t.Context(), badWire); !errors.Is(e, brokeradmission.ErrRollback) {
			t.Fatalf("%s accepted: %v", scenario, e)
		}
	}
	wire, err := brokeradmission.Sign(desired, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Force a real native reload rejection after the signed checkpoint write.
	// Retry must retain the new revision and must not acknowledge old grants.
	originalHost := state.baseline.Host
	state.baseline.Host = "127.0.0.2"
	if err := handle.ApplyEnrollmentGrants(t.Context(), wire); err == nil {
		t.Fatal("unsupported native host reload succeeded")
	}
	state.baseline.Host = originalHost
	if state.applied || state.desired.Revision != desired.Revision {
		t.Fatal("failed reload lost pending desired state")
	}
	_, checkpoint, err := brokeradmission.ReadCheckpoint(config.CheckpointPath, verifier)
	if err != nil || checkpoint.Revision != desired.Revision {
		t.Fatalf("failed reload lost durable desired state: %v", err)
	}
	if err := handle.ApplyEnrollmentGrants(t.Context(), firstWire); !errors.Is(err, brokeradmission.ErrRollback) {
		t.Fatalf("failed reload permitted rollback: %v", err)
	}
	// A crash at this point must reconstruct the pending grants from the
	// signed checkpoint, even while live control authority is unavailable.
	authorityLost = true
	pendingRecovery, err := prepareEnrollmentBroker(t.Context(), baseline, config)
	if err != nil || pendingRecovery.desired.Revision != desired.Revision {
		t.Fatalf("pending reload recovery failed: %v", err)
	}
	authorityLost = false
	if err := handle.ApplyEnrollmentGrants(t.Context(), wire); err != nil {
		t.Fatal(err)
	}
	for i, c := range connected {
		deadline := time.Now().Add(2 * time.Second)
		for !c.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !c.IsClosed() {
			t.Fatalf("old %s connection survived revocation", brokeradmission.Roles[i])
		}
	}
	for _, role := range brokeradmission.Roles {
		if c, err := connect(instance, oldKeys[role]); err == nil {
			c.Close()
			t.Fatalf("retired %s reconnected", role)
		}
		c, err := connect(instance, newKeys[role])
		if err != nil {
			t.Fatalf("new %s: %v", role, err)
		}
		c.Close()
	}
	if err := handle.ApplyEnrollmentGrants(t.Context(), firstWire); !errors.Is(err, brokeradmission.ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)/2] ^= 1
	if err := handle.ApplyEnrollmentGrants(t.Context(), tampered); err == nil {
		t.Fatal("tampered grant accepted")
	}
	authorityLost = true
	if err := handle.ApplyEnrollmentGrants(t.Context(), wire); err == nil {
		t.Fatal("lost authority acknowledged")
	}
	unauthorized := desired
	unauthorized.Revision++
	unauthorized.AuthorityEpoch++
	unauthorized.LeaseID = "unaccepted-lease"
	unauthorizedWire, err := brokeradmission.Sign(unauthorized, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.ApplyEnrollmentGrants(t.Context(), unauthorizedWire); err == nil {
		t.Fatal("signature invented live control authority")
	}
	_, retained, err := brokeradmission.ReadCheckpoint(config.CheckpointPath, verifier)
	if err != nil || retained.Revision != desired.Revision {
		t.Fatalf("unaccepted authority replaced durable grants: %v", err)
	}
	instance.Shutdown()
	instance.WaitForShutdown()
	recovered, err := prepareEnrollmentBroker(t.Context(), baseline, config)
	if err != nil {
		t.Fatalf("control-loss recovery: %v", err)
	}
	restarted, err := server.NewServer(recovered.options)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Start()
	defer restarted.Shutdown()
	if !restarted.ReadyForConnections(5 * time.Second) {
		t.Fatal("restart not ready")
	}
	for _, role := range brokeradmission.Roles {
		if c, err := connect(restarted, oldKeys[role]); err == nil {
			c.Close()
			t.Fatalf("restart resurrected %s", role)
		}
	}
	for _, key := range []nkeys.KeyPair{controller, reader, newKeys["node"]} {
		c, err := connect(restarted, key)
		if err != nil {
			t.Fatalf("retained service unavailable: %v", err)
		}
		c.Close()
	}
}
