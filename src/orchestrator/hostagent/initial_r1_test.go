package hostagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// Run these tests in a root mount namespace with private tmpfs /var/lib.
// Ordinary checks skip them rather than modify a real host's admission state.
func initialHostFixture(t *testing.T, delivery ...controltransition.Delivery) (*testHarness, hostmanifest.HostManifest, []byte, []byte, string) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("TS_INITIAL_R1_ISOLATED_TEST") != "1" {
		t.Skip("requires isolated root /var/lib mount")
	}
	if _, err := os.Lstat(nodeauthority.InitialR1AdmissionDirectory); !os.IsNotExist(err) {
		t.Fatal("initial admission directory must be absent")
	}
	t.Cleanup(func() { _ = os.RemoveAll(nodeauthority.InitialR1AdmissionDirectory) })
	h := newTestHarness(t)
	publicKey := func() string {
		k, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		defer k.Wipe()
		p, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	membership := base64.StdEncoding.EncodeToString(raw)
	digest := strings.Repeat("a", 64)
	tls := initialgrant.TLSFiles{CAFile: "/keys/ca.pem", CASHA256: digest, CertificateFile: "/keys/cert.pem", CertificateSHA256: digest, KeyFile: "/keys/key.pem"}
	connection := func() initialgrant.Connection {
		return initialgrant.Connection{NKeySeedFile: "/keys/user.seed", PublicNKey: publicKey(), TLS: tls}
	}
	regional, global, rp, gp := connection(), connection(), connection(), connection()
	config := initialgrant.Config{Version: 1, Mode: initialgrant.Mode, Role: "seed", NodeID: "gru-1", Cell: "gru", Instance: "gru-1", SeedInstance: "gru-1", ProfileSHA256: digest,
		Broker:   initialgrant.Broker{Configuration: `{}`, ServerName: "gru-1", StoreDir: "/data/broker", Endpoint: "tls://localhost:4222", StorageBudgetBytes: 4 << 30, TLS: tls},
		Regional: initialgrant.Store{Account: "GRU_CONTROL", Provisioner: &rp, Runtime: regional}, Global: &initialgrant.Store{Account: "GLOBAL_CONTROL", Provisioner: &gp, Runtime: global},
		Membership: initialgrant.Membership{SigningKeyFile: "/keys/member.key", PublicKey: membership, PinsFile: "/keys/pins.json", PinsSHA256: digest},
		Peers:      []initialgrant.Peer{{Instance: "gru-1", RegionalPublicNKey: regional.PublicNKey, GlobalPublicNKey: global.PublicNKey, MembershipPublicKey: membership}}}
	if len(delivery) > 0 {
		config.StorageTransition = delivery[0]
	}
	config.AuthorityReader = nodeauthority.ReaderConfig{Endpoint: config.Broker.Endpoint, ServerName: config.Broker.ServerName, Account: config.Regional.Account, NKeySeedFile: "/reader/user.seed", PublicNKey: publicKey(), CAFile: "/reader/ca.pem", CASHA256: digest, CertificateFile: "/reader/client.pem", CertificateSHA256: digest, KeyFile: "/reader/client.key"}
	config.Peers[0].AuthorityReaderPublicNKey = config.AuthorityReader.PublicNKey
	if err = config.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	spec := h.publish(t, "orchestrator", "1.0.0")
	spec.User = "terrascale-orchestrator"
	spec.Arguments = initialgrant.Arguments
	spec.Configuration = string(encoded)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	_, public, wire, _ := bootstrapTestGrant(t, manifest)
	path := filepath.Join(h.dataVolume, hostmanifest.TsNodeComponentName, "manifest.json")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return h, manifest, public, wire, path
}

func TestInitialR1HostPublication(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport", true: "offline"}[local], func(t *testing.T) {
			h, manifest, public, wire, path := initialHostFixture(t)
			if local {
				session, err := OpenLocalBootstrap(context.Background(), h.lifecycle, "gru-1", public, wire, path, func(ctx context.Context, _ string, _ string) error {
					_, err := initialgrant.AdmitComponent(ctx, manifest.Components[0])
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
			} else {
				authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
				if err != nil {
					t.Fatal(err)
				}
				bootstrapTestTransport(t, h, authority)
			}
			admission, err := initialgrant.AdmitComponent(context.Background(), manifest.Components[0])
			if err != nil || admission == nil {
				t.Fatalf("trusted proof unpublished: %v", err)
			}
			info, err := os.Stat(nodeauthority.InitialR1AdmissionDirectory)
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("public traversal: %v %v", info, err)
			}
			if h.systemd.isActive(UnitName("orchestrator")) {
				t.Fatal("initial startup activated before explicit deploy")
			}
			changed := manifest.Components[0]
			changed.User = "forged-user"
			if _, err = initialgrant.AdmitComponent(context.Background(), changed); err == nil {
				t.Fatal("edited signed component accepted")
			}
		})
	}
}

func TestInitialR1HostRetirementPrecedesEffectsAndRetry(t *testing.T) {
	h, initial, public, wire, path := initialHostFixture(t)
	authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := bootstrapTestTransport(t, h, authority)
	if err = transport.reconcileAdmittedManifest(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	oldDigest, _ := hostmanifest.HostManifestSha256(initial)
	spec := h.publish(t, "orchestrator", "2.0.0")
	replacement := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	command, err := hostmanifest.NewApplyManifestCommand("retire-initial", oldDigest, replacement)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(command)
	transport.authorizer = testCommandAuthorizer{}
	ctx, cancelAuthority, err := transport.authorizeLocked(&nats.Msg{Data: body, Header: nats.Header{internalCommandProof: []string{base64.StdEncoding.EncodeToString(body)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer cancelAuthority()
	auth, ok := ctx.Value(commandAuthorizationContextKey{}).(nodeauthority.CommandAuthorization)
	if !ok || string(auth.Command) != string(body) {
		t.Fatal("verified command proof missing from execution context")
	}

	// The supplied parsed object cannot substitute for the authenticated bytes.
	forged := command
	forged.CommandId = "forged-retirement"
	before := len(h.systemd.ops())
	if _, err = transport.applyManifest(ctx, forged); err == nil {
		t.Fatal("forged command retired grant")
	}
	if len(h.systemd.ops()) != before {
		t.Fatal("failed retirement performed effects")
	}
	if _, err = initialgrant.AdmitComponent(context.Background(), initial.Components[0]); err != nil {
		t.Fatal(err)
	}

	admission, err := initialgrant.AdmitComponent(context.Background(), initial.Components[0])
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- admission.WithinMutation(context.Background(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	bounded, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	_, blockedErr := transport.applyManifest(bounded, command)
	cancel()
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if blockedErr == nil {
		t.Fatal("replacement succeeded while initial mutation held admission")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	originalBefore, _ := hostmanifest.CanonicalHostManifestJSON(initial)
	if string(unchanged) != string(originalBefore) || len(h.systemd.ops()) != before {
		t.Fatal("blocked retirement changed manifest or units")
	}
	delete(h.lifecycle.enabledUnits, UnitName("orchestrator"))
	h.systemd.failOn["enable"] = UnitName("orchestrator")
	response, err := transport.applyManifest(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), "convergence pending") {
		t.Fatalf("injected replacement failure missing: %s", response)
	}
	if _, err = initialgrant.AdmitComponent(context.Background(), initial.Components[0]); err == nil {
		t.Fatal("replacement failure left initial authority live")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := hostmanifest.ParseHostManifest(persisted)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := hostmanifest.HostManifestSha256(parsed)
	wanted, _ := hostmanifest.HostManifestSha256(replacement)
	if actual != wanted {
		t.Fatal("replacement not committed")
	}
	delete(h.systemd.failOn, "enable")
	auth.Epoch++
	auth.LeaseID = "replacement-lease"
	auth.ExpiresAt = time.Now().Add(time.Minute)
	if err = transport.epochs.Admit(auth); err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(context.Background(), commandAuthorizationContextKey{}, auth)
	if _, err = transport.applyManifest(ctx, command); err != nil {
		t.Fatalf("same transition retry: %v", err)
	}
	resurrect, _ := hostmanifest.NewApplyManifestCommand("resurrect", wanted, initial)
	if _, err = transport.applyManifest(ctx, resurrect); err == nil {
		t.Fatal("retired manifest re-admitted")
	}
	// A stale manifest without a pending recovery intent must remain denied.
	original, _ := hostmanifest.CanonicalHostManifestJSON(initial)
	if err = writeDurableManifest(path, original); err != nil {
		t.Fatal(err)
	}
	if err = transport.initializeManifestAuthority(); err == nil {
		t.Fatal("retired predecessor restored")
	}
	// An installed immutable R1 release cannot bypass the manifest gate.
	called := false
	err = h.lifecycle.installer.withVerifiedTransition(context.Background(), "orchestrator", "1.0.0", initial.Components[0].Sha256, func(context.Context) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("retired installed release entered transition")
	}
}

// Signature verification is tested in nodeauthority; this accepted successor
// result exercises the actual receiver proof and durable command replay path.
type initialHostSuccessor struct{}

func (initialHostSuccessor) Authorize(ctx context.Context, subject string, body []byte) (nodeauthority.CommandAuthorization, error) {
	a, err := (testCommandAuthorizer{}).Authorize(ctx, subject, body)
	a.Epoch = 2
	a.LeaseID = "successor-lease"
	return a, err
}
func TestInitialR1HostCrashBeforeManifestRename(t *testing.T) {
	for _, previous := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired-before-admission", true: "retired-previous-admission"}[previous], func(t *testing.T) {
			h, initial, public, wire, path := initialHostFixture(t)
			authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
			if err != nil {
				t.Fatal(err)
			}
			transport, _ := bootstrapTestTransport(t, h, authority)
			if err = transport.reconcileAdmittedManifest(context.Background(), initial); err != nil {
				t.Fatal(err)
			}
			if err = h.lifecycle.BeginDrain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = h.lifecycle.Deploy(context.Background(), "orchestrator", "1.0.0"); err != nil {
				t.Fatal(err)
			}
			if err = h.systemd.StopUnit(context.Background(), UnitName("orchestrator")); err != nil {
				t.Fatal(err)
			}
			oldDigest, _ := hostmanifest.HostManifestSha256(initial)
			replacement := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{h.publish(t, "orchestrator", "2.0.0")}}
			command, _ := hostmanifest.NewApplyManifestCommand("crash-replacement", oldDigest, replacement)
			body, _ := json.Marshal(command)
			auth, _ := testCommandAuthorizer{}.Authorize(context.Background(), "", body)
			if err = transport.epochs.Admit(auth); err != nil {
				t.Fatal(err)
			}
			if _, err = transport.journal.begin(commandKindManifest, command.CommandId, body, nil); err != nil {
				t.Fatal(err)
			}
			if err = initialgrant.RetireForReplacement(context.Background(), transport.epochs, auth, command, initial); err != nil {
				t.Fatal(err)
			}
			if previous {
				wanted, _ := hostmanifest.HostManifestSha256(replacement)
				if err = transport.epochs.AdmitRuntimeManifest(wanted, oldDigest); err != nil {
					t.Fatal(err)
				}
			}
			if err = transport.Close(); err != nil {
				t.Fatal(err)
			}
			before := len(h.systemd.ops())
			h.lifecycle, err = NewLifecycle(LifecycleConfig{InstallRoot: h.root, UnitDir: h.unitDir, DataVolumeRoot: h.dataVolume, Installer: h.lifecycle.installer, Systemd: h.systemd, Users: h.users})
			if err != nil {
				t.Fatal(err)
			}
			restarted, connection := bootstrapTestTransport(t, h, authority)
			if len(h.lifecycle.Desired()) != 0 || len(h.systemd.ops()) != before {
				t.Fatal("retired launch hydrated or started during receiver recovery")
			}
			restarted.authorizer = initialHostSuccessor{}
			subject, _ := NodeApplyManifestSubject(NodeId{Value: "gru-1"})
			response, err := connection.request(subject, body)
			if err != nil || !strings.Contains(string(response), `"accepted":true`) {
				t.Fatalf("successor retry failed: %s %v", response, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			expected, _ := hostmanifest.CanonicalHostManifestJSON(replacement)
			if string(data) != string(expected) {
				t.Fatal("successor did not finish replacement rename")
			}
			if _, err = initialgrant.AdmitComponent(context.Background(), initial.Components[0]); err == nil {
				t.Fatal("recovery revived initial authority")
			}
		})
	}
}
