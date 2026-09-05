package hostagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func bootstrapTestGrant(t *testing.T, manifest hostmanifest.HostManifest) (*security.CommandSignatureSigner, []byte, []byte, BootstrapGrant) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	grant := BootstrapGrant{Version: 1, GrantID: "owner-grant-1", NodeID: "gru-1", Manifest: manifest, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	wire, err := SignBootstrapGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), wire, grant
}
func bootstrapTestTransport(t *testing.T, harness *testHarness, authority *BootstrapAuthority) (*NatsTransport, *fakeNatsConnection) {
	t.Helper()
	connection := newFakeNatsConnection()
	transport, err := NewNatsTransport(NatsTransportConfig{CommandAuthority: authority, RequireManifestAdmission: true, NodeId: NodeId{Value: "gru-1"}, Connection: connection, Lifecycle: harness.lifecycle, Facts: harness.factsSource(t), Ticker: &manualTicker{channel: make(chan time.Time)}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err = transport.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport, connection
}
func TestBootstrapReceiverInstallsActivatesRetriesAndRetires(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	spec.Arguments, spec.Configuration = "--config @config", `{"region":"gru"}`
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	signer, public, wire, grant := bootstrapTestGrant(t, manifest)
	authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(harness.dataVolume, hostmanifest.TsNodeComponentName, "manifest.json")
	if err = os.MkdirAll(filepath.Dir(manifestPath), 0700); err != nil {
		t.Fatal(err)
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifestPath, canonical, 0600); err != nil {
		t.Fatal(err)
	}
	transport, connection := bootstrapTestTransport(t, harness, authority)
	if err = transport.reconcileAdmittedManifest(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if !InstalledVersion(harness.root, spec.Name, spec.Version) {
		t.Fatal("admitted initial binary was not installed")
	}
	commands, _ := BootstrapCommands(grant)
	request := func(step BootstrapCommand) ([]byte, error) {
		issued := time.Now().UTC()
		signed, err := SignBootstrapCommand(signer, wire, step.Subject, step.Command, issued, issued.Add(30*time.Second))
		if err != nil {
			return nil, err
		}
		return connection.request(step.Subject, signed)
	}
	for _, step := range commands {
		response, err := request(step)
		if err != nil || !bytes.Contains(response, []byte(`"commandId"`)) {
			t.Fatalf("step=%s response=%s err=%v", step.Command, response, err)
		}
		before := len(harness.systemd.ops())
		repeated, err := request(step)
		if err != nil || !bytes.Equal(response, repeated) || len(harness.systemd.ops()) != before {
			t.Fatalf("retry changed effects: %s %v", repeated, err)
		}
	}
	current, err := CurrentVersion(harness.root, spec.Name)
	if err != nil || current != spec.Version || !harness.systemd.isActive(UnitName(spec.Name)) {
		t.Fatalf("initial activation current=%s err=%v", current, err)
	}
	// The real regional cryptographic boundary is separately tested against live
	// authenticated NATS. This test injects its accepted result to exercise the
	// durable receiver handoff and signed-bootstrap replay boundary.
	transport.commandMutex.Lock()
	regional, _ := testCommandAuthorizer{}.Authorize(context.Background(), "", nil)
	err = transport.epochs.Admit(regional)
	transport.commandMutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before := len(harness.systemd.ops())
	response, err := request(commands[len(commands)-1])
	if err != nil || !strings.Contains(string(response), "permanently retired") || len(harness.systemd.ops()) != before {
		t.Fatalf("retired replay=%s err=%v", response, err)
	}
	if err = transport.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, connection := bootstrapTestTransport(t, harness, authority)
	_ = restarted
	response, err = request(commands[len(commands)-1])
	if err != nil || !!bytes.Contains(response, []byte(`"commandId"`)) {
		t.Fatalf("restart replay=%s err=%v", response, err)
	}
}

func TestBootstrapManifestAdmissionPrecedesInstallAndRejectsEditedLaunch(t *testing.T) {
	for _, field := range []string{"arguments", "configuration", "user", "data-volume"} {
		t.Run(field, func(t *testing.T) {
			harness := newTestHarness(t)
			spec := harness.publish(t, "terrabase", "1.0.0")
			_, public, wire, _ := bootstrapTestGrant(t, hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
			authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
			if err != nil {
				t.Fatal(err)
			}
			changed := spec
			switch field {
			case "arguments":
				changed.Arguments = "--foreign"
			case "configuration":
				changed.Configuration = "foreign"
				changed.Arguments = "@config"
			case "user":
				changed.User = "foreign"
			case "data-volume":
				changed.DataVolume = filepath.Join(harness.dataVolume, "foreign")
			}
			path := filepath.Join(harness.dataVolume, hostmanifest.TsNodeComponentName, "manifest.json")
			if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			canonical, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{changed}})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, canonical, 0600); err != nil {
				t.Fatal(err)
			}
			transport, err := NewNatsTransport(NatsTransportConfig{CommandAuthority: authority, RequireManifestAdmission: true, NodeId: NodeId{Value: "gru-1"}, Connection: newFakeNatsConnection(), Lifecycle: harness.lifecycle, Facts: harness.factsSource(t), Ticker: newManualTicker(), Now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			if err = transport.Start(context.Background()); err == nil {
				t.Fatal("edited seed was admitted")
			}
			_ = transport.Close()
			if InstalledVersion(harness.root, spec.Name, spec.Version) || len(harness.systemd.ops()) != 0 {
				t.Fatal("unsigned launch settings caused installation or service effects")
			}
		})
	}
}

func TestBootstrapStartupHydratesVerifiedManifestAndPinsSigner(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	_, public, wire, grant := bootstrapTestGrant(t, manifest)
	authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(harness.dataVolume, hostmanifest.TsNodeComponentName, "manifest.json")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	canonical, _ := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err = os.WriteFile(path, canonical, 0600); err != nil {
		t.Fatal(err)
	}
	// Model a different first read before the authenticated startup read.
	foreign := spec
	foreign.Name = "foreign"
	if err = harness.lifecycle.HydrateDesired([]hostmanifest.ComponentSpec{foreign}); err != nil {
		t.Fatal(err)
	}
	journal, err := newCommandJournal(filepath.Join(harness.dataVolume, hostmanifest.TsNodeComponentName, "command-journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.initialize(); err != nil {
		t.Fatal(err)
	}
	command, _ := NewDrainCommand("previous-done-drain", true)
	if _, err = journal.storeDone(commandKindDrain, command.CommandId, mustJSON(t, command), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	transport, _ := bootstrapTestTransport(t, harness, authority)
	desired := harness.lifecycle.Desired()
	if len(desired) != 1 || desired[0].Name != spec.Name {
		t.Fatalf("hydrated unverified desired: %+v", desired)
	}
	for _, operation := range harness.systemd.ops() {
		if strings.Contains(operation, "foreign") {
			t.Fatalf("restored drain touched unsigned component: %s", operation)
		}
	}
	if err = transport.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, otherPublic, _, _ := bootstrapTestGrant(t, manifest)
	reSigned, err := SignBootstrapGrant(replacement, grant)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", otherPublic, reSigned)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNatsTransport(NatsTransportConfig{CommandAuthority: other, NodeId: NodeId{Value: "gru-1"}, Connection: newFakeNatsConnection(), Lifecycle: harness.lifecycle, Facts: harness.factsSource(t), Ticker: newManualTicker(), Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	before := len(harness.systemd.ops())
	if err = restarted.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "conflicts with durable admission") {
		t.Fatalf("changed signer admitted identical grant: %v", err)
	}
	_ = restarted.Close()
	if len(harness.systemd.ops()) != before {
		t.Fatal("changed signer caused effects")
	}
}
