package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

var peerCredentialManifest = bootstrap.Manifest{Slot: "controller-a", SeedSlot: "seed-a"}

func credentialPathFixture(t *testing.T) (LiveCredentials, map[string]string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("cert.pem"), KeyFile: path("key.pem")}
	config := natscell.Config{Cell: "gru", Instance: "broker-a", Replicas: 1,
		CredentialsFile: path("controller.creds"), TLS: tlsFiles,
		Embedded: &natscell.Embedded{TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"),
			CellJWTFile: path("cell.jwt"), SystemCredentialsFile: path("system.creds"),
			TicketPublicKeyFile: path("ticket.pub")},
	}
	expected := map[string]string{}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "controller.creds", "operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ticket.pub", "response.key", "ticket.key", "host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem"} {
		content := []byte("signed fixture " + name)
		expected[name] = digest(content)
		if err := os.WriteFile(path(name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return LiveCredentials{Config: config, ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()),
		ResponseKeyFile: path("response.key"), BrokerTicketKeyFile: path("ticket.key"),
		HostNATSIssuerSeedFile: path("host-nats-issuer.seed"), HostTLSIssuerKeyFile: path("host-tls-issuer-key.pem"),
		HostTLSIssuerCertFile:  path("host-tls-issuer-cert.pem"),
		ValidateControllerKeys: func() error { return nil }, directory: directory, allowUnsafeAncestors: true}, expected
}

func TestCredentialCheckerBindsPathsAndExactInventory(t *testing.T) {
	check, expected := credentialPathFixture(t)
	if err := check.verifyPaths(expected, peerCredentialManifest); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); err != nil {
		t.Fatal(err)
	}
	wrongPath := check
	wrongConfig := wrongPath.Config
	wrongEmbedded := *wrongConfig.Embedded
	wrongConfig.Embedded = &wrongEmbedded
	wrongEmbedded.SystemJWTFile = filepath.Join(t.TempDir(), "system.jwt")
	wrongPath.Config = wrongConfig
	if err := wrongPath.verifyPaths(expected, peerCredentialManifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("unbound path = %v, want refusal", err)
	}
	delete(expected, "system.jwt")
	if err := check.verifyPaths(expected, peerCredentialManifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("missing signed credential = %v, want refusal", err)
	}
	expected["system.jwt"] = digest([]byte("signed fixture system.jwt"))
	expected["unreferenced.key"] = digest([]byte("unreferenced"))
	if err := check.verifyPaths(expected, peerCredentialManifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("unassigned signed material = %v, want refusal", err)
	}
}

func TestCredentialCheckerRejectsExtraAndChangedInstalledFiles(t *testing.T) {
	check, expected := credentialPathFixture(t)
	path := filepath.Join(check.directory, "controller.creds")
	if err := os.WriteFile(path, []byte("changed credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("changed digest = %v, want refusal", err)
	}
	if err := os.WriteFile(path, []byte("signed fixture controller.creds"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(check.directory, "extra.key"), []byte("unpinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("extra credential file = %v, want refusal", err)
	}
}

func TestSeedSignerCredentialPathsFollowSelectedSignedManifest(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	seed, err := verifiedFounderManifest(fixture.current, fixture.accepted.Slot, fixture.baked.Roots, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := seed.Manifest()
	check, expected := credentialPathFixture(t)
	for name, key := range map[string][]byte{
		"founder-peer.key": fixture.peerKey, "founder-ledger.key": fixture.ledgerKey,
	} {
		if err := os.WriteFile(filepath.Join(check.directory, name), key, 0o600); err != nil {
			t.Fatal(err)
		}
		expected[name] = fixture.accepted.MaterialSHA256[name]
	}
	if err := check.verifyPaths(expected, manifest); err != nil {
		t.Fatalf("selected seed signer paths: %v", err)
	}
	if err := check.verifyInventory(expected); err != nil {
		t.Fatalf("selected seed signer inventory: %v", err)
	}
	store := fixture.store
	store.directory = check.directory
	keys, err := store.Load(fixture.current, fixture.accepted, fixture.baked.Roots, fixture.now)
	if err != nil {
		t.Fatalf("load selected installed signers: %v", err)
	}
	keys.Close()

	assertRejected := func(label string, changed bootstrap.Manifest) {
		t.Helper()
		if err := check.verifyPaths(expected, changed); !errors.Is(err, ErrLiveCredentials) {
			t.Fatalf("%s: got %v, want signer path refusal", label, err)
		}
	}
	peer := manifest
	peer.Slot = "controller-a"
	assertRejected("seed keys presented to peer", peer)
	wrongSlot := manifest
	wrongSlot.Secrets = slices.Clone(manifest.Secrets)
	wrongSlot.Secrets[0].Slot = "controller-a"
	assertRejected("wrong signer slot", wrongSlot)
	wrongDigest := manifest
	wrongDigest.Secrets = slices.Clone(manifest.Secrets)
	wrongDigest.Secrets[0].SHA256 = digest([]byte("different signer"))
	assertRejected("wrong signer digest", wrongDigest)
	wrongPurpose := manifest
	wrongPurpose.Secrets = slices.Clone(manifest.Secrets)
	wrongPurpose.Secrets[0].Purpose = bootstrap.SecretController
	assertRejected("missing signer purpose", wrongPurpose)

	expected["unassigned.key"] = digest([]byte("signed but unassigned"))
	if err := check.verifyPaths(expected, manifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("unassigned material: got %v, want refusal", err)
	}
	delete(expected, "unassigned.key")
	if err := os.WriteFile(filepath.Join(check.directory, "unassigned.key"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("extra installed material: got %v, want refusal", err)
	}
}

func TestContinuationSignerRolesRequireExactAcceptedManifestBytes(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	wire := fixture.current.ManifestWires[fixture.accepted.Slot]
	state := bootstrap.SlotState{ManifestRecord: &bootstrap.StoredRecord{
		SHA256: fixture.accepted.ManifestSHA256, Bytes: wire,
	}}
	manifest, err := pinnedCredentialManifest(fixture.accepted, state)
	if err != nil || manifest.Slot != fixture.accepted.Slot {
		t.Fatalf("accepted signer manifest: manifest=%+v err=%v", manifest, err)
	}
	state.ManifestRecord.Bytes = append(slices.Clone(wire), 'x')
	if _, err := pinnedCredentialManifest(fixture.accepted, state); !errors.Is(err, ErrFounderInstallContinuation) {
		t.Fatalf("changed envelope bytes: got %v, want refusal", err)
	}
	state.ManifestRecord.Bytes = wire
	wrongRole := fixture.accepted
	wrongRole.SeedSlot = "controller-a"
	if _, err := pinnedCredentialManifest(wrongRole, state); !errors.Is(err, ErrFounderInstallContinuation) {
		t.Fatalf("changed accepted seed slot: got %v, want refusal", err)
	}
}
