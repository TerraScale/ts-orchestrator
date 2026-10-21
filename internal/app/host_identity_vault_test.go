package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// fakeIdentityRecord is a Vault record: its CURRENT value and versions.
type fakeIdentityRecord struct {
	value     []byte
	version   int64
	published int
}

func (fake *fakeIdentityRecord) record() *hostIdentityRecord {
	return &hostIdentityRecord{
		read: func(context.Context) (string, int64, []byte, error) {
			return "ocid1.vaultsecret.oc1.sa-saopaulo-1.record", fake.version, bytes.Clone(fake.value), nil
		},
		publish: func(_ context.Context, _ string, expected int64, value []byte) (int64, error) {
			if expected != fake.version {
				return 0, os.ErrExist
			}
			fake.value, fake.version = bytes.Clone(value), fake.version+1
			fake.published++
			return fake.version, nil
		}}
}

// A host enrolled with its identity on disk moves it to memory: host-setup
// restores it from its Vault record, renews the credentials into memory and
// removes the disk copies; after a reboot it renews from Vault alone. A disk
// identity the record lacks is published before it is used (TS-745).
func TestHostEnrollmentIdentityMovesToVaultAndMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.db1", "gru-1-db-1", "10.251.0.21")
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, "10.251.0.21"); err != nil {
		t.Fatalf("legacy host setup: %v", err)
	}
	legacy, err := os.ReadFile(filepath.Join(root, pendingHostEnrollmentFile))
	if err != nil {
		t.Fatal(err)
	}
	// A granted host's roles come from its grant, not the static default;
	// the move keeps them.
	installed, err := LoadConfig(filepath.Join(root, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	installed.Host.Roles = []string{"terrabase", "ts-auth"}
	wire, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "host.json"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	vault := &fakeIdentityRecord{value: []byte("an older identity"), version: 1}
	secrets := t.TempDir()
	memory := func() error {
		return runHostSetupWithMetadata(ctx, lab.bundle, metadata, root, &bytes.Buffer{}, hostSetupRuntime{
			ownerUID: uint32(os.Geteuid()), secrets: secrets, identity: vault.record(),
			post: func(_ context.Context, _ hostenroll.PublicBundle, wire []byte) ([]byte, error) {
				return lab.post(wire, "10.251.0.21")
			}})
	}
	parsed := func() (pendingHostEnrollment, hostenroll.Request, hostboot.Descriptor) {
		t.Helper()
		pending, err := readOrCreateHostEnrollment(ctx, secrets, metadata, nil)
		if err != nil {
			t.Fatal(err)
		}
		var original hostenroll.Request
		if err := json.Unmarshal(pending.Request, &original); err != nil {
			t.Fatal(err)
		}
		request, descriptor, err := hostenroll.ParseRequest(pending.Request, original.IssuedAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return pending, request, descriptor
	}
	// The move rebuilds the on-disk credentials in memory, keeping the roles.
	if err := vault.record().restore(ctx, root, secrets); err != nil {
		t.Fatal(err)
	}
	pending, request, descriptor := parsed()
	if err := recoverHostCredentials(ctx, root, secrets, lab.bundle, descriptor, pending, request,
		hostSetupRuntime{ownerUID: uint32(os.Geteuid())}); err != nil {
		t.Fatal(err)
	}
	moved, err := LoadConfig(filepath.Join(root, "host.json"))
	if err != nil || filepath.Dir(filepath.Dir(moved.NATS.CredentialsFile)) != secrets ||
		strings.Join(moved.Host.Roles, ",") != "terrabase,ts-auth" {
		t.Fatalf("moved credentials %s with roles %v: %v", moved.NATS.CredentialsFile, moved.Host.Roles, err)
	}
	if err := memory(); err != nil {
		t.Fatalf("host setup into memory: %v", err)
	}
	if vault.published != 1 || !bytes.Equal(vault.value, legacy) {
		t.Fatalf("published %d versions; Vault holds the disk identity: %v", vault.published, bytes.Equal(vault.value, legacy))
	}
	config, err := LoadConfig(filepath.Join(root, "host.json"))
	if err != nil || filepath.Dir(filepath.Dir(config.NATS.CredentialsFile)) != secrets {
		t.Fatalf("host.json names %s, want credentials in memory: %v", config.NATS.CredentialsFile, err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "host-credentials-") || strings.HasPrefix(entry.Name(), ".host-enrollment") {
			t.Fatalf("disk copy %s survived", entry.Name())
		}
	}

	if _, err := os.Stat(filepath.Join(root, hostResponseFile)); err != nil {
		t.Fatalf("the credentials' public half was not kept: %v", err)
	}

	// The reboot empties memory; Vault restores the identity and the kept
	// response the credentials, without the controller, which renews only
	// within a credential's last day.
	if err := os.RemoveAll(secrets); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := vault.record().restore(ctx, root, secrets); err != nil {
		t.Fatal(err)
	}
	pending, request, descriptor = parsed()
	if err := recoverHostCredentials(ctx, root, secrets, lab.bundle, descriptor, pending, request,
		hostSetupRuntime{ownerUID: uint32(os.Geteuid())}); err != nil {
		t.Fatal(err)
	}
	if config, err = LoadConfig(filepath.Join(root, "host.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.NATS.CredentialsFile); err != nil || filepath.Dir(filepath.Dir(config.NATS.CredentialsFile)) != secrets {
		t.Fatalf("credentials were not rebuilt in memory: %s, %v", config.NATS.CredentialsFile, err)
	}
	// A rebuild cut short leaves part of the set: the next one completes it.
	if err := os.Remove(config.NATS.TLS.CertFile); err != nil {
		t.Fatal(err)
	}
	if err := recoverHostCredentials(ctx, root, secrets, lab.bundle, descriptor, pending, request,
		hostSetupRuntime{ownerUID: uint32(os.Geteuid())}); err != nil {
		t.Fatal(err)
	}
	if config, err = LoadConfig(filepath.Join(root, "host.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.NATS.TLS.CertFile); err != nil {
		t.Fatalf("a partial rebuild was not completed: %v", err)
	}
	if err := memory(); err != nil {
		t.Fatalf("host setup after a reboot: %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(secrets, pendingHostEnrollmentFile))
	if err != nil || !bytes.Equal(restored, legacy) || vault.published != 1 {
		t.Fatalf("restored identity equal = %v, published %d, %v", bytes.Equal(restored, legacy), vault.published, err)
	}
	if config, err = LoadConfig(filepath.Join(root, "host.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.NATS.CredentialsFile); err != nil {
		t.Fatalf("renewed credentials: %v", err)
	}
	// A missing certificate without a reusable response renews, not fails.
	if err := os.Remove(config.NATS.TLS.CertFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, hostResponseFile)); err != nil {
		t.Fatal(err)
	}
	if err := memory(); err != nil {
		t.Fatalf("host setup without its certificate: %v", err)
	}
	if config, err = LoadConfig(filepath.Join(root, "host.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.NATS.TLS.CertFile); err != nil {
		t.Fatalf("renewal did not replace the certificate: %v", err)
	}

	// A disk copy that reappears after the move (an older release) is not
	// the live identity: the record is restored, kept, and the copy dropped.
	if err := os.WriteFile(filepath.Join(root, pendingHostEnrollmentFile), []byte("a stale identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir()
	if err := vault.record().restore(ctx, root, fresh); err != nil {
		t.Fatal(err)
	}
	restored, err = os.ReadFile(filepath.Join(fresh, pendingHostEnrollmentFile))
	if err != nil || !bytes.Equal(restored, legacy) || vault.published != 1 {
		t.Fatalf("stale disk copy replaced the record: equal %v, published %d, %v", bytes.Equal(restored, legacy), vault.published, err)
	}
	if _, err := os.Stat(filepath.Join(root, pendingHostEnrollmentFile)); !os.IsNotExist(err) {
		t.Fatalf("stale disk copy survived: %v", err)
	}
}

// The first start of a release after a prepare that predates the mounts
// keeps the on-disk role layout and restarts once the release is known-good,
// so its own prepare mounts the runtime directories; otherwise memory is
// enforced.
func TestHostMemoryRuntimeWaitsForItsOwnPrepare(t *testing.T) {
	managed, root := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(managed, "roles"), 0o750); err != nil {
		t.Fatal(err)
	}
	if vaultsecret.RequireMemoryFilesystem(filepath.Join(managed, "roles")) == nil {
		t.Skip("the test directory is already in memory")
	}
	link := func(name, digest string) {
		t.Helper()
		path := filepath.Join(root, name)
		_ = os.Remove(path)
		if err := os.Symlink("releases/"+digest, path); err != nil {
			t.Fatal(err)
		}
	}
	old, next := strings.Repeat("a", 64), strings.Repeat("b", 64)
	cfg := Config{Host: HostConfig{ManagedRuntimeRoot: managed, SelfUpdateRoot: root}}
	link("current", next)
	link("known-good", old)
	memoryPrepareMarker = filepath.Join(root, "memory-prepare")
	t.Cleanup(func() { memoryPrepareMarker = selfupdate.MemoryPrepareMarker })
	if enforce, _, release := hostMemoryRuntime(cfg); enforce || release != next {
		t.Fatalf("unconfirmed release: enforce %v, restart on %q", enforce, release)
	}
	// A prepare that knows the mounts but could not make them fails closed.
	if err := os.WriteFile(memoryPrepareMarker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if enforce, _, _ := hostMemoryRuntime(cfg); !enforce {
		t.Fatal("a memory-aware prepare's failed mount must enforce memory")
	}
	if err := os.Remove(memoryPrepareMarker); err != nil {
		t.Fatal(err)
	}
	link("known-good", next)
	if enforce, _, release := hostMemoryRuntime(cfg); !enforce || release != "" {
		t.Fatalf("known-good release: enforce %v, restart on %q", enforce, release)
	}
	if err := os.Remove(filepath.Join(root, "known-good")); err != nil {
		t.Fatal(err)
	}
	if enforce, _, _ := hostMemoryRuntime(cfg); !enforce {
		t.Fatal("a release without a known-good one must enforce memory")
	}
}
