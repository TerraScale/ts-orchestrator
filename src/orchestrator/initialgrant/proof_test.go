package initialgrant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/nats-io/nkeys"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"testing"
	"time"
)

func configFixture(t *testing.T) Config {
	t.Helper()
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
	tls := TLSFiles{CAFile: "/keys/ca.pem", CASHA256: digest, CertificateFile: "/keys/cert.pem", CertificateSHA256: digest, KeyFile: "/keys/key.pem"}
	connection := func() Connection {
		return Connection{NKeySeedFile: "/keys/user.seed", PublicNKey: publicKey(), TLS: tls}
	}
	regional, global, rp, gp := connection(), connection(), connection(), connection()
	config := Config{Version: 1, Mode: Mode, Role: "seed", NodeID: "gru-1", Cell: "gru", Instance: "gru-1", SeedInstance: "gru-1", ProfileSHA256: digest,
		Broker:   Broker{Configuration: `{}`, ServerName: "gru-1", StoreDir: "/data/broker", Endpoint: "tls://localhost:4222", StorageBudgetBytes: 4 << 30, TLS: tls},
		Regional: Store{Account: "GRU_CONTROL", Provisioner: &rp, Runtime: regional}, Global: &Store{Account: "GLOBAL_CONTROL", Provisioner: &gp, Runtime: global},
		Membership: Membership{SigningKeyFile: "/keys/member.key", PublicKey: membership, PinsFile: "/keys/pins.json", PinsSHA256: digest},
		Peers:      []Peer{{Instance: "gru-1", RegionalPublicNKey: regional.PublicNKey, GlobalPublicNKey: global.PublicNKey, MembershipPublicKey: membership}}}
	if err = config.Validate(); err != nil {
		t.Fatal(err)
	}
	return config
}

func proofFixture(t *testing.T) *Proof {
	t.Helper()
	cfg := configFixture(t)
	raw, _ := json.Marshal(cfg)
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", Version: "1.0.0", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 67108864, IOWeight: 100, Arguments: Arguments, Configuration: string(raw)}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "owner-grant", NodeID: cfg.NodeID, Manifest: manifest, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyProof(cfg.NodeID, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), wire)
	if err != nil || p == nil {
		t.Fatalf("proof: %v", err)
	}
	return p
}
func TestConfigAndOriginalSignature(t *testing.T) {
	p := proofFixture(t)
	raw := []byte(p.Component().Configuration)
	for name, bad := range map[string][]byte{"duplicate": append([]byte(`{"version":1,`), raw[1:]...), "unknown": append([]byte(`{"unknown":1,`), raw[1:]...), "case": bytes.Replace(raw, []byte(`"version"`), []byte(`"Version"`), 1), "trailing": append(append([]byte(nil), raw...), '\n')} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(bad); err == nil {
				t.Fatal("accepted malformed config")
			}
		})
	}
	for _, args := range []string{"", "run", "check"} {
		if _, initial, err := ComponentConfig(hostmanifest.ComponentSpec{Name: "orchestrator", Arguments: args}); err != nil || initial {
			t.Fatalf("ordinary %q: %v", args, err)
		}
	}
	for _, args := range []string{Mode, Mode + " --config /chosen", Mode + " --config @config extra"} {
		if _, _, err := ComponentConfig(hostmanifest.ComponentSpec{Name: "orchestrator", Arguments: args}); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	if _, err := VerifyProof("gru-other", p.public, p.signed); err == nil {
		t.Fatal("foreign host accepted")
	}
	tamper := append([]byte(nil), p.signed...)
	tamper = bytes.Replace(tamper, []byte("owner-grant"), []byte("other-grant"), 1)
	if _, err := VerifyProof(p.node, p.public, tamper); err == nil {
		t.Fatal("changed owner grant accepted")
	}
	cfg := p.Config()
	cfg.Peers[0].Instance = "mutated"
	if p.Config().Peers[0].Instance == "mutated" {
		t.Fatal("proof config not immutable")
	}
	cfg = p.Config()
	cfg.Role = "participant"
	if cfg.Validate() == nil {
		t.Fatal("participant with seed privileges accepted")
	}
}
func privatePublicationNamespace(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("TS_INITIAL_R1_ISOLATED_TEST") != "1" {
		t.Skip("requires explicit private root mount namespace")
	}
	mountPublicationTestState(t)
}
func TestRootPublicationBinding(t *testing.T) {
	privatePublicationNamespace(t)
	p := proofFixture(t)
	private := filepath.Join(t.TempDir(), "epochs")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	epochs, err := nodeauthority.NewEpochStore(private, p.node)
	if err != nil {
		t.Fatal(err)
	}
	defer epochs.Close()
	if err = Publish(t.Context(), epochs, p); err == nil {
		t.Fatal("unpinned proof published")
	}
	if _, err = os.Stat(nodeauthority.InitialR1AdmissionDirectory); !os.IsNotExist(err) {
		t.Fatal("unpinned publication had effects")
	}
	if err = epochs.AdmitBootstrap(p.identity.GrantSHA256, p.identity.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = Publish(t.Context(), epochs, p); err != nil {
			t.Fatal(err)
		}
	}
	a, err := AdmitComponent(t.Context(), p.Component())
	if err != nil || a == nil {
		t.Fatalf("host admission before handoff: %v", err)
	}
	if _, err = AdmitConfiguration(t.Context(), []byte(p.Component().Configuration)); err == nil {
		t.Fatal("runtime accepted missing credentials")
	}
	changed := p.Component()
	changed.User = "forged"
	if _, err = AdmitComponent(t.Context(), changed); err == nil {
		t.Fatal("changed component accepted")
	}
	path := filepath.Join(nodeauthority.InitialR1AdmissionDirectory, "proof.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPublishedProof(); err == nil {
		t.Fatal("writable proof trusted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPublishedProof(); err == nil {
		t.Fatal("hardlinked proof trusted")
	}
	if err = os.Remove(path + ".link"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(original, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPublishedProof(); err == nil {
		t.Fatal("noncanonical proof trusted")
	}
	if err = os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPublishedProof(); err == nil {
		t.Fatal("symlink proof trusted")
	}
	var nilAdmission *Admission
	if nilAdmission.Check(context.Background()) == nil {
		t.Fatal("nil admission accepted")
	}
}

func TestMaterialDescriptorTraversal(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(real, "material")
	if err := os.WriteFile(path, []byte("captured"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadConfiguration(path)
	if err != nil || string(raw) != "captured" {
		t.Fatalf("safe config: %v", err)
	}
	alias := filepath.Join(root, "alias")
	if err = os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadConfiguration(filepath.Join(alias, "material")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if err = os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadConfiguration(path); err == nil {
		t.Fatal("hardlinked material accepted")
	}
	if err = os.Remove(path + ".link"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readMaterial(path, 100, true); err == nil {
		t.Fatal("readable private credential accepted")
	}
}
