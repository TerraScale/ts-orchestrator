package hostbootstrap_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "terrascale.tech/orchestrator/src/orchestrator/hostagent"
	. "terrascale.tech/orchestrator/src/orchestrator/hostbootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type localSystemd struct {
	accountReady, credentialReady, requireCredentials bool
	active                                            bool
	starts                                            int
	failRestart                                       bool
}

func (s *localSystemd) DaemonReload(context.Context) error        { return nil }
func (s *localSystemd) EnableUnit(context.Context, string) error  { return nil }
func (s *localSystemd) DisableUnit(context.Context, string) error { return nil }
func (s *localSystemd) StartUnit(context.Context, string) error {
	if s.requireCredentials && !s.credentialReady {
		return errors.New("credentials not handed off before start")
	}
	s.active = true
	s.starts++
	return nil
}
func (s *localSystemd) StopUnit(context.Context, string) error { s.active = false; return nil }
func (s *localSystemd) RestartUnit(context.Context, string) error {
	if s.failRestart {
		s.failRestart = false
		return errors.New("injected restart interruption")
	}
	if s.requireCredentials && !s.credentialReady {
		return errors.New("credentials not handed off before start")
	}
	s.active = true
	s.starts++
	return nil
}
func (s *localSystemd) UnitActive(context.Context, string) (bool, error) { return s.active, nil }

type localUsers struct{ systemd *localSystemd }

func (u localUsers) EnsureUser(context.Context, string) error {
	u.systemd.accountReady = true
	return nil
}
func (localUsers) OwnDirectory(context.Context, string, string) error { return nil }

type localDownloads map[string][]byte

func (d localDownloads) Download(ctx context.Context, url, target string, limit int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, ok := d[url]
	if !ok || int64(len(data)) > limit {
		return errors.New("unknown release")
	}
	return os.WriteFile(target, data, 0600)
}
func localBootstrapFixture(t *testing.T) (LocalBootstrapConfig, *localSystemd, string) {
	return localBootstrapComponent(t, "terrabase")
}
func localBootstrapComponent(t *testing.T, component string) (LocalBootstrapConfig, *localSystemd, string) {
	t.Helper()
	root := t.TempDir()
	dataRoot := filepath.Join(t.TempDir(), "data")
	unitRoot := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("actual signed initial fixture artifact")
	digest := sha256.Sum256(artifact)
	spec := ComponentSpec{Name: component, Version: "1.0.0", ArtifactURL: "https://releases.terrascale.tech/terrabase", SignatureURL: "https://releases.terrascale.tech/terrabase.sig", Sha256: hex.EncodeToString(digest[:]), User: "terrascale-" + component, DataVolume: filepath.Join(dataRoot, component), CPUWeight: 100, MemoryMaxBytes: 67108864, IOWeight: 100, Arguments: "--config @config", Configuration: `{"region":"gru"}`}
	downloads := localDownloads{spec.ArtifactURL: artifact, spec.SignatureURL: ed25519.Sign(priv, artifact)}
	installer, err := NewInstaller(InstallerConfig{InstallRoot: root, PublicKeyHex: hex.EncodeToString(pub), Downloader: downloads})
	if err != nil {
		t.Fatal(err)
	}
	systemd := &localSystemd{}
	lifecycle, err := NewLifecycle(LifecycleConfig{InstallRoot: root, UnitDir: unitRoot, DataVolumeRoot: dataRoot, Installer: installer, Systemd: systemd, Users: localUsers{systemd: systemd}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := HostManifest{Components: []ComponentSpec{spec}}
	_, public, grant, _ := bootstrapTestGrant(t, manifest)
	path := filepath.Join(dataRoot, TsNodeComponentName, "manifest.json")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	canonical, _ := CanonicalHostManifestJSON(manifest)
	if err = os.WriteFile(path, canonical, 0600); err != nil {
		t.Fatal(err)
	}
	return LocalBootstrapConfig{NodeID: "gru-1", PublicKeyPEM: public, SignedGrant: grant, Lifecycle: lifecycle, ManifestPath: path, InstallRoot: root, Timeout: 3 * time.Second}, systemd, root
}
func TestOfflineInitialGrantActivatesWithoutBrokerAndRetires(t *testing.T) {
	config, systemd, root := localBootstrapFixture(t)
	if err := RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	current, err := CurrentVersion(root, "terrabase")
	if err != nil || current != "1.0.0" || !systemd.active {
		t.Fatalf("initial state %s active=%v err=%v", current, systemd.active, err)
	}
	starts := systemd.starts
	if err = RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if starts != systemd.starts {
		t.Fatal("completed local activation repeated restart")
	}
	store, err := nodeauthority.NewEpochStore(filepath.Join(filepath.Dir(config.ManifestPath), "command-journal"), "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Admit(nodeauthority.CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 7, CandidateID: "gru-controller-1", LeaseID: "actual-lease"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	systemd.active = false
	if err = RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if systemd.active || systemd.starts != starts {
		t.Fatal("retired local grant caused effects")
	}
}
func TestOfflineInitialGrantRetriesInterruptedEffectAndBoundsReadiness(t *testing.T) {
	config, systemd, _ := localBootstrapFixture(t)
	systemd.failRestart = true
	if err := RunLocalBootstrap(context.Background(), config); err == nil {
		t.Fatal("failed initial restart reported success")
	}
	if err := RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatalf("fresh local signed grant retry: %v", err)
	}
	config.Timeout = time.Nanosecond
	if err := RunLocalBootstrap(context.Background(), config); err == nil {
		t.Fatal("expired operation timeout reported readiness")
	}
}

func bootstrapTestGrant(t *testing.T, manifest HostManifest) (*security.CommandSignatureSigner, []byte, []byte, BootstrapGrant) {
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

func TestCredentialHandoffUsesSignedAccountBeforeAnyServiceStart(t *testing.T) {
	config, systemd, root := localBootstrapComponent(t, "orchestrator")
	systemd.requireCredentials = true
	observed := false
	config.CredentialHandoff = func(ctx context.Context, user, digest string) error {
		if !systemd.accountReady || systemd.starts != 0 || user != "terrascale-orchestrator" {
			t.Fatalf("handoff ordering/account differs: user=%s account=%v starts=%d", user, systemd.accountReady, systemd.starts)
		}
		grant, err := VerifyBootstrapGrant(config.NodeID, config.PublicKeyPEM, config.SignedGrant)
		if err != nil {
			return err
		}
		expected, err := HostManifestSha256(grant.Manifest)
		if err != nil || expected != digest {
			t.Fatal("handoff did not receive authenticated full manifest digest")
		}
		observed = true
		return errors.New("injected ownership journal interruption")
	}
	if err := RunLocalBootstrap(context.Background(), config); err == nil {
		t.Fatal("failed credential handoff reported success")
	}
	if !observed || systemd.starts != 0 || InstalledVersion(root, "orchestrator", "1.0.0") {
		t.Fatal("failed handoff allowed install/service effects")
	}
	config.CredentialHandoff = func(context.Context, string, string) error { systemd.credentialReady = true; return nil }
	if err := RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatalf("handoff retry: %v", err)
	}
	if !systemd.active {
		t.Fatal("service did not activate after credentials were handed off")
	}
}

func TestConfiguredInitialJournalRejectsAmbiguousLaunchFields(t *testing.T) {
	config, systemd, _ := localBootstrapFixture(t)
	systemd.failRestart = true
	if err := RunLocalBootstrap(context.Background(), config); err == nil {
		t.Fatal("injected restart interruption did not leave a pending plan")
	}
	journalPath := filepath.Join(filepath.Dir(config.ManifestPath), "command-journal", "commands.json")
	original, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	starts := systemd.starts
	for _, replacement := range []string{
		`"unknownArguments":`,
		`"Arguments":`,
		`"arguments":"--config @config","arguments":`,
		`"arguments":null,"arguments":`,
	} {
		changed := bytes.Replace(original, []byte(`"arguments":`), []byte(replacement), 1)
		if bytes.Equal(changed, original) {
			t.Fatal("configured transition plan was not journaled")
		}
		if err = os.WriteFile(journalPath, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err = RunLocalBootstrap(context.Background(), config); err == nil {
			t.Fatalf("ambiguous journal launch field admitted: %s", replacement)
		}
		if systemd.starts != starts {
			t.Fatal("invalid journal triggered a service effect")
		}
	}
	if err = os.WriteFile(journalPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatalf("canonical configured journal replay: %v", err)
	}
	starts = systemd.starts
	if err = RunLocalBootstrap(context.Background(), config); err != nil {
		t.Fatalf("completed configured journal replay: %v", err)
	}
	if systemd.starts != starts {
		t.Fatal("completed configured journal replay restarted service")
	}
}
