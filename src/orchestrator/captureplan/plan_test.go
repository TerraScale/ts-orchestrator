package captureplan

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func capturePlanFixture(t *testing.T, enabled bool) (planInput, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Version: "1.0.0", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100}}}
	guests := []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(pub)}}
	seeds, err := vmcontrolseed.GenerateGRU("0123456789abcdef0123456789abcdef", guests)
	if enabled {
		for _, seed := range seeds {
			seed.Clear()
		}
		seeds, err = vmcontrolseed.GenerateGRUWithPreliminaryCapture("0123456789abcdef0123456789abcdef", guests, vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 32 << 20})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, seed := range seeds {
			seed.Clear()
		}
	}()
	raw, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source, err := seeds["gru-1"].LaunchManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	sourceRaw, err := hostmanifest.CanonicalHostManifestJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "source-bootstrap", NodeID: "gru-1", Manifest: sourceRaw, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	input := planInput{OwnerPrivateKeyFile: write("owner-secret.pem", private), PublicKeyFile: write("owner.pem", public), SourceNodeID: "gru-1", SourceBootstrapGrantFile: write("source.json", signed), TransitionID: "transition-1", ControlEpoch: 1, IssuedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(30 * time.Minute)}
	raw, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return input, write("input.json", raw), private
}

func TestCapturePlanDerivesExactPublicOwnerRequest(t *testing.T) {
	input, path, private := capturePlanFixture(t, true)
	defer clear(private)
	var output bytes.Buffer
	if err := Run(context.Background(), path, &output); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{private, []byte(input.OwnerPrivateKeyFile), []byte(input.SourceBootstrapGrantFile), []byte("nkeyFile"), []byte("privateKeyFile"), []byte("outputDir")} {
		if bytes.Contains(output.Bytes(), secret) {
			t.Fatal("private material or path escaped output")
		}
	}
	var bundle publicBundle
	if err := json.Unmarshal(output.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarycapture.VerifyRequest([]byte(bundle.PublicKeyPEM), bundle.Request)
	if err != nil || verified.Check(time.Now().UTC()) != nil {
		t.Fatalf("request signature: %v", err)
	}
	original, err := os.ReadFile(input.SourceBootstrapGrantFile)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := initialgrant.VerifyProof(input.SourceNodeID, []byte(bundle.PublicKeyPEM), original)
	if err != nil {
		t.Fatal(err)
	}
	cfg, identity := proof.Config(), proof.Identity()
	request := verified.Request
	wantAccounts, err := initialcontrol.PreliminaryInventory(cfg.Cell, cfg.SeedInstance, cfg.Regional.Account, cfg.Global.Account)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(request.Accounts)
	want, _ := json.Marshal(wantAccounts)
	if !bytes.Equal(got, want) || request.InitialGrantSHA256 != identity.GrantSHA256 || request.StoreScopeSHA256 != identity.StoreScopeSHA256 || request.ProfileSHA256 != cfg.ProfileSHA256 || request.ControlEpoch != input.ControlEpoch || request.TransitionID != input.TransitionID || !request.IssuedAt.Equal(input.IssuedAt) || !request.ExpiresAt.Equal(input.ExpiresAt) {
		t.Fatal("request changed exact source binding")
	}
}

func TestCapturePlanRejectsInvalidBindingsWithoutOutput(t *testing.T) {
	input, path, private := capturePlanFixture(t, true)
	defer clear(private)
	other, _, otherPrivate := capturePlanFixture(t, true)
	defer clear(otherPrivate)
	tests := []struct {
		name   string
		change func(*planInput)
	}{
		{"wrong-owner", func(i *planInput) { i.OwnerPrivateKeyFile = other.OwnerPrivateKeyFile }},
		{"wrong-source", func(i *planInput) { i.SourceNodeID = "gru-other" }},
		{"wrong-public", func(i *planInput) { i.PublicKeyFile = other.PublicKeyFile }},
		{"zero-epoch", func(i *planInput) { i.ControlEpoch = 0 }},
		{"future", func(i *planInput) { i.IssuedAt = time.Now().Add(time.Minute) }},
		{"expired", func(i *planInput) { i.ExpiresAt = time.Now().Add(-time.Second) }},
		{"before-grant", func(i *planInput) { i.IssuedAt = time.Now().Add(-time.Hour) }},
		{"outlives-grant", func(i *planInput) { i.ExpiresAt = time.Now().Add(2 * time.Hour) }},
		{"invalid-transition", func(i *planInput) { i.TransitionID = "bad transition" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := input
			test.change(&changed)
			raw, _ := json.Marshal(changed)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid request produced output")
			}
		})
	}
}

func TestCapturePlanRequiresEnabledSeedAndProtectedInputs(t *testing.T) {
	_, disabled, secret := capturePlanFixture(t, false)
	defer clear(secret)
	var out bytes.Buffer
	if err := Run(context.Background(), disabled, &out); err == nil || out.Len() != 0 {
		t.Fatal("unsigned capture capability admitted")
	}
	input, path, private := capturePlanFixture(t, true)
	defer clear(private)
	for _, target := range []string{path, input.OwnerPrivateKeyFile, input.SourceBootstrapGrantFile} {
		if err := os.Chmod(target, 0644); err != nil {
			t.Fatal(err)
		}
		if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
			t.Fatal("unprotected input admitted")
		}
		if err := os.Chmod(target, 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(filepath.Dir(path), "linked-input")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), link, &out); err == nil || out.Len() != 0 {
		t.Fatal("symlink admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, path, &out); err != context.Canceled || out.Len() != 0 {
		t.Fatal("cancellation lost")
	}
}

func TestCapturePlanStrictInputAndOutputFailure(t *testing.T) {
	_, path, private := capturePlanFixture(t, true)
	defer clear(private)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), []byte("{}")...),
		bytes.Replace(raw, []byte(`"controlEpoch":1`), []byte(`"controlEpoch":1,"controlEpoch":2`), 1),
		bytes.Replace(raw, []byte(`"controlEpoch":1`), []byte(`"ControlEpoch":1`), 1),
		bytes.Replace(raw, []byte(`"controlEpoch":1`), []byte(`"controlEpoch":null`), 1),
		bytes.Replace(raw, []byte(`"controlEpoch":1`), []byte(`"controlEpoch":1,"accounts":[]`), 1),
	} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
			t.Fatal("ambiguous input accepted")
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), path, shortWriter{}); err == nil {
		t.Fatal("short output accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }
