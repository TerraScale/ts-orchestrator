package candidateplan

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

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func candidatePlanFixture(t *testing.T) (candidatePlanInput, string, []byte) {
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
	seeds, err := vmcontrolseed.GenerateGRU("0123456789abcdef0123456789abcdef", []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(pub)}})
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
	input := candidatePlanInput{OwnerPrivateKeyFile: write("owner-secret.pem", private), PublicKeyFile: write("owner.pem", public), SourceNodeID: "gru-1", SourceBootstrapGrantFile: write("source.json", signed), TransitionID: "transition-1", TargetEpoch: 2, MinimumControlEpoch: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), BootstrapExpiresAt: now.Add(10 * time.Minute)}
	for _, region := range []string{"sfo", "fra"} {
		input.Candidates = append(input.Candidates, Entry{Manifest: manifest, BootstrapGrantID: "bootstrap-" + region, Config: transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: input.TransitionID, NodeID: region + "-1", Region: region, ServerName: region + "-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem"}})
	}
	raw, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return input, write("input.json", raw), private
}

func TestPlanControlCandidatesEmitsExactPublicSignedBundle(t *testing.T) {
	input, path, private := candidatePlanFixture(t)
	defer clear(private)
	var output bytes.Buffer
	if err := Run(context.Background(), path, &output); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{private, []byte(input.OwnerPrivateKeyFile), []byte(input.SourceBootstrapGrantFile)} {
		if bytes.Contains(output.Bytes(), secret) {
			t.Fatal("private material or producer path escaped output")
		}
	}
	var bundle candidatePlanBundle
	if err := json.Unmarshal(output.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	verified, err := transitiongrant.VerifyGrant([]byte(bundle.PublicKeyPEM), bundle.PreparationGrant)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(input.SourceBootstrapGrantFile)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := initialgrant.VerifyProof(input.SourceNodeID, []byte(bundle.PublicKeyPEM), original)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Grant.Source.InitialGrantSHA256 != proof.Identity().GrantSHA256 || verified.Grant.Source.StoreScopeSHA256 != proof.Identity().StoreScopeSHA256 {
		t.Fatal("source was not derived from signed initial proof")
	}
	if len(bundle.Candidates) != 2 {
		t.Fatal("candidate inventory incomplete")
	}
	for i, candidate := range bundle.Candidates {
		peer, err := bootstrap.PlanControlCandidatePeer(input.Candidates[i].Config, []byte(bundle.PublicKeyPEM), candidate.BootstrapGrant)
		if err != nil {
			t.Fatal(err)
		}
		if err := verified.CheckCandidate(time.Now().UTC(), input.Candidates[i].Config, peer.BootstrapGrantSHA256, peer.PreparedManifestSHA256); err != nil {
			t.Fatal(err)
		}
		authority, err := nodebootstrap.NewBootstrapAuthority(candidate.NodeID, []byte(bundle.PublicKeyPEM), candidate.BootstrapGrant)
		if err != nil {
			t.Fatal(err)
		}
		if !authority.Grant().ExpiresAt.Equal(input.BootstrapExpiresAt) || !verified.Grant.ExpiresAt.Equal(input.ExpiresAt) || !authority.Grant().ExpiresAt.Before(verified.Grant.ExpiresAt) {
			t.Fatal("bootstrap and preparation expiry were not preserved independently")
		}
		if !bytes.Equal(authority.Grant().Manifest, candidate.Manifest) {
			t.Fatal("bundle manifest differs from signed admission")
		}
	}
}

func TestPlanControlCandidatesRejectsUntrustedInputsWithoutOutput(t *testing.T) {
	input, path, private := candidatePlanFixture(t)
	defer clear(private)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"duplicate root", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"targetEpoch":2`), []byte(`"targetEpoch":2,"targetEpoch":2`), 1)
		}},
		{"duplicate nested", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"region":"sfo"`), []byte(`"region":"sfo","region":"sfo"`), 1)
		}},
		{"case alias", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"region":"sfo"`), []byte(`"Region":"sfo"`), 1)
		}},
		{"unknown nested", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"region":"sfo"`), []byte(`"region":"sfo","unexpected":true`), 1)
		}},
		{"wrong transition", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"transitionId":"transition-1"`), []byte(`"transitionId":"transition-other"`), 1)
		}},
		{"wrong source", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"sourceNodeId":"gru-1"`), []byte(`"sourceNodeId":"gru-other"`), 1)
		}},
		{"trailing", func(raw []byte) []byte { return append(raw, []byte(`{}`)...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, test.mutate(append([]byte(nil), original...)), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := Run(context.Background(), path, &output); err == nil || output.Len() != 0 {
				t.Fatal("invalid plan produced output")
			}
		})
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []time.Time{input.IssuedAt, input.ExpiresAt.Add(time.Second), time.Now().Add(-time.Second), {}} {
		changed := input
		changed.BootstrapExpiresAt = expiry
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := Run(context.Background(), path, &output); err == nil || output.Len() != 0 {
			t.Fatal("out-of-range bootstrap expiry accepted")
		}
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(input.OwnerPrivateKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(context.Background(), path, &output); err == nil || output.Len() != 0 {
		t.Fatal("unprotected owner key accepted")
	}
	if err := os.Chmod(input.OwnerPrivateKeyFile, 0600); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.OwnerPrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	clear(der)
	if err := Run(context.Background(), path, &output); err == nil || output.Len() != 0 {
		t.Fatal("foreign owner signer accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, path, &output); err != context.Canceled {
		t.Fatalf("canceled producer: %v", err)
	}
}
