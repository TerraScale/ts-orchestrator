package candidateplan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func syncPlanFixture(t *testing.T) (candidatePlanInput, string) {
	t.Helper()
	input, path, owner := candidatePlanFixture(t)
	clear(owner)
	public, err := os.ReadFile(input.PublicKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(public)
	seeds, err := vmcontrolseed.GenerateGRU("0123456789abcdef0123456789abcdef", []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(block.Bytes)}})
	if err != nil {
		t.Fatal(err)
	}
	m := seeds["gru-1"]
	defer m.Clear()
	reader, err := m.AuthorityReader()
	if err != nil {
		t.Fatal(err)
	}
	runner := t.TempDir()
	write := func(name, guest string) string {
		p := filepath.Join(runner, name)
		if err := os.WriteFile(p, m.Files[guest], 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	d := vmcandidateseed.Declaration{Reader: reader, ReaderNKeyFile: write("reader.seed", reader.NKeySeedFile), ReaderCAFile: write("ca.pem", reader.CAFile), ReaderCertificateFile: write("client.pem", reader.CertificateFile), ReaderPrivateKeyFile: write("client.key", reader.KeyFile)}
	input.PrivateMaterialDirectory = filepath.Join(runner, "private")
	for i := range input.Candidates {
		input.Candidates[i].SyncGeneration = &d
		input.Candidates[i].Config.Sync = &transitiongrant.CandidateSyncConfig{RequestFile: "/etc/terrascale/candidate/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: vmcandidateseed.ReceiptKeyPath, MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 8 << 20, MaxRestoreBytes: 8 << 20, Identity: ociinstance.Config{Region: "us-phoenix-1"}}
	}
	raw, _ := json.Marshal(input)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return input, path
}
func TestSyncPlanPersistsIdentityBeforeSigningAndReusesAfterOutputFailure(t *testing.T) {
	input, path := syncPlanFixture(t)
	if err := Run(context.Background(), path, failedOutput{}); err == nil {
		t.Fatal("failed output accepted")
	}
	before := map[string][]byte{}
	for _, e := range input.Candidates {
		p := filepath.Join(input.PrivateMaterialDirectory, e.Config.NodeID, "material.json")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		before[e.Config.NodeID] = raw
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("private artifact not protected")
		}
	}
	var out bytes.Buffer
	if err := Run(context.Background(), path, &out); err != nil {
		t.Fatal(err)
	}
	var retried bytes.Buffer
	if err := Run(context.Background(), path, &retried); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), retried.Bytes()) {
		t.Fatal("retry changed original signed public bundle")
	}
	var bundle candidatePlanBundle
	if err := json.Unmarshal(out.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	for _, e := range bundle.Candidates {
		raw, err := os.ReadFile(filepath.Join(input.PrivateMaterialDirectory, e.NodeID, "material.json"))
		if err != nil || !bytes.Equal(before[e.NodeID], raw) {
			t.Fatal("retry replaced material")
		}
		m, err := vmcandidateseed.Load(input.PrivateMaterialDirectory, e.NodeID, out.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.ValidateManifest(e.Manifest); err != nil {
			t.Fatal(err)
		}
		secret := m.Files[vmcandidateseed.ReceiptKeyPath]
		if bytes.Contains(out.Bytes(), secret) || bytes.Contains(out.Bytes(), []byte(input.PrivateMaterialDirectory)) {
			t.Fatal("private material escaped bundle")
		}
		other := append([]byte(nil), m.BootstrapGrant...)
		m.BootstrapGrant[len(m.BootstrapGrant)-3] ^= 1
		if m.Validate() == nil {
			t.Fatal("modified original owner admission accepted")
		}
		m.BootstrapGrant = other
		m.Reader.ServerName = "foreign"
		if m.Validate() == nil {
			t.Fatal("unbound reader accepted")
		}
		m.Clear()
	}
	input.Candidates[0].Config.Sync.MaxTotalBytes++
	raw, _ := json.Marshal(input)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
		t.Fatal("retry changed immutable configuration")
	}
	for node, expected := range before {
		raw, err := os.ReadFile(filepath.Join(input.PrivateMaterialDirectory, node, "material.json"))
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatal("rejected retry modified private identity")
		}
	}
}
func TestSyncPlanRejectsUnprotectedAndSymlinkMaterialDirectory(t *testing.T) {
	for _, kind := range []string{"mode", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			input, path := syncPlanFixture(t)
			if kind == "mode" {
				if err := os.Mkdir(input.PrivateMaterialDirectory, 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Symlink(t.TempDir(), input.PrivateMaterialDirectory); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("unprotected output accepted")
			}
		})
	}
}
func TestSyncPlanDoesNotReplaceCorruptPrivateArtifact(t *testing.T) {
	input, path := syncPlanFixture(t)
	var out bytes.Buffer
	if err := Run(context.Background(), path, &out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(input.PrivateMaterialDirectory, input.Candidates[0].Config.NodeID, "material.json")
	if err := os.WriteFile(p, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
		t.Fatal("corrupt prior identity replaced")
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "truncated" {
		t.Fatal("corrupt material overwritten")
	}
}
