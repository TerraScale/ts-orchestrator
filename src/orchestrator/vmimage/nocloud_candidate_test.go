package vmimage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func candidateImageFixture(t *testing.T) TSNodeBootstrap {
	t.Helper()
	input := validNoCloudSpec(t).TSNode
	_, membership, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(input.MembershipIdentityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	seeds, err := vmcontrolseed.GenerateGRU("candidate-image", []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: membership}})
	if err != nil {
		t.Fatal(err)
	}
	source := seeds["gru-1"]
	defer source.Clear()
	reader, err := source.AuthorityReader()
	if err != nil {
		t.Fatal(err)
	}
	runner := t.TempDir()
	write := func(name, guest string) string {
		path := filepath.Join(runner, name)
		if err := os.WriteFile(path, source.Files[guest], 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	declaration := vmcandidateseed.Declaration{Reader: reader, ReaderNKeyFile: write("seed", reader.NKeySeedFile), ReaderCAFile: write("ca", reader.CAFile), ReaderCertificateFile: write("cert", reader.CertificateFile), ReaderPrivateKeyFile: write("key", reader.KeyFile)}
	config := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "transition-1", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: vmcandidateseed.GrantPath, GrantPublicKeyFile: vmcandidateseed.OwnerPath, Sync: &transitiongrant.CandidateSyncConfig{RequestFile: "/etc/terrascale/candidate/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: vmcandidateseed.ReceiptKeyPath, MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 8 << 20, MaxRestoreBytes: 8 << 20, Identity: ociinstance.Config{Region: "us-phoenix-1"}}}
	private, err := vmcandidateseed.Generate(filepath.Join(runner, "private"), config, declaration, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	m := &vmcandidateseed.Material{PrivateArtifact: private}
	t.Cleanup(m.Clear)
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = bootstrap.PlanControlCandidateManifest(manifest, m.Config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hostmanifest.CanonicalHostManifestJSON(manifest)
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
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	m.PublicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	now := time.Now().UTC()
	m.BootstrapGrant, err = nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "sfo-bootstrap", NodeID: "sfo-1", Manifest: raw, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := bootstrap.PlanControlCandidatePeer(m.Config, m.PublicKeyPEM, m.BootstrapGrant)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	grant := transitiongrant.Grant{Version: 1, TransitionID: "transition-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), TargetEpoch: 2, MinimumControlEpoch: 1, Source: transitiongrant.SourceIdentity{NodeID: "gru-1", ServerName: "gru-store", InitialGrantSHA256: digest, StoreScopeSHA256: digest}, Peers: []transitiongrant.Peer{{Region: "gru", NodeID: "gru-1", ServerName: "gru-store", BootstrapGrantSHA256: digest, PreparedManifestSHA256: digest}, peer, {Region: "fra", NodeID: "fra-1", ServerName: "fra-store", BootstrapGrantSHA256: digest, PreparedManifestSHA256: digest}}}
	m.PreparationGrant, err = transitiongrant.SignGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	input.Candidate = m
	input.Config.NodeID = "sfo-1"
	input.Config.AuthorityReader = reader
	input.DesiredHostManifest = raw
	input.InitialGrant = &TSNodeInitialGrant{PublicKeyPEM: m.PublicKeyPEM, SignedGrant: m.BootstrapGrant}
	return input
}
func TestCandidateImageStagesOnlyBoundPrivateFiles(t *testing.T) {
	input := candidateImageFixture(t)
	files, err := canonicalCandidateBootstrap(input)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, file := range files {
		found[file.Path] = true
		if err := file.Validate(); err != nil {
			t.Fatal(err)
		}
		if vmcontrolseed.IsAuthorityFilePath(file.Path) && file.Owner != "" {
			t.Fatal("reader credentials must remain root-owned")
		}
		if vmcandidateseed.IsServiceFile(file.Path) && file.Owner != vmcontrolseed.ServiceUser {
			t.Fatal("candidate worker cannot access own credentials")
		}
	}
	if !found[vmcandidateseed.ReceiptKeyPath] || !found[vmcandidateseed.GrantPath] || !found[vmcandidateseed.OwnerPath] || len(found) != 7 {
		t.Fatal("unexpected candidate sideband")
	}
	script := controllerOwnershipBootstrap(files)
	if !strings.Contains(script, "chown terrascale-orchestrator:terrascale-orchestrator "+vmcandidateseed.ReceiptKeyPath) || strings.Contains(script, " "+vmcontrolseed.AuthorityPrivateKeyPath+"\n") {
		t.Fatal("incorrect candidate ownership staging")
	}
	private := input.Candidate.Files[vmcandidateseed.ReceiptKeyPath]
	if bytes.Contains(input.DesiredHostManifest, private) {
		t.Fatal("receipt private key in public manifest")
	}
}
func TestCandidateImageRejectsChangedAdmissionAndCredentials(t *testing.T) {
	for _, kind := range []string{"reader", "node", "manifest", "owner", "grant", "private", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			input := candidateImageFixture(t)
			switch kind {
			case "reader":
				input.Config.AuthorityReader.ServerName = "other"
			case "node":
				input.Config.NodeID = "sfo-other"
			case "manifest":
				input.DesiredHostManifest = []byte(`{"components":[]}`)
			case "owner":
				input.InitialGrant.PublicKeyPEM = []byte("other")
			case "grant":
				input.Candidate.PreparationGrant[len(input.Candidate.PreparationGrant)-3] ^= 1
			case "private":
				input.Candidate.Files[vmcandidateseed.ReceiptKeyPath] = input.MembershipIdentityPrivateKey
			case "mixed":
				input.Controller = &vmcontrolseed.Material{}
			}
			if _, err := canonicalCandidateBootstrap(input); err == nil {
				t.Fatal("unbound candidate image accepted")
			}
		})
	}
}
