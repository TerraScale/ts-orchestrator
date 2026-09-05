package nodeauthority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type candidateTransferFixture struct {
	owner, source        *security.CommandSignatureSigner
	public, sourcePublic []byte
	config               transitiongrant.Config
	grant                transitiongrant.Grant
	receipt              CandidatePreparationReceipt
	directory            string
	now                  time.Time
}

func candidateTransferSigner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Dispose() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func newCandidateTransferFixture(t *testing.T) candidateTransferFixture {
	t.Helper()
	owner, public := candidateTransferSigner(t)
	source, sourcePublic := candidateTransferSigner(t)
	_, candidatePublic := candidateTransferSigner(t)
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewEpochStore(private, "sfo-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	boot, manifest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := store.AdmitBootstrap(boot, manifest); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	config := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-one", Region: "sfo", ServerName: "sfo-control", StoreDir: "/var/lib/terrascale/orchestrator/control", GrantFile: filepath.Join(root, "grant.json"), GrantPublicKeyFile: filepath.Join(root, "owner.pem"), Sync: &transitiongrant.CandidateSyncConfig{AuthorityReaderSHA256: strings.Repeat("e", 64), RequestFile: "/etc/terrascale/candidate/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: "/etc/terrascale/candidate/receipt.key", ReceiptPublicKeyPEM: string(candidatePublic), MaxSnapshotBytes: 4096, MaxTotalBytes: 8192, MaxRestoreBytes: 8192, Identity: ociinstance.Config{Region: "us-sanjose-1"}}}
	grant := transitiongrant.Grant{Version: 1, TransitionID: config.TransitionID, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Source: transitiongrant.SourceIdentity{NodeID: "gru-one", ServerName: "gru-control", InitialGrantSHA256: boot, StoreScopeSHA256: manifest}, TargetEpoch: 2, MinimumControlEpoch: 5}
	for _, region := range []string{"gru", "sfo", "fra"} {
		grant.Peers = append(grant.Peers, transitiongrant.Peer{Region: region, NodeID: region + "-one", ServerName: region + "-control", BootstrapGrantSHA256: boot, PreparedManifestSHA256: manifest})
	}
	signed, err := transitiongrant.SignGrant(owner, grant)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "public")
	receipt, err := store.admitCandidatePreparation(context.Background(), public, signed, config, boot, manifest, directory, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return candidateTransferFixture{owner, source, public, sourcePublic, config, grant, receipt, directory, now}
}

func (f candidateTransferFixture) request(t *testing.T, changeCapture func(*preliminarycapture.Request), changeScope func(*preliminarytransfer.Scope), changeAuth func(*preliminarytransfer.CandidateAuthorization)) []byte {
	t.Helper()
	request := preliminarycapture.Request{Version: 1, TransitionID: f.config.TransitionID, SourceNodeID: f.grant.Source.NodeID, InitialGrantSHA256: f.grant.Source.InitialGrantSHA256, StoreScopeSHA256: f.grant.Source.StoreScopeSHA256, ProfileSHA256: strings.Repeat("c", 64), Accounts: []preliminarycapture.AccountInventory{{Account: "GLOBAL", Streams: []string{"SPEC"}}, {Account: "REGIONAL", Streams: []string{"EVENTS"}}}, ControlEpoch: 5, IssuedAt: f.now.Add(-2 * time.Hour), ExpiresAt: f.now.Add(-110 * time.Minute)}
	if changeCapture != nil {
		changeCapture(&request)
	}
	capture, err := preliminarycapture.SignRequest(f.owner, request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: preliminarytransfer.Digest(capture), SourceNodeID: request.SourceNodeID, ControlEpoch: request.ControlEpoch, CreatedAt: request.IssuedAt.Add(2 * time.Minute)}
	for _, account := range request.Accounts {
		key, err := preliminarycapture.ObjectKey(account.Account, account.Streams[0], request.ControlEpoch)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: account.Account, Stream: account.Streams[0], Key: key, SHA256: "sha256:" + strings.Repeat("d", 64), Size: 2048, CreatedAt: request.IssuedAt.Add(time.Minute)})
	}
	signedReceipt, err := preliminarycapture.SignReceipt(f.source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(f.sourcePublic), CaptureRequest: capture, CaptureReceipt: signedReceipt, RequestSHA256: preliminarytransfer.Digest(capture), ReceiptSHA256: preliminarytransfer.Digest(signedReceipt), PreparationGrantSHA256: f.receipt.GrantSHA256, Prefix: "preliminary/first-r3", MaxSnapshotBytes: 4096, MaxTotalBytes: 8192, MaxRestoreBytes: 8192}
	for _, region := range []string{"gru", "sfo", "fra"} {
		ociRegion := "oci-" + region
		if region == "sfo" {
			ociRegion = f.config.Sync.Identity.Region
		}
		scope.Destinations = append(scope.Destinations, preliminarytransfer.Destination{Region: region, OCIRegion: ociRegion, Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}})
		for _, object := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: region, Account: object.Account, Stream: object.Stream, LocalKey: object.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + object.Key, SHA256: object.SHA256, Size: object.Size})
		}
	}
	_, fraPublic := candidateTransferSigner(t)
	for _, region := range []string{"sfo", "fra"} {
		key := string(fraPublic)
		if region == "sfo" {
			key = f.config.Sync.ReceiptPublicKeyPEM
		}
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: region + "-one", ServerName: region + "-control", BootstrapGrantSHA256: f.receipt.BootstrapGrantSHA256, ManifestSHA256: f.receipt.ManifestSHA256, ReceiptPublicKeyPEM: key})
	}
	if changeScope != nil {
		changeScope(&scope)
	}
	signedScope, err := preliminarytransfer.SignScope(f.owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	verifiedScope, err := preliminarytransfer.VerifyScope(f.public, signedScope)
	if err != nil {
		t.Fatal(err)
	}
	auth := preliminarytransfer.CandidateAuthorization{Version: 1, ScopeSHA256: verifiedScope.Digest, NodeID: f.config.NodeID, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(30 * time.Minute)}
	if changeAuth != nil {
		changeAuth(&auth)
	}
	signedAuth, err := preliminarytransfer.SignCandidateAuthorization(f.owner, auth)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := preliminarytransfer.MarshalRequest(signedScope, signedAuth)
	if err != nil {
		t.Fatal(err)
	}
	// Every rejection test starts with valid protocol authority, isolating the
	// additional original host admission boundary exercised below.
	if _, err := preliminarytransfer.VerifyCandidateRequest(f.public, raw, time.Now()); err != nil {
		t.Fatalf("invalid protocol fixture: %v", err)
	}
	return raw
}

func TestPublishedCandidateTransferBindsOriginalAdmission(t *testing.T) {
	f := newCandidateTransferFixture(t)
	raw := f.request(t, nil, nil, nil)
	var decoded transitiongrant.Config
	encoded, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Sync == f.config.Sync {
		t.Fatal("fixture did not independently allocate nested config")
	}
	verified, receipt, err := verifyCandidateRequest(context.Background(), decoded, raw, f.directory, uint32(os.Geteuid()))
	if err != nil || receipt != f.receipt || verified.Authorization.NodeID != f.config.NodeID {
		t.Fatalf("original admission with decoded config rejected: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := verifyCandidateRequest(canceled, decoded, raw, f.directory, uint32(os.Geteuid())); err == nil {
		t.Fatal("canceled admission accepted transfer")
	}
	cases := []struct {
		name    string
		capture func(*preliminarycapture.Request)
		scope   func(*preliminarytransfer.Scope)
		auth    func(*preliminarytransfer.CandidateAuthorization)
	}{
		{name: "source", capture: func(r *preliminarycapture.Request) { r.SourceNodeID = "gru-other" }},
		{name: "initial grant", capture: func(r *preliminarycapture.Request) { r.InitialGrantSHA256 = strings.Repeat("f", 64) }},
		{name: "store scope", capture: func(r *preliminarycapture.Request) { r.StoreScopeSHA256 = strings.Repeat("f", 64) }},
		{name: "minimum capture epoch", capture: func(r *preliminarycapture.Request) { r.ControlEpoch = 4 }},
		{name: "preparation grant", scope: func(s *preliminarytransfer.Scope) { s.PreparationGrantSHA256 = strings.Repeat("f", 64) }},
		{name: "manifest", scope: func(s *preliminarytransfer.Scope) { s.Candidates[0].ManifestSHA256 = strings.Repeat("f", 64) }},
		{name: "bootstrap grant", scope: func(s *preliminarytransfer.Scope) { s.Candidates[0].BootstrapGrantSHA256 = strings.Repeat("f", 64) }},
		{name: "server", scope: func(s *preliminarytransfer.Scope) { s.Candidates[0].ServerName = "sfo-other" }},
		{name: "receipt key", scope: func(s *preliminarytransfer.Scope) {
			_, key := candidateTransferSigner(t)
			s.Candidates[0].ReceiptPublicKeyPEM = string(key)
		}},
		{name: "snapshot budget", scope: func(s *preliminarytransfer.Scope) { s.MaxSnapshotBytes++ }},
		{name: "total budget", scope: func(s *preliminarytransfer.Scope) { s.MaxTotalBytes++ }},
		{name: "restore budget", scope: func(s *preliminarytransfer.Scope) { s.MaxRestoreBytes++ }},
		{name: "OCI region", scope: func(s *preliminarytransfer.Scope) { s.Destinations[1].OCIRegion = "eu-frankfurt-1" }},
		{name: "node", auth: func(a *preliminarytransfer.CandidateAuthorization) { a.NodeID = "fra-one" }},
		{name: "authorization predates preparation", auth: func(a *preliminarytransfer.CandidateAuthorization) { a.IssuedAt = f.grant.IssuedAt.Add(-time.Second) }},
		{name: "authorization outlives preparation", auth: func(a *preliminarytransfer.CandidateAuthorization) { a.ExpiresAt = f.grant.ExpiresAt.Add(time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := f.request(t, tc.capture, tc.scope, tc.auth)
			if _, _, err := verifyCandidateRequest(context.Background(), f.config, raw, f.directory, uint32(os.Geteuid())); err == nil {
				t.Fatal("transfer escaped original admission")
			}
		})
	}
}

func TestPublishedCandidateTransferDoesNotTrustConfigurationKeyFiles(t *testing.T) {
	f := newCandidateTransferFixture(t)
	raw := f.request(t, nil, nil, nil)
	replacement, public := candidateTransferSigner(t)
	// Writing a replacement owner into the configured key path cannot change
	// trust, even though an otherwise valid request is signed by that owner.
	if err := os.WriteFile(f.config.GrantPublicKeyFile, public, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config.GrantFile, []byte("replacement grant"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyCandidateRequest(context.Background(), f.config, raw, f.directory, uint32(os.Geteuid())); err != nil {
		t.Fatalf("configured files replaced pinned owner: %v", err)
	}
	attacker := f
	attacker.owner = replacement
	attacker.public = public
	if _, _, err := verifyCandidateRequest(context.Background(), f.config, attacker.request(t, nil, nil, nil), f.directory, uint32(os.Geteuid())); err == nil {
		t.Fatal("configured replacement owner authorized transfer")
	}
	changed := f.config
	copySync := *f.config.Sync
	changed.Sync = &copySync
	changed.Sync.MaxTotalBytes++
	if _, _, err := verifyCandidateRequest(context.Background(), changed, raw, f.directory, uint32(os.Geteuid())); err == nil {
		t.Fatal("nested configuration changed after publication")
	}
	for _, mode := range []string{"corrupt", "missing"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(f.directory, "preparation.json")
			if mode == "corrupt" {
				if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifyCandidateRequest(context.Background(), f.config, raw, f.directory, uint32(os.Geteuid())); err == nil {
				t.Fatal("transfer accepted without valid publication")
			}
			called := false
			if err := withinCandidateMutation(context.Background(), f.config, f.directory, uint32(os.Geteuid()), func(context.Context) error { called = true; return nil }); err == nil || called {
				t.Fatal("effect ran without valid publication")
			}
		})
	}
}
