package transferplan

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
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func planKey(t *testing.T) (*security.CommandSignatureSigner, []byte, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), der
}
func planWrite(t *testing.T, path string, v any) string {
	t.Helper()
	raw, ok := v.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func transferPlanFixture(t *testing.T) (planInput, string, []byte) {
	t.Helper()
	owner, private, public, _ := planKey(t)
	source, _, _, sourceDER := planKey(t)
	dir := t.TempDir()
	write := func(name string, v any) string { return planWrite(t, filepath.Join(dir, name), v) }
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Version: "1.0.0", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100}}}
	materials, err := vmcontrolseed.GenerateGRUWithPreliminaryCapture("0123456789abcdef0123456789abcdef", []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(sourceDER)}}, vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 32 << 20, Publication: &vmcontrolseed.PreliminaryPublicationDeclaration{Identity: ociinstance.Config{Region: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	raw, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := materials["gru-1"].LaunchManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	launchRaw, err := hostmanifest.CanonicalHostManifestJSON(launch)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grantIssued := now.Add(-3 * time.Hour)
	grantExpires := now.Add(3 * time.Hour)
	signedSource, err := nodebootstrap.SignBootstrapGrant(owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "source-bootstrap", NodeID: "gru-1", Manifest: launchRaw, IssuedAt: grantIssued, ExpiresAt: grantExpires})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := initialgrant.VerifyProof("gru-1", public, signedSource)
	if err != nil {
		t.Fatal(err)
	}
	cfg, id := proof.Config(), proof.Identity()
	inventory, err := initialcontrol.PreliminaryInventory(cfg.Cell, cfg.SeedInstance, cfg.Regional.Account, cfg.Global.Account)
	if err != nil {
		t.Fatal(err)
	}
	request := preliminarycapture.Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: id.GrantSHA256, StoreScopeSHA256: id.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, Accounts: inventory, ControlEpoch: 5, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	capture, err := preliminarycapture.SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: preliminarytransfer.Digest(capture), SourceNodeID: "gru-1", ControlEpoch: 5, CreatedAt: now.Add(-90 * time.Minute)}
	for _, a := range inventory {
		for _, stream := range a.Streams {
			key, err := preliminarycapture.ObjectKey(a.Account, stream, 5)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: a.Account, Stream: stream, Key: key, SHA256: "sha256:" + strings.Repeat("b", 64), Size: 2048, CreatedAt: receipt.CreatedAt.Add(-time.Minute)})
		}
	}
	captureReceipt, err := preliminarycapture.SignReceipt(source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	input := planInput{OwnerPrivateKeyFile: write("owner.key", private), PublicKeyFile: write("owner.pem", public), SourceNodeID: "gru-1", SourceBootstrapGrantFile: write("source.json", signedSource), CaptureRequestFile: write("capture.json", capture), CaptureReceiptFile: write("capture-receipt.json", captureReceipt), Prefix: "preliminary/transition-1", MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 32 << 20, MaxRestoreBytes: 32 << 20, UploadControlEpoch: 7, UploadIssuedAt: now.Add(-time.Minute), UploadExpiresAt: now.Add(time.Hour), CandidateIssuedAt: now.Add(-time.Minute), CandidateExpiresAt: now.Add(time.Hour)}
	preparation := transitiongrant.Grant{Version: 1, TransitionID: request.TransitionID, IssuedAt: grantIssued, ExpiresAt: grantExpires, TargetEpoch: 8, MinimumControlEpoch: 5, Source: transitiongrant.SourceIdentity{NodeID: "gru-1", ServerName: cfg.Broker.ServerName, InitialGrantSHA256: id.GrantSHA256, StoreScopeSHA256: id.StoreScopeSHA256}, Peers: []transitiongrant.Peer{{Region: "gru", NodeID: "gru-1", ServerName: cfg.Broker.ServerName, BootstrapGrantSHA256: id.GrantSHA256, PreparedManifestSHA256: id.ManifestSHA256}}}
	for i, region := range []string{"sfo", "fra"} {
		_, _, pin, _ := planKey(t)
		candidateCfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: request.TransitionID, NodeID: region + "-1", Region: region, ServerName: region + "-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem", Sync: &transitiongrant.CandidateSyncConfig{AuthorityReaderSHA256: strings.Repeat("c", 64), RequestFile: "/etc/terrascale/sync/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: "/etc/terrascale/sync/receipt.key", ReceiptPublicKeyPEM: string(pin), MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 32 << 20, MaxRestoreBytes: 32 << 20, Identity: ociinstance.Config{Region: []string{"us-sanjose-1", "eu-frankfurt-1"}[i]}}}
		m, err := bootstrap.PlanControlCandidateManifest(manifest, candidateCfg)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hostmanifest.CanonicalHostManifestJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := nodebootstrap.SignBootstrapGrant(owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: region + "-bootstrap", NodeID: candidateCfg.NodeID, Manifest: raw, IssuedAt: grantIssued, ExpiresAt: grantExpires})
		if err != nil {
			t.Fatal(err)
		}
		peer, err := bootstrap.PlanControlCandidatePeer(candidateCfg, public, signed)
		if err != nil {
			t.Fatal(err)
		}
		preparation.Peers = append(preparation.Peers, peer)
		input.Candidates = append(input.Candidates, candidateInput{NodeID: candidateCfg.NodeID, BootstrapGrantFile: write(region+".json", signed)})
	}
	prep, err := transitiongrant.SignGrant(owner, preparation)
	if err != nil {
		t.Fatal(err)
	}
	input.PreparationGrantFile = write("preparation.json", prep)
	for i, region := range []string{"gru", "sfo", "fra"} {
		input.Destinations = append(input.Destinations, preliminarytransfer.Destination{Region: region, OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.fixture", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}})
	}
	return input, write("input.json", input), private
}
func runPlanBundle(t *testing.T, path string) publicBundle {
	t.Helper()
	var out bytes.Buffer
	if err := Run(context.Background(), path, &out); err != nil {
		t.Fatal(err)
	}
	var b publicBundle
	if err := json.Unmarshal(out.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}
func TestTransferPlanEmitsHistoricalCaptureAndRenewal(t *testing.T) {
	input, path, private := transferPlanFixture(t)
	defer clear(private)
	bundle := runPlanBundle(t, path)
	now := time.Now().UTC()
	scope, err := preliminarytransfer.VerifyScope([]byte(bundle.PublicKeyPEM), bundle.Scope)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := scope.CaptureEpoch()
	if err != nil || epoch != 5 {
		t.Fatalf("capture epoch %d %v", epoch, err)
	}
	if scope.Digest != bundle.ScopeSHA256 || len(scope.Scope.Objects) != 45 || scope.Scope.MaxRestoreBytes != input.MaxRestoreBytes {
		t.Fatalf("scope inventory or limits changed: objects=%d restore=%d", len(scope.Scope.Objects), scope.Scope.MaxRestoreBytes)
	}
	upload, err := preliminarytransfer.VerifyUploadRequest([]byte(bundle.PublicKeyPEM), bundle.UploadRequest, now)
	if err != nil || upload.Authorization.ControlEpoch != 7 {
		t.Fatalf("upload: %v", err)
	}
	if len(bundle.Candidates) != 2 {
		t.Fatal("missing candidates")
	}
	for _, c := range bundle.Candidates {
		v, err := preliminarytransfer.VerifyCandidateRequest([]byte(bundle.PublicKeyPEM), c.Request, now)
		if err != nil || v.Authorization.NodeID != c.NodeID {
			t.Fatalf("candidate: %v", err)
		}
	}
	raw, _ := json.Marshal(bundle)
	for _, secret := range [][]byte{private, []byte(input.OwnerPrivateKeyFile), []byte(input.SourceBootstrapGrantFile), []byte("nkeyFile"), []byte("privateKeyFile")} {
		if bytes.Contains(raw, secret) {
			t.Fatal("private input escaped public output")
		}
	}
	input.PreviousUploadRequestFile = planWrite(t, filepath.Join(filepath.Dir(path), "previous.json"), []byte(bundle.UploadRequest))
	input.UploadControlEpoch = 8
	input.UploadIssuedAt = input.UploadIssuedAt.Add(30 * time.Second)
	input.UploadExpiresAt = input.UploadExpiresAt.Add(30 * time.Second)
	planWrite(t, path, input)
	renewed := runPlanBundle(t, path)
	if renewed.ScopeSHA256 != bundle.ScopeSHA256 {
		t.Fatal("renewal changed immutable scope")
	}
	input.Destinations[0].Bucket = "changed-bucket"
	planWrite(t, path, input)
	var out bytes.Buffer
	if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
		t.Fatal("changed renewal target accepted")
	}
}
func TestTransferPlanRefusesInvalidBindingsAndModes(t *testing.T) {
	input, path, private := transferPlanFixture(t)
	defer clear(private)
	other, _, otherPrivate := transferPlanFixture(t)
	defer clear(otherPrivate)
	for _, test := range []struct {
		name   string
		change func(*planInput)
	}{
		{"owner", func(i *planInput) { i.OwnerPrivateKeyFile = other.OwnerPrivateKeyFile }},
		{"capture-source-key", func(i *planInput) { i.CaptureReceiptFile = other.CaptureReceiptFile }},
		{"preparation", func(i *planInput) { i.PreparationGrantFile = other.PreparationGrantFile }},
		{"candidate-pins", func(i *planInput) { i.Candidates = other.Candidates }},
		{"source", func(i *planInput) { i.SourceNodeID = "gru-other" }},
		{"epoch", func(i *planInput) { i.UploadControlEpoch = 4 }},
		{"restore-capacity", func(i *planInput) { i.MaxRestoreBytes++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := input
			test.change(&changed)
			planWrite(t, path, changed)
			var out bytes.Buffer
			if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid plan produced output")
			}
		})
	}
	planWrite(t, path, input)
	for _, target := range []string{path, input.OwnerPrivateKeyFile, input.SourceBootstrapGrantFile, input.CaptureRequestFile, input.CaptureReceiptFile, input.PreparationGrantFile, input.Candidates[0].BootstrapGrantFile} {
		if err := os.Chmod(target, 0644); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
			t.Fatal("unprotected input accepted")
		}
		if err := os.Chmod(target, 0600); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), original...), []byte(`{}`)...), bytes.Replace(original, []byte(`"uploadControlEpoch":7`), []byte(`"uploadControlEpoch":7,"uploadControlEpoch":8`), 1), bytes.Replace(original, []byte(`"sourceNodeId"`), []byte(`"SourceNodeId"`), 1), bytes.Replace(original, []byte(`"uploadControlEpoch":7`), []byte(`"uploadControlEpoch":null`), 1)} {
		planWrite(t, path, bad)
		var out bytes.Buffer
		if err := Run(context.Background(), path, &out); err == nil || out.Len() != 0 {
			t.Fatal("ambiguous plan accepted")
		}
	}
}
