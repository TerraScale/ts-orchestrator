package vmqualbootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/candidateplan"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func TestPersistedSourcePlansCandidatesAndSignsFiniteCommandsWithoutLease(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	const runID = "0123456789abcdef0123456789abcdef"
	issuer, err := NewPersistentIssuer(state, runID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { issuer.Close() })
	block, _ := pem.Decode(issuer.public)
	seeds, err := vmcontrolseed.GenerateGRU(runID, []vmcontrolseed.Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(block.Bytes)}})
	if err != nil {
		t.Fatal(err)
	}
	seed := seeds["gru-1"]
	defer seed.Clear()
	base := grantManifest(t)
	raw, err := hostmanifest.CanonicalHostManifestJSON(base)
	if err != nil {
		t.Fatal(err)
	}
	sourceManifest, err := seed.LaunchManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	source, err := issuer.Grant("gru-1", sourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := seed.AuthorityReader()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, path string) string {
		t.Helper()
		filename := filepath.Join(root, name)
		if err := os.WriteFile(filename, seed.Files[path], 0600); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	declaration := vmcandidateseed.Declaration{Reader: reader, ReaderNKeyFile: write("reader.seed", reader.NKeySeedFile), ReaderCAFile: write("reader.ca", reader.CAFile), ReaderCertificateFile: write("reader.cert", reader.CertificateFile), ReaderPrivateKeyFile: write("reader.key", reader.KeyFile)}
	now := time.Now().UTC()
	plan := candidateplan.Plan{PrivateMaterialDirectory: filepath.Join(root, "candidates"), SourceNodeID: "gru-1", TargetEpoch: 2, MinimumControlEpoch: 1, TransitionID: "first-r3", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour), BootstrapExpiresAt: now.Add(10 * time.Minute)}
	for index, region := range []string{"sfo", "fra"} {
		location := []string{"us-sanjose-1", "eu-frankfurt-1"}[index]
		plan.Candidates = append(plan.Candidates, candidateplan.Entry{Manifest: base, BootstrapGrantID: region + "-candidate", SyncGeneration: &declaration, Config: transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: plan.TransitionID, NodeID: region + "-1", Region: region, ServerName: region + "-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: vmcandidateseed.GrantPath, GrantPublicKeyFile: vmcandidateseed.OwnerPath, Sync: &transitiongrant.CandidateSyncConfig{RequestFile: "/etc/terrascale/candidate/request.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: vmcandidateseed.ReceiptKeyPath, MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 8 << 20, MaxRestoreBytes: 8 << 20, Identity: ociinstance.Config{Region: location}}}})
	}
	first, err := issuer.PrepareCandidates(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].Config.Sync.ReceiptPublicKeyPEM != "" {
		t.Fatal("planning mutated signed caller intent")
	}
	candidate, err := issuer.AdmittedGrant("sfo-1")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := hostagent.VerifyBootstrapGrant("sfo-1", candidate.PublicKeyPEM, candidate.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := hostagent.NewBootstrapAuthority(refuseRuntime{}, "sfo-1", candidate.PublicKeyPEM, candidate.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := hostagent.BootstrapCommands(grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		wire, err := issuer.Sign("sfo-1", step.Subject, step.Command)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := authority.Authorize(t.Context(), step.Subject, wire)
		if err != nil || accepted.Epoch != 0 || accepted.LeaseID != "" || !bytes.Equal(accepted.Command, step.Command) {
			t.Fatalf("finite candidate command required or invented election: %v", err)
		}
	}
	issuer.Close()
	issuer, err = NewPersistentIssuer(state, runID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := issuer.Grant("gru-1", sourceManifest)
	if err != nil || !bytes.Equal(recovered.SignedGrant, source.SignedGrant) {
		t.Fatal("restart changed source admission", err)
	}
	second, err := issuer.PrepareCandidates(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("restart changed source-bound candidate signatures")
	}
	retained, err := issuer.AdmittedGrant("sfo-1")
	if err != nil || !bytes.Equal(retained.SignedGrant, candidate.SignedGrant) {
		t.Fatal("restart changed candidate finite admission", err)
	}
	plan.SourceNodeID = "gru-unissued"
	if _, err := issuer.PrepareCandidates(t.Context(), plan); err == nil {
		t.Fatal("planned candidates from an unissued source")
	}
}
