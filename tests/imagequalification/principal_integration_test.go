package imagequalification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

func TestPrincipalRefinementRequiresSealedResultAndOriginalQualifier(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var p principal.Preparation
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Schema = principal.PreparationSchema
	p.IssuerPrincipal, p.IssuerFingerprint = "ocid1.user.oc1..issuer", strings.TrimSuffix(strings.Repeat("12:", 16), ":")
	p.PrincipalName, p.GroupName, p.PolicyName = "ts-qualification-"+a.RunID+"-user", "ts-qualification-"+a.RunID+"-group", "ts-qualification-"+a.RunID+"-policy"
	p.Object = "qualification/" + a.RunID + "/" + a.Candidate.ArtifactSHA256 + ".qcow2"
	p.ExpiresAt = f.prepared.expires
	p.PublicKeyPEM, p.PublicKeyFingerprint, err = principal.GenerateKey(filepath.Join(t.TempDir(), "escrow"))
	if err != nil {
		t.Fatal(err)
	}
	p.PolicyTemplate = principal.RequiredTemplate(p)
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := trust.Sign(payload, principal.PreparationScope(p.RunID, p.Candidate), f.now.Add(-time.Minute), p.CleanupUntil, f.private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.VerifyPreparation(wire, nil, f.roots, p.RunID, f.now); err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		signer     ed25519.PrivateKey
	}{
		{"unsealed-result", "sealed SDK principal result", f.private},
		{"different-qualifier", "original preparation qualifier", other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, approval, err := PrepareFromPrincipal(wire, nil, f.roots, principal.Result{}, tc.signer, p.RunID, f.disk, f.qualification, f.now)
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(approval) != 0 || prepared.approvalSHA256 != "" {
				t.Fatalf("refinement produced authority: prepared=%v approval=%d err=%v", prepared.approvalSHA256 != "", len(approval), err)
			}
		})
	}
}
