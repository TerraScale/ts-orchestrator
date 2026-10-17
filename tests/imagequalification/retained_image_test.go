package imagequalification

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSDKRetainedImageCleansHostsThenExpiresExactImage(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	a.Purpose, a.Candidate.Role = qualification.RootCredentialBoundaryPurpose, release.FoundationWriterRole
	a.ArtifactDisposition, a.ReaderIAMAuthority, a.ImagePublicationBucket = qualification.RetainTestedImage, qualification.ExactHostReaders, "gru-1-head"
	a.ImageRetainUntil, a.ImageTransferUntil = f.now.Add(30*time.Minute), f.now.Add(20*time.Minute)
	sign := func(body any, role string, expires time.Time) []byte {
		payload, err := json.Marshal(body, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		e, err := trust.Sign(payload, qualification.Scope(a.RunID, a.Candidate, role), f.now.Add(-time.Minute), expires, f.private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	approvalWire := sign(a, "disposable-host", f.now.Add(40*time.Minute))
	p, err := Prepare(approvalWire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	prep := qualification.Preparation{Schema: "terrascale.test.image-qualification.principal.v1"}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &prep); err != nil {
		t.Fatal(err)
	}
	prep.Schema, prep.ExpiresAt = "terrascale.test.image-qualification.principal.v1", f.now.Add(40*time.Minute)
	p.principalWire = sign(prep, "disposable-principal", prep.CleanupUntil)
	remote := &cloudFixture{hosts: map[string]map[string]any{}, tokens: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(remote.serve))
	defer server.Close()
	c, err := newCloud(p, sdkFactory(t, a), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return f.now.Add(time.Minute) }
	path := filepath.Join(t.TempDir(), "resources.json")
	j, err := c.prepareResources(t.Context(), path, publicSSHKey(t))
	if err != nil {
		t.Fatal(err)
	}
	b := hostadmission.Binding{Schema: hostadmission.BindingSchema, Purpose: a.Purpose, RunID: a.RunID, PreparationSHA256: hashBytes(p.principalWire), ApprovalSHA256: p.approvalSHA256, HostName: a.Hosts[0].Name}
	for i, spec := range a.Hosts {
		b.Hosts = append(b.Hosts, hostadmission.BoundHost{Name: spec.Name, InstanceID: j.Hosts[spec.Name], ImageID: j.ImageID, PrivateIP: fmt.Sprintf("10.8.0.%d", i+2)})
	}
	proof := hostadmission.Proof{Schema: hostadmission.ProofSchema, Preparation: p.principalWire, Approval: approvalWire, Binding: sign(b, "disposable-host", a.ImageRetainUntil)}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := hostadmission.VerifyReaderPlan(wire, f.roots, f.now)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := json.Marshal(qualification.ReaderStatements("ocid1.dynamicgroup.oc1..readers", a.Compartment, plan.ExpiresAt()), json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	b.ReaderIAM = hostadmission.ReaderIAM{DynamicGroupID: "ocid1.dynamicgroup.oc1..readers", PolicyID: "ocid1.policy.oc1..readers", PolicySHA256: hashBytes(statements), PlanSHA256: plan.SHA256()}
	proof.Binding = sign(b, "disposable-host", a.ImageRetainUntil)
	j.RetainedReaderProof, err = json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	j.RetainedAt, j.RootGateSHA256 = f.now, hashBytes([]byte("test-only-typed-gate"))
	if err := checkpoint(path, j); err != nil {
		t.Fatal(err)
	}
	if err := c.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	cleaned, err := c.load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleaned.Terminated) != 4 || !cleaned.ObjectDeleted || cleaned.ImageDeleted || cleaned.CapabilityDeleted || remote.image == nil || remote.capability == nil {
		t.Fatal("retention preserved a host or deleted the exact tested image")
	}
	c.now = func() time.Time { return a.ImageRetainUntil.Add(time.Minute) }
	if err := c.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	cleaned, err = c.load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cleaned.ImageDeleted || !cleaned.CapabilityDeleted || remote.image != nil || remote.capability != nil {
		t.Fatal("expired original retention left an image or capability")
	}
	if err := c.cleanup(t.Context(), path); err != nil {
		t.Fatal("completed retained image cleanup did not remain idempotent", err)
	}
}
