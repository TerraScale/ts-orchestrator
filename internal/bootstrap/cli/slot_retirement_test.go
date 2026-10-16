package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignSlotRetirementRequiresOperatorConfirmation(t *testing.T) {
	fixture := newManifestFixture(t, 30*24*time.Hour, 20*24*time.Hour)
	now := time.Now().UTC().Truncate(time.Second)
	const instance = "ocid1.instance.oc1.sa-saopaulo-1.controller-b"
	candidate := bootstrap.RetirementEvidence{SchemaVersion: 1, DeploymentID: fixture.manifest.DeploymentID,
		Cell: string(fixture.manifest.Cell), Environment: fixture.manifest.Environment, Role: "controller",
		Slot: "controller-b", PreviousAttempt: 1, PreviousGeneration: 1,
		PreviousResultDigest: strings.Repeat("c", 64), PriorInstanceOCID: instance,
		PriorCreateKey: "founder-controller-b-key", Disposition: bootstrap.SlotRetirementDisposition,
		ObservedEvidenceDigest: strings.Repeat("e", 64), FencingAuthority: "authority-epoch-4",
		ObservedAt: now.Add(-time.Minute)}
	wire, err := protocol.EncodeJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(fixture.directory, "controller-b.retirement-request.json")
	writeFixture(t, candidatePath, wire, 0o600)
	run := func(out, slot, attempt, instanceID string) error {
		var output bytes.Buffer
		return command{ctx: t.Context(), output: &output}.runAt([]string{"sign-slot-retirement",
			"--candidate", candidatePath, "--slot", slot, "--attempt", attempt, "--instance", instanceID,
			"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath, "--out", out}, now)
	}
	for _, mismatch := range [][3]string{{"controller-c", "1", instance}, {"controller-b", "2", instance},
		{"controller-b", "1", instance + "x"}} {
		out := filepath.Join(fixture.directory, "mismatch.retirement")
		if err := run(out, mismatch[0], mismatch[1], mismatch[2]); err == nil {
			t.Fatalf("signed with mismatched confirmation %v", mismatch)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("mismatched confirmation wrote evidence")
		}
	}
	out := filepath.Join(fixture.directory, "controller-b.retirement")
	if err := run(out, "controller-b", "1", instance); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := bootstrap.DecodeSlotRetirementCandidate(signed)
	if err != nil || decoded != candidate {
		t.Fatalf("decoded = %+v, %v", decoded, err)
	}
	envelope, err := trust.DecodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.VerifyCurrent(envelope, envelope.Scope, roots, now, trust.Policy{
		MaxLifetime: bootstrap.MaxSlotRetirementLifetime, ClockSkew: time.Minute}); err != nil {
		t.Fatalf("signed retirement does not verify under the root: %v", err)
	}
	if err := run(out, "controller-b", "1", instance); err == nil {
		t.Fatal("existing evidence was overwritten")
	}
}
