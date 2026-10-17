package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Exercise retained qualification files against actual Git-built ELF bytes,
// then apply their signed release through OCI SDK HTTP without external tools.
func TestQualificationRetainedBinaryFilesystemApply(t *testing.T) {
	f := newApplyHTTPFixture(t)
	qualificationPath := filepath.Join(f.releaseDir, "qualification.json")
	wire, err := os.ReadFile(qualificationPath)
	if err != nil {
		t.Fatal(err)
	}
	qualification, digest, err := readQualification(qualificationPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(wire)
	if digest != hex.EncodeToString(wantDigest[:]) || qualification.Verification != (release.QualificationCheck{
		Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
		RunID: 4001, RunNumber: 620, Conclusion: "success",
	}) {
		t.Fatalf("retained qualification lost exact bytes or required check identity: digest=%s check=%+v", digest, qualification.Verification)
	}

	// Fixture production is complete; the consumer must not need Git, gh or Go.
	t.Setenv("PATH", t.TempDir())
	c := command{ctx: t.Context(), output: io.Discard}
	candidateArgs := func(output string) []string {
		return []string{"--binary", f.binaryPath, "--source-revision", f.binary.SourceRevision,
			"--qualification", qualificationPath, "--go-version", f.binary.GoVersion, "--out", output}
	}
	output := filepath.Join(t.TempDir(), "candidate.json")
	if err := c.binaryCandidate(candidateArgs(output)); err != nil {
		t.Fatalf("retained qualification and ELF rejected: %v", err)
	}
	candidate, err := readCanonicalPayload[binaryReceipt](output)
	if err != nil || candidate != f.binary || candidate.QualificationSHA256 != digest {
		t.Fatalf("candidate differs from retained bytes or exact qualification: %+v, %v", candidate, err)
	}
	applyEnv := f.env
	applyEnv.timeout = 5 * time.Second
	if err := c.applyWith(f.args, applyEnv); err != nil {
		t.Fatalf("signed retained release could not apply without external tools: %v", err)
	}
	binary, err := os.ReadFile(f.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		if f.channelWrites[cell] != 1 || f.binaryCreates[cell] != 1 ||
			!bytes.Equal(f.objects[cell][releasechannel.BinaryObject(candidate.SHA256)], binary) {
			t.Errorf("%s did not retain the qualified binary and signed channel: channels=%d binaries=%d",
				cell, f.channelWrites[cell], f.binaryCreates[cell])
		}
	}
	f.mu.Unlock()

	for _, test := range []struct {
		name   string
		mutate func(*release.Qualification)
	}{
		{"missing run", func(q *release.Qualification) { q.Verification.RunID = 0 }},
		{"missing run number", func(q *release.Qualification) { q.Verification.RunNumber = 0 }},
		{"failed check", func(q *release.Qualification) { q.Verification.Conclusion = "failure" }},
		{"wrong job", func(q *release.Qualification) { q.Verification.Job = "build-only" }},
		{"missing lock digest", func(q *release.Qualification) { q.GoSumSHA256 = "" }},
		{"missing architecture", func(q *release.Qualification) { q.Artifacts = q.Artifacts[:1] }},
		{"duplicate architecture", func(q *release.Qualification) { q.Artifacts[1] = q.Artifacts[0] }},
		{"other artifact bytes", func(q *release.Qualification) { q.Artifacts[0].SHA256 = strings.Repeat("b", 64) }},
		{"other source", func(q *release.Qualification) { q.SourceRevision = strings.Repeat("b", 40) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := qualification
			changed.Artifacts = slices.Clone(qualification.Artifacts)
			test.mutate(&changed)
			encoded, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			writeFixtureFile(t, qualificationPath, encoded, 0o600)
			output := filepath.Join(t.TempDir(), "refused.json")
			if err := c.binaryCandidate(candidateArgs(output)); !errors.Is(err, release.ErrInvalidQualification) {
				t.Fatalf("invalid retained qualification error = %v; want ErrInvalidQualification", err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused qualification left a candidate: %v", err)
			}
		})
	}
	for _, test := range []struct{ name, suffix string }{
		{"duplicate JSON member", `,"schema":"terrascale.release.qualification.v1"}`},
		{"unknown JSON member", `,"unrecognized":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := append(bytes.Clone(wire[:len(wire)-1]), test.suffix...)
			writeFixtureFile(t, qualificationPath, changed, 0o600)
			output := filepath.Join(t.TempDir(), "refused.json")
			if err := c.binaryCandidate(candidateArgs(output)); err == nil {
				t.Fatal("ambiguous retained qualification produced a candidate")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ambiguous qualification left a candidate: %v", err)
			}
		})
	}
}
