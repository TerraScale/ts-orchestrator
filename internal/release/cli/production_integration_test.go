package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestProductionAdmissionRetainedArtifactBoundary(t *testing.T) {
	f := newApplyHTTPFixture(t)
	candidate := productionCandidate(f.binary, "GRU")
	for _, refusal := range []string{"", "missing record", "source", "digest", "manifest", "cell", "environment", "runtime", "architecture", "role", "missing gate", "future proof", "tampered evidence", "expired", "future record", "wrong signer", "release capability"} {
		t.Run(refusal, func(t *testing.T) {
			directory := t.TempDir()
			record := writeProductionEvidence(t, directory, candidate)
			signer := f.rootPrivate
			now := time.Now().UTC()
			issued, expires := now.Add(-time.Minute), now.Add(time.Hour)
			switch refusal {
			case "source":
				record.Candidate.SourceRevision = strings.Repeat("1", 40)
			case "digest":
				record.Candidate.ArtifactSHA256 = strings.Repeat("1", 64)
			case "manifest":
				record.Candidate.QualificationSHA256 = strings.Repeat("1", 64)
			case "cell":
				record.Candidate.Cell = "SJC"
			case "environment":
				record.Candidate.Environment = "canary"
			case "runtime":
				record.Candidate.Runtime = "unqualified"
			case "architecture":
				record.Candidate.Architecture = "arm64"
			case "role":
				record.Candidate.Role = "terrabase"
			case "missing gate":
				record.Evidence = record.Evidence[:1]
			case "future proof":
				record.Evidence[0].CompletedAt = now.Add(time.Minute)
			case "tampered evidence":
				if err := os.WriteFile(filepath.Join(directory, "objects", record.Evidence[0].SHA256), []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "future record":
				issued = now.Add(5 * time.Minute)
				expires = now.Add(time.Hour)
			case "expired":
				issued, expires = now.Add(-2*time.Hour), now.Add(-time.Hour)
			case "wrong signer", "release capability":
				_, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer = private
			}
			path := filepath.Join(directory, "GRU", "amd64", "production.json")
			if refusal != "missing record" {
				writeProductionRecord(t, path, record, signer, issued, expires)
			}
			if refusal == "release capability" {
				writeQualificationDelegation(t, filepath.Join(filepath.Dir(path), "delegation.json"), candidate, signer, f.rootPrivate, release.BinaryDomain)
			}
			var output bytes.Buffer
			err := Run(t.Context(), []string{"verify-production", "--dir", f.releaseDir, "--evidence-dir", directory,
				"--root-key", f.rootPath, "--cell", "GRU", "--arch", "amd64"}, &output)
			if (err != nil) != (refusal != "") {
				t.Fatalf("qualification %q: %v\n%s", refusal, err, output.String())
			}
			if !strings.Contains(output.String(), `"schema":"terrascale.release.production-admission.v1"`) ||
				strings.Contains(output.String(), `"state":"qualified"`) != (refusal == "") {
				t.Fatalf("missing versioned qualified/refused result: %s", output.String())
			}
		})
	}
	t.Run("explicit qualification capability", func(t *testing.T) {
		directory := t.TempDir()
		record := writeProductionEvidence(t, directory, candidate)
		_, signer, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "GRU", "amd64", "production.json")
		writeProductionRecord(t, path, record, signer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		writeQualificationDelegation(t, filepath.Join(filepath.Dir(path), "delegation.json"), candidate, signer, f.rootPrivate, release.ProductionQualificationDomain)
		if err := (command{ctx: t.Context(), output: io.Discard}).verifyProductionArtifacts(directory, f.roots, "GRU", "production",
			map[string]binaryReceipt{"amd64": f.binary}, time.Now().Add(30*time.Minute)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("regional failures preserve other admission results", func(t *testing.T) {
		directory := t.TempDir()
		record := writeProductionEvidence(t, directory, candidate)
		writeProductionRecord(t, filepath.Join(directory, "GRU", "amd64", "production.json"), record, f.rootPrivate,
			time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		var output bytes.Buffer
		err := Run(t.Context(), []string{"verify-production", "--dir", f.releaseDir, "--evidence-dir", directory,
			"--root-key", f.rootPath, "--cell", "SJC", "--cell", "GRU", "--arch", "amd64"}, &output)
		if err == nil || !strings.Contains(err.Error(), "SJC") || !strings.Contains(output.String(), `"cell":"GRU"`) ||
			!strings.Contains(output.String(), `"state":"qualified"`) || !strings.Contains(output.String(), `"state":"refused"`) {
			t.Fatalf("lost independent regional result: %v\n%s", err, output.String())
		}
	})
	t.Run("future authorization cannot start a rollout", func(t *testing.T) {
		directory := t.TempDir()
		record := writeProductionEvidence(t, directory, candidate)
		now := time.Now().UTC()
		writeProductionRecord(t, filepath.Join(directory, "GRU", "amd64", "production.json"), record, f.rootPrivate, now.Add(5*time.Minute), now.Add(time.Hour))
		err := (command{ctx: t.Context(), output: io.Discard}).verifyProductionArtifacts(directory, f.roots, "GRU", "production", map[string]binaryReceipt{"amd64": f.binary}, now.Add(20*time.Minute))
		if !errors.Is(err, release.ErrProductionQualification) {
			t.Fatalf("future authorization started immediately: %v", err)
		}
	})
	t.Run("future rollout deadline outlives qualification", func(t *testing.T) {
		directory := t.TempDir()
		record := writeProductionEvidence(t, directory, candidate)
		writeProductionRecord(t, filepath.Join(directory, "GRU", "amd64", "production.json"), record, f.rootPrivate,
			time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
		err := (command{ctx: t.Context()}).verifyProductionArtifacts(directory, f.roots, "GRU", "production",
			map[string]binaryReceipt{"amd64": f.binary}, time.Now().Add(30*time.Minute))
		if !errors.Is(err, trust.ErrExpired) {
			t.Fatalf("rollout can outlive admission: %v", err)
		}
	})
}

func productionCandidate(binary binaryReceipt, cell string) release.ProductionExpectation {
	return release.ProductionExpectation{SourceRevision: binary.SourceRevision, ArtifactSHA256: binary.SHA256,
		QualificationSHA256: binary.QualificationSHA256, Cell: cell, Environment: "production",
		Runtime: release.ProductionRuntime, Architecture: binary.GOARCH, Role: "orchestrator"}
}

func writeProductionEvidence(t *testing.T, directory string, candidate release.ProductionExpectation) release.ProductionQualification {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(directory, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	record := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		data, err := json.Marshal(struct{ Gate, SourceRevision, ArtifactSHA256 string }{gate, candidate.SourceRevision, candidate.ArtifactSHA256})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		sum := hex.EncodeToString(digest[:])
		if err := os.WriteFile(filepath.Join(directory, "objects", sum), data, 0o600); err != nil {
			t.Fatal(err)
		}
		record.Evidence = append(record.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: sum,
			Bytes: int64(len(data)), CompletedAt: time.Now().UTC().Add(-3 * time.Hour)})
	}
	return record
}

func writeProductionRecord(t *testing.T, path string, record release.ProductionQualification, private ed25519.PrivateKey, issued, expires time.Time) {
	t.Helper()
	payload, err := trust.EncodePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), issued, expires, private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeQualificationDelegation(t *testing.T, path string, candidate release.ProductionExpectation, private, root ed25519.PrivateKey, domain string) {
	t.Helper()
	public := private.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	scope := release.ProductionQualificationScope(candidate)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}},
		time.Now().Add(-time.Hour), time.Now().Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := trust.EncodeEnvelope(delegation)
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
}
