package delivery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenRequestPath and goldenReceiptPath are the compatibility fixtures:
// byte-for-byte what ts-deploy's DeliverySerialize produces for the same
// values. The test locks the two codecs together across repositories.
const (
	goldenRequestPath = "testdata/request-v1.json"
	goldenReceiptPath = "testdata/receipt-v1.json"
)

func golden(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(path))
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", path, err)
	}
	return string(body)
}

// TestContractRoundTripAgainstGoldenFixtures proves the mirrored contract
// parses what ts-deploy serializes, re-serializes it identically, and
// validates under the shared rules.
func TestContractRoundTripAgainstGoldenFixtures(t *testing.T) {
	requestText := golden(t, goldenRequestPath)
	request, err := ParseRequest(requestText)
	if err != nil {
		t.Fatalf("parse golden request: %v", err)
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("validate golden request: %v", err)
	}
	if Serialize(request) != requestText {
		t.Fatalf("request serialization diverged from the golden fixture:\n%s", Serialize(request))
	}

	receiptText := golden(t, goldenReceiptPath)
	receipt, err := ParseReceipt(receiptText)
	if err != nil {
		t.Fatalf("parse golden receipt: %v", err)
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("validate golden receipt: %v", err)
	}
	if Serialize(receipt) != receiptText {
		t.Fatalf("receipt serialization diverged from the golden fixture:\n%s", Serialize(receipt))
	}
}

// TestParseRequestRejectsMalformedDocuments mirrors the ts-deploy codec's
// closed-vocabulary rejections: unknown fields, trailing data, depth, and
// size bounds.
func TestParseRequestRejectsMalformedDocuments(t *testing.T) {
	valid := golden(t, goldenRequestPath)
	cases := []struct {
		name string
		body string
		code string
	}{
		{"empty", "", "delivery_request_invalid"},
		{"whitespace", "   ", "delivery_request_invalid"},
		{"not json", "terrabase", "delivery_request_invalid"},
		{"trailing document", valid + `{"another":1}`, "delivery_request_invalid"},
		// encoding/json matches fields case-insensitively, so a case change
		// alone is NOT an unknown field in either codec; a new name is.
		{"unknown field", strings.Replace(valid, `"requestedBy"`, `"requestedByExtra"`, 1), "delivery_request_invalid"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if _, err := ParseRequest(item.body); err == nil {
				t.Fatal("expected a rejection")
			} else if code, ok := AsValidationError(err); !ok {
				t.Fatalf("expected a validation error, got %v", err)
			} else if code.Code != item.code {
				t.Fatalf("expected code %s, got %s", item.code, code.Code)
			}
		})
	}
	oversized := `{"schemaVersion":1,"pad":"` + strings.Repeat("x", MaxDocumentBytes) + `"}`
	if _, err := ParseRequest(oversized); err == nil {
		t.Fatal("expected the oversized document to be rejected")
	}
	deep := strings.Repeat(`{"a":`, maxJSONDepth+2) + "1" + strings.Repeat("}", maxJSONDepth+2)
	if _, err := ParseRequest(deep); err == nil {
		t.Fatal("expected the deeply nested document to be rejected")
	}
}

// TestValidateRequestRejectsWithTsDeployCodes exercises the request
// validator against the same rejection classes ts-deploy tests, with the
// shared error codes.
func TestValidateRequestRejectsWithTsDeployCodes(t *testing.T) {
	base, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatalf("parse golden request: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Request)
		code   string
	}{
		{"schema", func(r *Request) { r.SchemaVersion = 2 }, "schema_unsupported"},
		{"operation id", func(r *Request) { r.OperationID = "../escape" }, "operation_id_invalid"},
		{"no source or artifact", func(r *Request) { r.Source = nil; r.Artifact = nil }, "source_or_artifact_required"},
		{"no target", func(r *Request) { r.Target = nil }, "target_required"},
		{"artifact digest", func(r *Request) { r.Artifact.Digest = "md5:zz" }, "digest_invalid"},
		{"artifact kind", func(r *Request) { r.Artifact.Kind = "container" }, "artifact_kind_invalid"},
		{"artifact architecture", func(r *Request) { r.Artifact.Architecture = "darwin/arm64" }, "artifact_architecture_invalid"},
		{"environment", func(r *Request) { r.Target.Environment = "staging" }, "target_invalid"},
		{"empty regions", func(r *Request) { r.Target.Regions = nil }, "target_invalid"},
		{"duplicate regions", func(r *Request) { r.Target.Regions = []string{"gru", "gru"} }, "target_invalid"},
		{"bad commit", func(r *Request) { r.Source.Commit = "main" }, "source_invalid"},
		{"rollback without artifact", func(r *Request) { r.Artifact = nil }, "rollback_invalid"},
		{"rollback same digest", func(r *Request) { r.Rollback.ArtifactDigest = r.Artifact.Digest }, "rollback_not_prior"},
		{"configuration revision", func(r *Request) { r.ConfigurationRevision = "v1" }, "digest_invalid"},
		{"actor", func(r *Request) { r.RequestedBy = "" }, "actor_invalid"},
		{"secret in reason", func(r *Request) { r.Reason = "token=abc123" }, "secret_input_rejected"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			request := *base
			if base.Source != nil {
				source := *base.Source
				request.Source = &source
			}
			if base.Artifact != nil {
				artifact := *base.Artifact
				request.Artifact = &artifact
			}
			if base.Target != nil {
				target := *base.Target
				target.Regions = append([]string(nil), base.Target.Regions...)
				request.Target = &target
			}
			if base.Rollback != nil {
				rollback := *base.Rollback
				request.Rollback = &rollback
			}
			item.mutate(&request)
			err := ValidateRequest(&request)
			if err == nil {
				t.Fatal("expected a rejection")
			}
			code, ok := AsValidationError(err)
			if !ok {
				t.Fatalf("expected a validation error, got %v", err)
			}
			if code.Code != item.code {
				t.Fatalf("expected code %s, got %s", item.code, code.Code)
			}
		})
	}
}

// TestValidateReceiptEnforcesTerminalContract locks the receipt rules the
// orchestrator must satisfy for ts-deploy to accept its receipts.
func TestValidateReceiptEnforcesTerminalContract(t *testing.T) {
	request, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatalf("parse golden request: %v", err)
	}
	receipt, err := ParseReceipt(golden(t, goldenReceiptPath))
	if err != nil {
		t.Fatalf("parse golden receipt: %v", err)
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("golden receipt must validate: %v", err)
	}

	mutate := func(name string, change func(*Receipt), wantCode string) {
		t.Helper()
		candidate := *receipt
		if candidate.Target != nil {
			target := *candidate.Target
			target.Regions = append([]string(nil), candidate.Target.Regions...)
			candidate.Target = &target
		}
		if candidate.Health != nil {
			health := *candidate.Health
			health.Checks = make([]*HealthCheck, len(candidate.Health.Checks))
			for i, check := range candidate.Health.Checks {
				if check != nil {
					copied := *check
					health.Checks[i] = &copied
				}
			}
			candidate.Health = &health
		}
		if candidate.Rollback != nil {
			rollback := *candidate.Rollback
			candidate.Rollback = &rollback
		}
		if candidate.Provenance != nil {
			provenance := *candidate.Provenance
			candidate.Provenance = &provenance
		}
		change(&candidate)
		err := ValidateReceipt(&candidate, request)
		if err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
		code, ok := AsValidationError(err)
		if !ok {
			t.Fatalf("%s: expected a validation error, got %v", name, err)
		}
		if code.Code != wantCode {
			t.Fatalf("%s: expected code %s, got %s", name, wantCode, code.Code)
		}
	}

	mutate("unverified success", func(r *Receipt) { r.Provenance.Verified = false }, "receipt_success_unverified")
	mutate("failed health success", func(r *Receipt) { r.Health.Checks[1].Status = "failed" }, "receipt_success_unverified")
	mutate("not converged", func(r *Receipt) { r.Health.Converged = false }, "receipt_success_unverified")
	mutate("status vocabulary", func(r *Receipt) { r.Status = "in_progress" }, "receipt_status_invalid")
	mutate("operation mismatch", func(r *Receipt) { r.OperationID = "other" }, "receipt_operation_mismatch")
	mutate("source missing", func(r *Receipt) { r.Source = nil }, "receipt_source_missing")
	mutate("target mismatch", func(r *Receipt) { r.Target.Regions = []string{"gru"} }, "receipt_target_mismatch")
	mutate("half artifact identity", func(r *Receipt) { r.ArtifactManifestDigest = nil }, "receipt_artifact_identity_incomplete")
	mutate("provenance mismatch", func(r *Receipt) { r.Provenance.ConfigurationRevision = "sha256:" + strings.Repeat("9", 64) }, "receipt_provenance_mismatch")
	mutate("success with rollback", func(r *Receipt) { r.Rollback.Status = RollbackSucceeded }, "receipt_rollback_invalid")

	failed := *receipt
	failed.Status = StatusFailed
	failed.Error = &Error{Code: ptr("gate_failed"), Message: ptr("health gate failed after canary"), Remediation: ptr("inspect the canary host")}
	failed.Health.Converged = false
	failed.Health.Checks[1].Status = "failed"
	failed.Rollback.Status = RollbackNotRequired
	if err := ValidateReceipt(&failed, request); err != nil {
		t.Fatalf("failed receipt must validate: %v", err)
	}

	rolledBack := *receipt
	rolledBack.Status = StatusRolledBack
	rolledBack.Health.Converged = false
	rolledBack.Rollback = &Rollback{
		Attempted:            true,
		TargetArtifactDigest: ptr(request.Rollback.ArtifactDigest),
		Status:               RollbackSucceeded,
		TargetManifestDigest: ptr(request.Rollback.ManifestDigest),
	}
	if err := ValidateReceipt(&rolledBack, request); err != nil {
		t.Fatalf("rolled-back receipt must validate: %v", err)
	}
}

func ptr[T any](value T) *T { return &value }
