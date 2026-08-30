// Port of tests/TerraScale.Orchestrator.Protocol.Tests/StrongValueObjectTests.cs.
package protocol

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
)

func TestIdentifiersRejectEmptyWhitespaceAndNul(t *testing.T) {
	invalidValues := []string{"", " ", "\t", "cell\x00suffix"}

	for _, value := range invalidValues {
		if cell, ok := contracts.CellIdTryCreate(value); ok || cell.IsValid() {
			t.Fatalf("CellId accepted %q", value)
		}

		if aggregate, ok := contracts.AggregateIdTryCreate(value); ok || aggregate.IsValid() {
			t.Fatalf("AggregateId accepted %q", value)
		}

		if operation, ok := contracts.OperationIdTryCreate(value); ok || operation.IsValid() {
			t.Fatalf("OperationId accepted %q", value)
		}

		if idempotency, ok := contracts.IdempotencyKeyTryCreate(value); ok || idempotency.IsValid() {
			t.Fatalf("IdempotencyKey accepted %q", value)
		}
	}
}

func TestIdentifiersPreserveCallerSuppliedIdentityExactly(t *testing.T) {
	value := "Cell/Case-Sensitive:01"

	cell, ok := contracts.CellIdTryCreate(value)
	if !ok || cell.Value != value || cell.String() != value {
		t.Fatalf("CellId must preserve the caller value exactly: %q", cell.Value)
	}

	lower, ok := contracts.CellIdTryCreate("cell/case-sensitive:01")
	if !ok {
		t.Fatal("lowercase value must be accepted")
	}

	if cell == lower {
		t.Fatal("identifiers are case sensitive")
	}
}

func TestPositiveProtocolNumbersRejectZeroAndNegativeValues(t *testing.T) {
	for _, value := range []int64{-1 << 63, -1, 0} {
		if revision, ok := ProtocolRevisionTryCreate(value); ok || revision.IsValid() {
			t.Fatalf("ProtocolRevision accepted %d", value)
		}

		if generation, ok := DesiredGenerationTryCreate(value); ok || generation.IsValid() {
			t.Fatalf("DesiredGeneration accepted %d", value)
		}

		if epoch, ok := WriterEpochTryCreate(value); ok || epoch.IsValid() {
			t.Fatalf("WriterEpoch accepted %d", value)
		}

		if attempt, ok := DeliveryAttemptTryCreate(value); ok || attempt.IsValid() {
			t.Fatalf("DeliveryAttempt accepted %d", value)
		}
	}
}

func TestPositiveProtocolNumbersAcceptFullPositiveRange(t *testing.T) {
	for _, value := range []int64{1, 2, 1<<63 - 1} {
		if revision, ok := ProtocolRevisionTryCreate(value); !ok || revision.Value != value {
			t.Fatalf("ProtocolRevision rejected %d", value)
		}

		if generation, ok := DesiredGenerationTryCreate(value); !ok || generation.Value != value {
			t.Fatalf("DesiredGeneration rejected %d", value)
		}

		if epoch, ok := WriterEpochTryCreate(value); !ok || epoch.Value != value {
			t.Fatalf("WriterEpoch rejected %d", value)
		}

		if attempt, ok := DeliveryAttemptTryCreate(value); !ok || attempt.Value != value {
			t.Fatalf("DeliveryAttempt rejected %d", value)
		}
	}
}
