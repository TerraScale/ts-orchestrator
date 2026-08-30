// Port of tools/TerraScale.Orchestrator.Tooling/ToolingTests.cs: the
// repository self-test suite behind the `test` command.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type toolingTests struct{}

// ToolingTests mirrors the C# static class.
var ToolingTests = toolingTests{}

type toolingTest struct {
	Name string
	Body func()
}

func (toolingTests) Run(arguments []string) (int, error) {
	if len(arguments) != 0 && !(len(arguments) == 1 && arguments[0] == "--repository-only") {
		return 0, newToolValidationException([]string{"test accepts only --repository-only"})
	}

	tests := toolingTestSuite()
	var failures []string
	for _, test := range tests {
		if err := runToolingTestBody(test.Body); err != nil {
			failures = append(failures, fmt.Sprintf("FAIL %s: %s", test.Name, err.Error()))
		} else {
			fmt.Printf("PASS %s\n", test.Name)
		}
	}

	if len(failures) != 0 {
		return 0, newToolValidationException(failures)
	}
	fmt.Printf("Passed %d C# tooling tests.\n", len(tests))
	return 0, nil
}

// runToolingTestBody mirrors the C# per-test catch: any panic becomes a
// recorded failure carrying its message.
func runToolingTestBody(body func()) (failure error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if err, ok := recovered.(error); ok {
				failure = err
				return
			}
			failure = fmt.Errorf("%v", recovered)
		}
	}()
	body()
	return nil
}

func toolingTestSuite() []toolingTest {
	return []toolingTest{
		{"adr baseline", func() {
			assertValidErrors(AdrReadinessCommand.Validate(mustDocument(ToolingSupport.ReadObject("docs/adr/readiness-index.yaml"))))
		}},
		{"adr duplicate id", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 1, "id"), 1), AdrReadinessCommand.Validate)
		}},
		{"adr accepted status", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "status"), "accepted"), AdrReadinessCommand.Validate)
		}},
		{"adr accepted field", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "accepted"), true), AdrReadinessCommand.Validate)
		}},
		{"adr invalid lane", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "ownerLane"), "unknown"), AdrReadinessCommand.Validate)
		}},
		{"adr missing field", func() {
			assertInvalidDocument(deleteDocumentValue("docs/adr/readiness-index.yaml", testSegments("entries", 0, "title")), AdrReadinessCommand.Validate)
		}},
		{"adr unknown controlling input", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "controllingInputs", 0), "unknown-input"), AdrReadinessCommand.Validate)
		}},
		{"adr ownership expansion drift", func() {
			assertInvalidDocument(deleteDocumentValue("docs/adr/readiness-index.yaml", testSegments("entries", 0, "openInputOwnershipReferences", 0)), AdrReadinessCommand.Validate)
		}},
		{"adr executable self dependency", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "executableDependencies"), []int{1}), AdrReadinessCommand.Validate)
		}},
		{"adr executable dependency cycle", adrExecutableDependencyCycle},
		{"adr malformed anchor", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "sourceAnchors", 0), "https://example.test/a:1-2"), AdrReadinessCommand.Validate)
		}},
		{"adr traversal anchor", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "sourceAnchors", 0), "../docs/architecture/orchestrator.md:1-2"), AdrReadinessCommand.Validate)
		}},
		{"adr absolute source anchor", absoluteSourceAnchor},
		{"adr source anchor bounds", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "sourceAnchors", 0), "README.md:999999-999999"), AdrReadinessCommand.Validate)
		}},
		{"adr evidence location bounds", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("entries", 0, "evidenceLocations", 0), "README.md:999999-999999"), AdrReadinessCommand.Validate)
		}},
		{"adr invalid closure reference", adrInvalidClosureReference},
		{"adr whitespace source anchor", whitespaceSourceAnchor},
		{"adr symlink escape anchor", symlinkEscapeAnchor},
		{"adr symlinked workspace Goal", symlinkedWorkspaceGoal},
		{"adr canonical lane substitution", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("canonicalOwnerLanes", 0), "other"), AdrReadinessCommand.Validate)
		}},
		{"adr normalization provenance", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("normalizationEvidence"), "README.md:1-1"), AdrReadinessCommand.Validate)
		}},
		{"adr normalization anchor bounds", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("normalizationEvidence"), "docs/architecture/orchestrator.md:999-999"), AdrReadinessCommand.Validate)
		}},
		{"adr canonical normalization range", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("normalizationEvidence"), "docs/architecture/orchestrator.md:83-104"), AdrReadinessCommand.Validate)
		}},
		{"adr open-input provenance", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("openInputs", "source"), "README.md:1-1"), AdrReadinessCommand.Validate)
		}},
		{"packet alias unknown target", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("controllingInputAliases", "storage-slo", 0), "unknown-input"), OwnerDecisionCommand.Validate)
		}},
		{"packet alias duplicate expansion", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("controllingInputAliases", "storage-slo", 1), "storage-minimum-iops-per-member"), OwnerDecisionCommand.Validate)
		}},
		{"packet empty alias", func() {
			assertInvalidDocument(addAliasDocument("", []string{"regional-rpo"}), OwnerDecisionCommand.Validate)
		}},
		{"packet self alias", func() {
			assertInvalidDocument(addAliasDocument("self-alias", []string{"self-alias"}), OwnerDecisionCommand.Validate)
		}},
		{"packet indirect alias cycle", func() {
			assertInvalidDocument(addAliasesDocument(aliasPair{"alias-a", []string{"alias-b"}}, aliasPair{"alias-b", []string{"alias-a"}}), OwnerDecisionCommand.Validate)
		}},
		{"packet alias atomic collision", func() {
			assertInvalidDocument(addAliasDocument("regional-rpo", []string{"regional-rpo"}), OwnerDecisionCommand.Validate)
		}},
		{"packet ownership record missing", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("openInputOwnershipRegister", "records", 0)), OwnerDecisionCommand.Validate)
		}},
		{"packet ownership status", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("openInputOwnershipRegister", "records", 0, "assignmentStatus"), "pending"), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection missing id", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "id")), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection missing selection", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "selection")), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection schema", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "readinessStage")), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection missing contract freeze", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "requiredBeforeContractFreeze")), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection malformed readiness stage", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "readinessStage"), "deployment-qualification"), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection malformed contract freeze", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "requiredBeforeContractFreeze"), "false"), OwnerDecisionCommand.Validate)
		}},
		{"packet later selection nonobject member", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0), "invalid"), OwnerDecisionCommand.Validate)
		}},
		{"packet policy anchors", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("atomicPolicyRecords", 0, "sourceAnchors"), []string{}), OwnerDecisionCommand.Validate)
		}},
		{"packet policy canonical anchor substitution", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("atomicPolicyRecords", 0, "sourceAnchors", 0), "docs/architecture/orchestrator.md:89-98"), OwnerDecisionCommand.Validate)
		}},
		{"packet accepted register anchors", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("acceptedDecisionRegister", "sourceAnchors"), []string{}), OwnerDecisionCommand.Validate)
		}},
		{"packet accepted canonical anchor substitution", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("acceptedDecisionRegister", "sourceAnchors", 0), "docs/architecture/orchestrator.md:89-98"), OwnerDecisionCommand.Validate)
		}},
		{"packet open input anchors", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("openInputRegister", "sourceAnchors"), []string{}), OwnerDecisionCommand.Validate)
		}},
		{"packet open input in-bounds anchor substitution", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("openInputRegister", "sourceAnchors", 0), "docs/architecture/orchestrator.md:1-1"), OwnerDecisionCommand.Validate)
		}},
		{"packet invariant gap deletion", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("unvalidatedInvariantGaps", 0)), OwnerDecisionCommand.Validate)
		}},
		{"packet invariant gap status", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("unvalidatedInvariantGaps", 0, "status"), "accepted"), OwnerDecisionCommand.Validate)
		}},
		{"packet invariant gap review prerequisite", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("unvalidatedInvariantGaps", 0, "prerequisite"), "review complete"), OwnerDecisionCommand.Validate)
		}},
		{"packet invariant gap source", func() {
			assertInvalidDocument(mutateDocument("docs/adr/readiness-index.yaml", testSegments("openInputs", "unvalidatedInvariantGap"), "docs/decisions/owner-decision-packet.json:124-126"), AdrReadinessCommand.Validate)
		}},
		{"owner baseline", func() {
			assertValidErrors(OwnerDecisionCommand.Validate(mustDocument(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json"))))
		}},
		{"owner decision drift", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("questions", 0, "answer"), "B"), OwnerDecisionCommand.Validate)
		}},
		{"owner invalid option", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("questions", 1, "answer"), "C"), OwnerDecisionCommand.Validate)
		}},
		{"owner invalid unit", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("inputs", 2, "unit"), "USD/month"), OwnerDecisionCommand.Validate)
		}},
		{"owner missing input impacts", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("inputs", 0, "impactedAdrs")), OwnerDecisionCommand.Validate)
		}},
		{"owner arbitrary input gate", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("inputs", 0, "impactedGates", 0), "L9"), OwnerDecisionCommand.Validate)
		}},
		{"owner malformed input validation", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("inputs", 0, "validation", "minimum"), "1"), OwnerDecisionCommand.Validate)
		}},
		{"owner question impact substitution", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("questions", 0, "impactedAdrs", 0), 24), OwnerDecisionCommand.Validate)
		}},
		{"owner later selection gate substitution", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "impactedGates", 0), "L5"), OwnerDecisionCommand.Validate)
		}},
		{"owner later selection default", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("laterImplementationSelections", 0, "selection"), "cosign"), OwnerDecisionCommand.Validate)
		}},
		{"owner missing question", func() {
			assertInvalidDocument(deleteDocumentValue("docs/decisions/owner-decision-packet.json", testSegments("questions", 4)), OwnerDecisionCommand.Validate)
		}},
		{"owner semantic drift", func() {
			assertInvalidDocument(mutateDocument("docs/decisions/owner-decision-packet.json", testSegments("questions", 0, "question"), "drift"), OwnerDecisionCommand.Validate)
		}},
		{"phase 0 evidence baseline", assertPhase0Valid},
		{"phase 0 invalid schema version", func() {
			assertInvalidDocument(mutateDocument("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", testSegments("schema_version"), 2), Phase0EvidenceCommand.ValidateInventory)
		}},
		{"phase 0 scalar descriptor", func() {
			assertInvalidDocument(mutateDocument("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", testSegments("repositories", 0, "descriptors", 0), "invalid"), Phase0EvidenceCommand.ValidateInventory)
		}},
		{"phase 0 malformed descriptor hash", func() {
			assertInvalidDocument(mutateDocument("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", testSegments("repositories", 0, "descriptors", 0, "source_sha256"), strings.Repeat("A", 64)), Phase0EvidenceCommand.ValidateInventory)
		}},
		{"phase 0 unavailable repository commit", func() {
			assertInvalidDocument(mutateDocument("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", testSegments("repositories", 0, "source_commit"), strings.Repeat("0", 40)), Phase0EvidenceCommand.ValidateInventory)
		}},
		{"workaround illicit closure", func() {
			assertInvalidDocument(mutateDocument("docs/retirement/workaround-ledger.yaml", testSegments("entries", 0, "status"), "retired"), Phase0EvidenceCommand.ValidateWorkaroundLedger)
		}},
		{"workaround identified receipt", workaroundIdentifiedReceipt},
		{"workaround missing closure key", workaroundMissingClosureKey},
		{"workaround extra closure key", workaroundExtraClosureKey},
		{"workaround unavailable closure receipt", func() {
			assertInvalidClosureReceipt(strings.Repeat("0", 40), strings.Repeat("a", 64))
		}},
		{"workaround mismatched closure receipt", func() {
			assertInvalidClosureReceipt("9653c0a337fb252602899b594b315639d32c8b20", strings.Repeat("a", 64))
		}},
		{"workaround unbound real closure receipt", workaroundUnboundRealClosureReceipt},
		{"workaround unrelated real closure receipt", workaroundUnrelatedRealClosureReceipt},
		{"workaround archival source mismatch", func() {
			assertInvalidDocument(mutateDocument("docs/retirement/workaround-ledger.yaml", testSegments("archivalSourceEvidence", "WRK-001", 0, "sha256"), strings.Repeat("a", 64)), Phase0EvidenceCommand.ValidateWorkaroundLedger)
		}},
		{"workaround missing archival source evidence", workaroundMissingArchivalSourceEvidence},
		{"workaround archival anchor drift", func() {
			assertInvalidDocument(mutateDocument("docs/retirement/workaround-ledger.yaml", testSegments("entries", 0, "source_anchors", 0), "archive:TerraScale.Infrastructure/AGENTS.md:1"), Phase0EvidenceCommand.ValidateWorkaroundLedger)
		}},
		{"workaround malformed archival anchor", func() {
			assertInvalidDocument(mutateDocument("docs/retirement/workaround-ledger.yaml", testSegments("entries", 0, "source_anchors", 0), "archive:unknown/AGENTS.md:1"), Phase0EvidenceCommand.ValidateWorkaroundLedger)
		}},
		{"workaround archival receipt swap", workaroundArchivalReceiptSwap},
		{"workaround archival receipt commit retarget", workaroundArchivalReceiptCommitRetarget},
		{"workaround archival anchor line bounds", workaroundArchivalAnchorLineBounds},
		{"workaround archival oversized anchor range end", workaroundArchivalOversizedAnchorRangeEnd},
		{"workaround archival anchor and receipt retarget", workaroundArchivalAnchorAndReceiptRetarget},
		{"git bytes preserve non UTF-8 blob", gitBytesPreserveNonUtf8Blob},
		{"no python sources", noPythonSources},
		{"CI result manifest", testCiResultManifest},
		{"development evidence fixed topology authorization", developmentEvidenceTopology},
		{"development evidence bounded execution", developmentEvidenceBounds},
		{"development bounded process observation", developmentBoundedProcessObservation},
		{"development validation lease", developmentValidationLease},
		{"development validation lease recovers stale holder", developmentValidationLeaseRecoversStaleHolder},
		{"workspace topology lease", developmentWorkspaceTopologyLease},
	}
}

func testSegments(segments ...any) []any {
	return segments
}

func assertPhase0Valid() {
	assertValidErrors(Phase0EvidenceCommand.ValidateInventory(
		mustDocument(ToolingSupport.ReadObject("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml"))))
	assertValidErrors(Phase0EvidenceCommand.ValidateWorkaroundLedger(
		mustDocument(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"))))
}

func adrExecutableDependencyCycle() {
	document := cloneToolingDocument("docs/adr/readiness-index.yaml")
	entries := objectArray(document.Get("entries"))
	entries.Get(0).(*JsonObject).Set("executableDependencies", intJsonArray(2))
	entries.Get(1).(*JsonObject).Set("executableDependencies", intJsonArray(1))
	assertInvalidDocument(document, AdrReadinessCommand.Validate)
}

func adrInvalidClosureReference() {
	document := cloneToolingDocument("docs/adr/readiness-index.yaml")
	objectArray(document.Get("entries")).Get(0).(*JsonObject).Set("closureEvidence", intJsonArray(99))
	assertInvalidDocument(document, AdrReadinessCommand.Validate)
}

func workaroundIdentifiedReceipt() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	closure := testObjectWith("repository", "TerraScale.Infrastructure")
	document.Get("closureEvidence").(*JsonObject).Set("WRK-001", closure)
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundMissingClosureKey() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	document.Get("closureEvidence").(*JsonObject).Remove("WRK-022")
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundExtraClosureKey() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	document.Get("closureEvidence").(*JsonObject).Set("WRK-023", nil)
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func assertInvalidClosureReceipt(commit string, hash string) {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	objectArray(document.Get("entries")).Get(0).(*JsonObject).Set("status", "retired")
	closure := newJsonObject()
	closure.Set("repository", "TerraBase")
	closure.Set("commit", commit)
	closure.Set("path", "TerraBase.slnx")
	closure.Set("sha256", hash)
	closure.Set("gate", "L1")
	closure.Set("timestamp", "2026-08-05T00:00:00Z")
	closure.Set("authority", "test")
	document.Get("closureEvidence").(*JsonObject).Set("WRK-001", closure)
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundUnboundRealClosureReceipt() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	unrelated := objectArray(document.Get("archivalSourceEvidence").(*JsonObject).Get("WRK-002")).Get(0).(*JsonObject)
	entries := objectArray(document.Get("entries"))
	closure := newJsonObject()
	closure.Set("workaround_id", "WRK-002")
	closure.Set("native_replacement_gate", mustDeepClone(entries.Get(1).(*JsonObject).Get("native_replacement_gate")))
	closure.Set("removal_assertion", "The retired implementation and its authority were removed.")
	closure.Set("approved_cleanup_authority", "approved test authority")
	closure.Set("repository", mustDeepClone(unrelated.Get("repository")))
	closure.Set("commit", mustDeepClone(unrelated.Get("commit")))
	closure.Set("path", mustDeepClone(unrelated.Get("path")))
	closure.Set("sha256", mustDeepClone(unrelated.Get("sha256")))
	closure.Set("timestamp", "2026-08-05T00:00:00Z")
	entries.Get(0).(*JsonObject).Set("status", "retired")
	document.Get("closureEvidence").(*JsonObject).Set("WRK-001", closure)
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundUnrelatedRealClosureReceipt() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	unrelated := objectArray(document.Get("archivalSourceEvidence").(*JsonObject).Get("WRK-002")).Get(0).(*JsonObject)
	entries := objectArray(document.Get("entries"))
	paths := &JsonArray{}
	paths.Append("safe/path")
	closure := newJsonObject()
	closure.Set("workaround_id", "WRK-001")
	closure.Set("native_replacement_gate", mustDeepClone(entries.Get(0).(*JsonObject).Get("native_replacement_gate")))
	closure.Set("removal_assertion", "The retired implementation and its authority were removed.")
	closure.Set("approved_cleanup_authority", "approved test authority")
	closure.Set("affected_safe_paths", paths)
	closure.Set("approval_identity", "test approver")
	closure.Set("repository", mustDeepClone(unrelated.Get("repository")))
	closure.Set("commit", mustDeepClone(unrelated.Get("commit")))
	closure.Set("path", mustDeepClone(unrelated.Get("path")))
	closure.Set("sha256", mustDeepClone(unrelated.Get("sha256")))
	closure.Set("timestamp", "2026-08-05T00:00:00Z")
	entries.Get(0).(*JsonObject).Set("status", "retired")
	document.Get("closureEvidence").(*JsonObject).Set("WRK-001", closure)
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundMissingArchivalSourceEvidence() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	entries := objectArray(document.Get("entries"))
	entries.Get(0).(*JsonObject).Set("source_anchors", &JsonArray{})
	document.Get("archivalSourceEvidence").(*JsonObject).Set("WRK-001", &JsonArray{})
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundArchivalReceiptSwap() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	receipt := objectArray(document.Get("archivalSourceEvidence").(*JsonObject).Get("WRK-001")).Get(0).(*JsonObject)
	receipt.Set("path", "src/TerraScale.Infrastructure/Program.cs")
	receipt.Set("sha256", "f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4")
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundArchivalReceiptCommitRetarget() {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	receipt := objectArray(document.Get("archivalSourceEvidence").(*JsonObject).Get("WRK-001")).Get(0).(*JsonObject)
	receipt.Set("commit", "3bfdb4ee0124fbcce43e7db57cf00045f374fbcb")
	receipt.Set("sha256", "f6b47e51a041bda7633dcc5a8f24e840604c1c85c98c8b742289c1c32868c462")
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func retargetArchiveAnchor(anchor string, anchorSha256 string) {
	document := cloneToolingDocument("docs/retirement/workaround-ledger.yaml")
	objectArray(document.Get("entries")).Get(0).(*JsonObject).Get("source_anchors").(*JsonArray).Set(0, anchor)
	receipt := objectArray(document.Get("archivalSourceEvidence").(*JsonObject).Get("WRK-001")).Get(0).(*JsonObject)
	receipt.Set("anchor", anchor)
	if anchorSha256 != "" {
		receipt.Set("anchor_sha256", anchorSha256)
	}
	assertInvalidDocument(document, Phase0EvidenceCommand.ValidateWorkaroundLedger)
}

func workaroundArchivalAnchorLineBounds() {
	retargetArchiveAnchor("archive:TerraScale.Infrastructure/AGENTS.md:999999", "")
}

func workaroundArchivalOversizedAnchorRangeEnd() {
	retargetArchiveAnchor("archive:TerraScale.Infrastructure/AGENTS.md:66-2147483648", "")
}

func workaroundArchivalAnchorAndReceiptRetarget() {
	retargetArchiveAnchor("archive:TerraScale.Infrastructure/AGENTS.md:65", "f288db607b8e7372ebff2a7dd7d8e39700ba65451d1445b2063fa300177ca7ab")
}

func gitBytesPreserveNonUtf8Blob() {
	root := filepath.Join(os.TempDir(), "tooling-git-bytes-"+randomTestToken())
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "blob.bin")
	expected := []byte{0xff, 0x00, 0x80, 0x0a}
	if err := os.WriteFile(path, expected, 0o644); err != nil {
		panic(err)
	}
	result, err := ToolingSupport.RunProcess("git", []string{"init", "--quiet", root}, "", 0)
	if err != nil {
		panic(err)
	}
	assertEqualValue(0, result.ExitCode)
	hash := strings.TrimSpace(mustGit(ToolingSupport.Git(root, "hash-object", "-w", path)))
	actual := mustBytes(ToolingSupport.GitBytes(root, "cat-file", "blob", hash))
	if !bytes.Equal(actual, expected) {
		panic(errors.New("git raw bytes changed a non-UTF-8 blob"))
	}
	assertEqualValue(ToolingSupport.Sha256Bytes(expected), ToolingSupport.Sha256Bytes(actual))
}

func noPythonSources() {
	var python []string
	_ = filepath.WalkDir(ToolingSupport.Root(), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			if name == "bin" || name == "obj" || name == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, ".py") {
			python = append(python, path)
		}
		return nil
	})
	if len(python) != 0 {
		panic(fmt.Errorf("Python sources remain: %s", strings.Join(python, ",")))
	}
}

func absoluteSourceAnchor() {
	anchors := &JsonArray{}
	anchors.Append("/tmp/tooling-anchor.md:1-1")
	errors := Validation.ValidateLocalAnchors(anchors, "source", nil)
	assertInvalidErrors(errors)
}

func whitespaceSourceAnchor() {
	name := "tooling-anchor-whitespace-" + randomTestToken() + ".md"
	path := filepath.Join(ToolingSupport.Root(), name)
	if err := os.WriteFile(path, []byte(" \n\t\n"), 0o644); err != nil {
		panic(err)
	}
	defer os.Remove(path)
	anchors := &JsonArray{}
	anchors.Append(name + ":1-2")
	errors := Validation.ValidateLocalAnchors(anchors, "source", nil)
	assertInvalidErrors(errors)
}

func symlinkEscapeAnchor() {
	target := filepath.Join(os.TempDir(), "tooling-symlink-target-"+randomTestToken())
	linkName := "tooling-symlink-escape-" + randomTestToken()
	link := filepath.Join(ToolingSupport.Root(), linkName)
	if err := os.MkdirAll(target, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(target, "evidence.md"), []byte("outside repository"), 0o644); err != nil {
		panic(err)
	}
	defer func() {
		os.Remove(link)
		os.RemoveAll(target)
	}()
	if err := os.Symlink(target, link); err != nil {
		fmt.Println("SKIP adr symlink escape anchor: symbolic links are unavailable on this platform")
		return
	}
	if !isSymbolicLink(link) {
		panic(errors.New("symbolic link creation did not produce a symbolic link"))
	}
	anchors := &JsonArray{}
	anchors.Append(linkName + "/evidence.md:1-1")
	anchorErrors := Validation.ValidateLocalAnchors(anchors, "symlink", nil)
	for _, validationError := range anchorErrors {
		if strings.Contains(validationError, "escapes the repository") {
			return
		}
	}
	panic(errors.New("validator accepted a symlink escape anchor"))
}

func symlinkedWorkspaceGoal() {
	workspace := filepath.Join(os.TempDir(), "tooling-workspace-"+randomTestToken())
	root := filepath.Join(workspace, "repository")
	target := filepath.Join(os.TempDir(), "tooling-goal-target-"+randomTestToken()+".md")
	goal := filepath.Join(workspace, "GOAL.md")
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(target, []byte("outside workspace"), 0o644); err != nil {
		panic(err)
	}
	defer func() {
		os.Remove(goal)
		os.RemoveAll(workspace)
		os.Remove(target)
	}()
	if err := os.Symlink(target, goal); err != nil {
		fmt.Println("SKIP adr symlinked workspace Goal: symbolic links are unavailable on this platform")
		return
	}
	anchors := &JsonArray{}
	anchors.Append("../GOAL.md:1-1")
	goalErrors := validationLocalAnchors(anchors, "Goal", nil, root)
	for _, validationError := range goalErrors {
		if strings.Contains(validationError, "escapes the repository") {
			return
		}
	}
	panic(errors.New("validator accepted a symlinked workspace Goal"))
}

func testTrxContent(first string, second string, failed int, notExecuted int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Results>
    <UnitTestResult executionId="11111111-1111-1111-1111-111111111111" testName="first" outcome="%s" />
    <UnitTestResult executionId="22222222-2222-2222-2222-222222222222" testName="second" outcome="%s" />
  </Results>
  <ResultSummary outcome="Completed">
    <Counters total="2" executed="%d" passed="1" failed="%d" error="0"
      timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0"
      notExecuted="%d" disconnected="0" warning="0" completed="0" inProgress="0" pending="0" />
  </ResultSummary>
</TestRun>
`, first, second, 2-notExecuted, failed, notExecuted)
}

func testCiResultManifest() {
	root := filepath.Join(os.TempDir(), "ci-result-manifest-"+randomTestToken())
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	trx := filepath.Join(root, "tests.trx")
	invalid := filepath.Join(root, "invalid.trx")
	output := filepath.Join(root, "terrascale-ci-result-v2.json")
	if err := os.WriteFile(trx, []byte(testTrxContent("Passed", "NotExecuted", 0, 1)), 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(invalid, []byte(testTrxContent("Passed", "Failed", 1, 0)), 0o644); err != nil {
		panic(err)
	}
	digest := strings.Repeat("a", 64)

	exitCode, err := CiResultManifestCommand.Run([]string{
		"--job", "pipeline:job", "--plan-digest", digest, "--trx", trx,
		"--artifact", "TerraScale/Orchestrator|LinuxX64|linux-x64|bin/app", "--output", output})
	if err != nil {
		panic(err)
	}
	assertEqualValue(0, exitCode)
	content, err := os.ReadFile(output)
	if err != nil {
		panic(err)
	}
	node, err := parseJSONNode(content)
	if err != nil || node == nil {
		panic(errors.New("ci result manifest output is not valid JSON"))
	}
	document := node.(*JsonObject)
	assertEqualValue(2, testInt(document, "schemaVersion"))
	assertEqualValue("pipeline:job", testString(document, "job"))
	assertEqualValue(digest, testString(document, "planDigest"))
	assertEqualValue(true, testBool(document, "succeeded"))
	assertEqualValue(1, testInt(document, "requiredTestSkips"))
	artifacts := objectArray(document.Get("artifacts"))
	artifact := artifacts.Get(0).(*JsonObject)
	assertEqualValue("TerraScale/Orchestrator", testString(artifact, "artifact"))
	assertEqualValue("LinuxX64", testString(artifact, "architecture"))
	assertEqualValue("linux-x64", testString(artifact, "path"))
	entrypoints := objectArray(artifact.Get("entrypoints"))
	assertEqualValue("bin/app", testString(entrypoints.Get(0), "entrypoint"))
	if _, _, err := CiResultManifestCommand.ReadTrx(invalid); !isToolValidationException(err) {
		panic(errors.New("expected ToolValidationException"))
	}
	if _, err := CiResultManifestCommand.Parse([]string{
		"--job", "pipeline:job", "--plan-digest", strings.Repeat("A", 64), "--output", output}); !isToolValidationException(err) {
		panic(errors.New("expected ToolValidationException"))
	}
	if _, err := CiResultManifestCommand.Parse([]string{
		"--job", "pipeline:job", "--plan-digest", digest,
		"--artifact", "artifact|LinuxX64|linux|app",
		"--artifact", "artifact|LinuxArm64|linux/arm64|app", "--output", output}); !isToolValidationException(err) {
		panic(errors.New("expected ToolValidationException"))
	}
}

func developmentEvidenceTopology() {
	if _, err := DevelopmentEvidenceCommand.Parse([]string{"--output", "/tmp/evidence.json"}); err != nil {
		panic(err)
	}
	if _, err := DevelopmentEvidenceCommand.Parse([]string{
		"--output", "/tmp/evidence.json", "--profile", "quick"}); !isToolValidationException(err) {
		panic(errors.New("expected ToolValidationException"))
	}
	if _, err := DevelopmentEvidenceCommand.Parse([]string{
		"--output", "/tmp/evidence.json", "--profile", "control"}); !isToolValidationException(err) {
		panic(errors.New("expected ToolValidationException"))
	}
}

func developmentEvidenceBounds() {
	assertEqualValue(1, DevelopmentMaximumParallelTestModules)
	assertEqualValue(2, DevelopmentEvidenceSchemaVersion)
	assertEqualValue(4, DevelopmentMaximumParallelTests)
	assertEqualValue(5, len(DevelopmentTestModules))
	assertEqualValue(5, DevelopmentDefaultTestModuleTimeoutMinutes)
	assertEqualValue(15, DevelopmentIntegrationTestModuleTimeoutMinutes)
	for _, module := range DevelopmentTestModules[:4] {
		assertEqualValue(DevelopmentDefaultTestModuleTimeoutMinutes, module.TimeoutMinutes)
	}
	assertEqualValue(DevelopmentIntegrationTestModuleTimeoutMinutes,
		DevelopmentTestModules[len(DevelopmentTestModules)-1].TimeoutMinutes)
	assertEqualValue(int64(24)*1024*1024*1024, DevelopmentAggregateMemoryLimitBytes)
	assertEqualValue(int64(20)*1024*1024*1024, DevelopmentExecutionMemoryLimitBytes)
	assertEqualValue(int64(4)*1024*1024*1024, DevelopmentReservedHeadroomBytes)
	total, err := DevelopmentEvidenceCommand.ParseTestTotal("sample", "total: 46\n")
	if err != nil {
		panic(err)
	}
	assertEqualValue(46, total)
}

func developmentValidationLease() {
	scope := "tooling-test-" + randomTestToken()
	lease, err := AcquireLocalValidationLease(scope)
	if err != nil {
		panic(err)
	}
	defer lease.Close()
	if _, err := AcquireLocalValidationLease(scope); err == nil {
		panic(errors.New("expected an error while the validation lease is held"))
	}
}

func developmentValidationLeaseRecoversStaleHolder() {
	scope := "tooling-test-" + randomTestToken()
	path := filepath.Join(os.TempDir(), fmt.Sprintf("terrascale-orchestrator-validation-%s.lock", scope))
	if err := os.WriteFile(path, []byte("999999999"), 0o644); err != nil {
		panic(err)
	}
	lease, err := AcquireLocalValidationLease(scope)
	if err != nil {
		panic(err)
	}
	defer lease.Close()
}

func developmentBoundedProcessObservation() {
	// The C# suite observed `dotnet --version`; the Go toolchain equivalent is
	// `go version`.
	result, err := BoundedProcessRunner.Run(
		"go",
		[]string{"version"},
		ToolingSupport.Root(),
		30*time.Second,
		256*1024*1024,
		4)
	if err != nil {
		panic(err)
	}
	assertEqualValue(0, result.ExitCode)
	if result.Observation.PeakMemoryBytes <= 0 || result.Observation.PeakProcessCount <= 0 {
		panic(errors.New("bounded process observation did not capture resource use"))
	}
}

type leaseHolderProcess struct {
	command    *exec.Cmd
	stdin      io.WriteCloser
	stdoutLine chan string
	stderrDone chan string
}

func developmentWorkspaceTopologyLease() {
	previousNamespace, hadPrevious := os.LookupEnv(workspaceTopologyNamespaceVariable)
	leaseNamespace := "tooling-" + randomTestToken()
	defer func() {
		if hadPrevious {
			os.Setenv(workspaceTopologyNamespaceVariable, previousNamespace)
		} else {
			os.Unsetenv(workspaceTopologyNamespaceVariable)
		}
	}()

	os.Unsetenv(workspaceTopologyNamespaceVariable)
	name, err := workspaceTopologyMutexName()
	if err != nil {
		panic(err)
	}
	assertEqualValue("terrascale-workspace-topology-"+envUserName(), name)
	os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace)
	name, err = workspaceTopologyMutexName()
	if err != nil {
		panic(err)
	}
	assertEqualValue("terrascale-workspace-topology-"+leaseNamespace, name)
	os.Setenv(workspaceTopologyNamespaceVariable, "invalid namespace")
	if _, err := workspaceTopologyMutexName(); err == nil {
		panic(errors.New("expected an invalid namespace error"))
	}
	os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace)

	first, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	func() {
		defer func() {
			if closeErr := first.Close(); closeErr != nil {
				panic(closeErr)
			}
		}()
		_, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 50*time.Millisecond)
		if err == nil || err.Error() != "Timed out acquiring the workspace topology lease." {
			panic(fmt.Errorf("expected a lease timeout, observed %v", err))
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancelled := make(chan error, 1)
		go func() {
			_, cancelErr := AcquireWorkspaceTopologyLease(ctx, "development-lab", 2*time.Second)
			cancelled <- cancelErr
		}()
		cancel()
		if cancelErr := <-cancelled; !errors.Is(cancelErr, context.Canceled) {
			panic(fmt.Errorf("expected context cancellation, observed %v", cancelErr))
		}
	}()

	second, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if err := second.Close(); err != nil {
		panic(err)
	}

	holder := startWorkspaceTopologyLeaseHolder(leaseNamespace, false, false)
	tryReadHolderReady(holder)
	if _, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 50*time.Millisecond); err == nil {
		panic(errors.New("The child process did not hold the workspace topology lease."))
	} else if err.Error() != "Timed out acquiring the workspace topology lease." {
		panic(err)
	}
	stopWorkspaceTopologyLeaseHolder(holder, 5*time.Second)
	assertEqualValue(0, holder.command.ProcessState.ExitCode())

	hostile := startWorkspaceTopologyLeaseHolder(leaseNamespace, true, true)
	tryReadHolderReady(hostile)
	stopWorkspaceTopologyLeaseHolder(hostile, 50*time.Millisecond)
	assertEqualValue(256, len(readHolderBoundedStderr(hostile)))

	afterChildExit, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if err := afterChildExit.Close(); err != nil {
		panic(err)
	}
}

func startWorkspaceTopologyLeaseHolder(leaseNamespace string, noisyStderr bool, ignoreStandardInput bool) *leaseHolderProcess {
	processPath, err := os.Executable()
	if err != nil {
		panic(errors.New("The tooling test host path is unavailable."))
	}
	arguments := []string{"workspace-topology-lease-holder", "--namespace", leaseNamespace}
	if noisyStderr {
		arguments = append(arguments, "--noisy-stderr", "--ignore-stdin")
	}
	command := exec.Command(processPath, arguments...)
	command.Dir = ToolingSupport.Root()
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		panic(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		panic(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		panic(err)
	}
	if err := command.Start(); err != nil {
		panic(err)
	}
	holder := &leaseHolderProcess{
		command:    command,
		stdin:      stdin,
		stdoutLine: make(chan string, 1),
		stderrDone: make(chan string, 1),
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			holder.stdoutLine <- scanner.Text()
		} else {
			holder.stdoutLine <- ""
		}
	}()
	go func() { holder.stderrDone <- captureBoundedStderr(stderr, 256) }()
	return holder
}

func tryReadHolderReady(holder *leaseHolderProcess) string {
	select {
	case text := <-holder.stdoutLine:
		if text == "" {
			panic(errors.New("The workspace topology lease holder exited before admission."))
		}
		return text
	case <-time.After(5 * time.Second):
		stopWorkspaceTopologyLeaseHolder(holder, 5*time.Second)
		exitCode := -1
		if holder.command.ProcessState != nil {
			exitCode = holder.command.ProcessState.ExitCode()
		}
		panic(fmt.Errorf("The workspace topology lease holder did not become ready (exit %d): %s",
			exitCode, readHolderBoundedStderr(holder)))
	}
}

func stopWorkspaceTopologyLeaseHolder(holder *leaseHolderProcess, gracefulTimeout time.Duration) {
	if holder.command.ProcessState != nil {
		return
	}
	_ = holder.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- holder.command.Wait() }()
	select {
	case <-done:
	case <-time.After(gracefulTimeout):
		killProcessTree(holder.command.Process.Pid)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			panic(fmt.Errorf("The workspace topology lease holder did not exit after termination: %s",
				readHolderBoundedStderr(holder)))
		}
	}
}

func captureBoundedStderr(reader io.Reader, maximumLength int) string {
	captured := make([]byte, 0, maximumLength)
	buffer := make([]byte, maximumLength)
	for {
		read, err := reader.Read(buffer)
		if read > 0 && len(captured) < maximumLength {
			remaining := maximumLength - len(captured)
			amount := read
			if remaining < amount {
				amount = remaining
			}
			captured = append(captured, buffer[:amount]...)
		}
		if err != nil {
			break
		}
	}
	return string(captured)
}

func readHolderBoundedStderr(holder *leaseHolderProcess) string {
	select {
	case text := <-holder.stderrDone:
		return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", " "), "\n", " "))
	case <-time.After(1 * time.Second):
		return "stderr unavailable"
	}
}

// Document mutation helpers mirroring the C# Mutate/Delete/Set/Resolve.

type aliasPair struct {
	Alias  string
	Values []string
}

func mutateDocument(path string, segments []any, value any) *JsonObject {
	document := cloneToolingDocument(path)
	setDocumentValue(document, segments, value)
	return document
}

func deleteDocumentValue(path string, segments []any) *JsonObject {
	document := cloneToolingDocument(path)
	parent := resolveDocumentValue(document, segments[:len(segments)-1])
	last := segments[len(segments)-1]
	switch target := parent.(type) {
	case *JsonObject:
		target.Remove(last.(string))
	case *JsonArray:
		target.RemoveAt(last.(int))
	}
	return document
}

func addAliasDocument(alias string, values []string) *JsonObject {
	return addAliasesDocument(aliasPair{alias, values})
}

func addAliasesDocument(aliases ...aliasPair) *JsonObject {
	document := cloneToolingDocument("docs/decisions/owner-decision-packet.json")
	target := document.Get("controllingInputAliases").(*JsonObject)
	for _, pair := range aliases {
		values := &JsonArray{}
		for _, value := range pair.Values {
			values.Append(value)
		}
		target.Set(pair.Alias, values)
	}
	return document
}

func setDocumentValue(document *JsonObject, segments []any, value any) {
	parent := resolveDocumentValue(document, segments[:len(segments)-1])
	last := segments[len(segments)-1]
	switch target := parent.(type) {
	case *JsonObject:
		target.Set(last.(string), value)
	case *JsonArray:
		target.Set(last.(int), value)
	}
}

func resolveDocumentValue(current any, segments []any) any {
	for _, segment := range segments {
		switch key := segment.(type) {
		case string:
			current = current.(*JsonObject).Get(key)
		case int:
			current = current.(*JsonArray).Get(key)
		}
	}
	return current
}

func cloneToolingDocument(path string) *JsonObject {
	return mustDocument(ToolingSupport.ReadObject(path)).deepClone()
}

func (o *JsonObject) deepClone() *JsonObject {
	return mustDocument2(deepCloneJSON(o))
}

// Assertion helpers mirroring the C# Assert* set.

func assertValidErrors(validationErrors []string) {
	if len(validationErrors) != 0 {
		panic(errors.New(strings.Join(validationErrors, "; ")))
	}
}

func assertInvalidErrors(validationErrors []string) {
	if len(validationErrors) == 0 {
		panic(errors.New("validator accepted an invalid document"))
	}
}

func assertInvalidDocument(document *JsonObject, validate func(*JsonObject) []string) {
	assertInvalidErrors(validate(document))
}

func assertEqualValue(expected any, actual any) {
	if expected == actual {
		return
	}
	panic(fmt.Errorf("expected %v, observed %v", expected, actual))
}

// Scalar accessors for parsed output documents.

func testInt(object *JsonObject, key string) int {
	value, ok := tryInt(object.Get(key))
	if !ok {
		panic(fmt.Errorf("%s is not an integer", key))
	}
	return value
}

func testString(node any, key string) string {
	value, ok := node.(string)
	if !ok {
		panic(fmt.Errorf("%s is not a string", key))
	}
	return value
}

func testBool(object *JsonObject, key string) bool {
	value, ok := tryBool(object.Get(key))
	if !ok {
		panic(fmt.Errorf("%s is not a boolean", key))
	}
	return value
}

func testObjectWith(key string, value string) *JsonObject {
	object := newJsonObject()
	object.Set(key, value)
	return object
}

func intJsonArray(values ...int) *JsonArray {
	array := &JsonArray{}
	for _, value := range values {
		array.Append(value)
	}
	return array
}

// must helpers turn (value, error) returns into the C# exception flow.

func mustDocument(object *JsonObject, err error) *JsonObject {
	if err != nil {
		panic(err)
	}
	return object
}

func mustDocument2(node any, err error) *JsonObject {
	if err != nil {
		panic(err)
	}
	object, ok := node.(*JsonObject)
	if !ok {
		panic(errors.New("expected a JSON object"))
	}
	return object
}

func mustDeepClone(node any) any {
	cloned, err := deepCloneJSON(node)
	if err != nil {
		panic(err)
	}
	return cloned
}

func mustGit(value string, err error) string {
	if err != nil {
		panic(err)
	}
	return value
}

func mustBytes(value []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}

func randomTestToken() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
