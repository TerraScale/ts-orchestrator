// Port of tools/TerraScale.Orchestrator.Tooling/TranslatedCommands.cs: the
// shared Validation helpers plus the phase0-evidence, adr-readiness, and
// owner-decisions command validators.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type validationStatic struct{}

// Validation mirrors the C# Validation static class.
var Validation = validationStatic{}

// JsonDocument mirrors Validation.JsonDocument.
func (validationStatic) JsonDocument(document *JsonObject, name string, requiredKeys ...string) []string {
	var errors []string
	for _, key := range requiredKeys {
		if !document.Has(key) {
			errors = append(errors, fmt.Sprintf("%s: missing key %s", name, key))
		}
	}
	return errors
}

// ValidateLocalAnchors mirrors Validation.ValidateLocalAnchors.
func (validationStatic) ValidateLocalAnchors(anchors *JsonArray, where string, errors []string) []string {
	return validationLocalAnchors(anchors, where, errors, ToolingSupport.Root())
}

func validationLocalAnchors(anchors *JsonArray, where string, errors []string, root string) []string {
	if anchors == nil {
		return append(errors, where+": expected anchor list")
	}
	for _, value := range anchors.items {
		anchor, isString := value.(string)
		if !isString || strings.TrimSpace(anchor) == "" {
			errors = append(errors, where+": anchor must be a non-empty string")
			continue
		}
		match := localAnchorPattern.FindStringSubmatch(anchor)
		relative := ""
		if match != nil {
			relative = match[1]
		}
		isWorkspaceGoal := relative == "../GOAL.md"
		invalid := match == nil || strings.Contains(anchor, "://") ||
			filepath.IsAbs(relative) || strings.Contains(relative, "\\") ||
			(!isWorkspaceGoal && hasInvalidAnchorSegment(relative))
		if invalid {
			errors = append(errors, fmt.Sprintf("%s: invalid local evidence anchor: %s", where, anchor))
			continue
		}

		workspaceGoal := filepath.Join(filepath.Dir(root), "GOAL.md")
		path := workspaceGoal
		if !isWorkspaceGoal {
			path = filepath.Join(root, relative)
		}
		if !fileExists(path) {
			errors = append(errors, fmt.Sprintf("%s: evidence target is missing: %s", where, anchor))
			continue
		}

		resolvedPath := resolveExistingPath(path)
		if isWorkspaceGoal {
			if isSymbolicLink(workspaceGoal) || resolvedPath != workspaceGoal {
				errors = append(errors, fmt.Sprintf("%s: evidence target escapes the repository: %s", where, anchor))
				continue
			}
		} else if !isWithinPath(resolvedPath, resolveExistingPath(root)) {
			errors = append(errors, fmt.Sprintf("%s: evidence target escapes the repository: %s", where, anchor))
			continue
		}

		lines := readFileLines(resolvedPath)
		start, startErr := strconv.Atoi(match[2])
		end, endErr := strconv.Atoi(match[3])
		if startErr != nil || endErr != nil {
			errors = append(errors, fmt.Sprintf("%s: evidence anchor is out of bounds: %s (file has %d lines)", where, anchor, len(lines)))
			continue
		}
		if end < start || end > len(lines) {
			errors = append(errors, fmt.Sprintf("%s: evidence anchor is out of bounds: %s (file has %d lines)", where, anchor, len(lines)))
		} else if !anyNonWhitespace(lines[start-1 : end]) {
			errors = append(errors, fmt.Sprintf("%s: evidence anchor contains no evidence: %s", where, anchor))
		}
	}
	return errors
}

var localAnchorPattern = regexp.MustCompile(`^([^:]+):([1-9][0-9]*)-([1-9][0-9]*)$`)

func hasInvalidAnchorSegment(relative string) bool {
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." {
			return true
		}
	}
	return false
}

// resolveExistingPath mirrors the C# segment-by-segment symlink resolver.
func resolveExistingPath(path string) string {
	fullPath := path
	if !filepath.IsAbs(fullPath) {
		if absolute, err := filepath.Abs(fullPath); err == nil {
			fullPath = absolute
		}
	}
	volume := filepath.VolumeName(fullPath)
	current := string(filepath.Separator)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	rest := fullPath[len(volume):]
	for _, segment := range strings.FieldsFunc(rest, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		current = filepath.Join(current, segment)
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			current = resolved
		}
	}
	return current
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isSymbolicLink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// readFileLines mirrors File.ReadAllLines (CR, LF, and CRLF line breaks, no
// trailing empty line).
func readFileLines(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	if normalized == "" {
		return nil
	}
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func anyNonWhitespace(lines []string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			return true
		}
	}
	return false
}

// tryParseDateOnly mirrors DateOnly.TryParse for the ISO-8601 invariant date
// formats used by the checked-in evidence documents.
func tryParseDateOnly(value string) bool {
	for _, layout := range []string{"2006-01-02", "2006/01/02", "01/02/2006"} {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}

// tryParseDateTimeOffset mirrors DateTimeOffset.TryParse for ISO-8601
// timestamps with an offset.
func tryParseDateTimeOffset(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

type phase0EvidenceCommand struct{}

// Phase0EvidenceCommand mirrors the C# static class.
var Phase0EvidenceCommand = phase0EvidenceCommand{}

var phase0Repositories = []string{
	"TerraBase", "TerraBase.Benchmark", "TerraScale.Deploy", "TerraScale.DotNet", "TerraScale.TypeScript",
	"TerraScale.Internals", "TerraScale.DevHost", "Terrascale.Documentation", "Terrascale.Landingpage",
	"TerraScale.Infrastructure",
}

var phase0WorkaroundFields = []string{
	"id", "status", "disposition", "source_anchors", "original_constraint", "retained_semantic_behavior",
	"native_replacement_requirement", "native_replacement_gate", "owner_workstream", "phase_removal_task",
	"regression_scenario", "real_boundary_needed", "recovery_rollback_boundary", "external_authority_dependency",
	"evidence_claim_status",
}

var phase0ClosureFields = []string{"workaround_id", "native_replacement_gate", "removal_assertion", "approved_cleanup_authority", "affected_safe_paths", "approval_identity", "repository", "commit", "path", "sha256", "timestamp"}

var phase0InventoryFields = []string{"repository", "branch", "source_commit", "checkout_state", "ownership", "descriptors"}

var phase0DescriptorFields = []string{"path", "type", "purpose", "classification", "production_relevance", "confidence", "source_sha256"}

var phase0ArchiveFields = []string{"repository", "commit", "path", "sha256", "anchor_sha256"}

var phase0ArchivalReceiptIdentities = map[string][]string{
	"WRK-001": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|AGENTS.md|08d99c7181085edc0678715ac7f3973577bbcbb8a7bc06214c7d9b9fa7d46bd5|archive:TerraScale.Infrastructure/AGENTS.md:66|5255536e3df2504021a4062ba63796e604b30e637c48b9995886cf6999854591", "TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/Program.cs|f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/Program.cs:13|14355c61e5cd5a2ab933ae49bb9fecfb1aad66b1c1d63755f47135c217c61b8a"},
	"WRK-002": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/clusters/production-gru/reconciliation.yaml|5471818590e70e54874e76593e0fbd251022d12ffed56e72574f5b18473b6205|archive:TerraScale.Infrastructure/gitops/clusters/production-gru/reconciliation.yaml:70|1597fd2d8689c55dd63efd4a920f3ccb7fa7d4d98e63c6ec09337de7e4b7da5a"},
	"WRK-003": {"TerraScale.Deploy|bd5ecec12efa857d098dfe12584c9a548eb3d06b|src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs|5d6a669fed73fcb7f1946057fc19708b5d1fae572c8efa329247827278b1327a|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs:959|7022c405edaa049877f7d1d305111dc17e8f13872fb6ba5e87c2a91380d0b914"},
	"WRK-004": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/controllers/flux-image-automation/production-gru/image-update-automation.yaml|17ad31816802f0276645546f3bfe3202304114b3e236c74bc10a378e11d31633|archive:TerraScale.Infrastructure/gitops/controllers/flux-image-automation/production-gru/image-update-automation.yaml:45|9d66be2cf5a9426a19d3b4df69caa8fc62c098a39da7d3416977fe01ee37f969"},
	"WRK-005": {"TerraScale.Deploy|bd5ecec12efa857d098dfe12584c9a548eb3d06b|src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs|5d6a669fed73fcb7f1946057fc19708b5d1fae572c8efa329247827278b1327a|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs:280|2a44168318e224e1f830fe9ab620aa00dd4f7b3fb19ef4399abf59593cf0756d"},
	"WRK-007": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/ObservabilityIngestTls.cs|0f4c9137ce89e21508a7e90b877a3cf05d87a06960b1b3758364f51ffe4a5837|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/ObservabilityIngestTls.cs:101|d36b85c97864094a1cae0e705bb5cf196629561bf01393e1cd4f6a6ba09947a4"},
	"WRK-008": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/runtime-secrets/production/external-secrets.yaml|6e80f0e86dbed4228040597b6a2a283874f1140f9f23a48547e92c8f71a8ee5f|archive:TerraScale.Infrastructure/gitops/observability/runtime-secrets/production/external-secrets.yaml:2|aed02990c9edd8692808020fb476cc0ab417a493681bc5bbab67def5908aefb2"},
	"WRK-009": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/prometheus-rules.yaml|efac7ead84a30bb5b53725de3b23d5ff082739dd95f900be6be091bfcbe02215|archive:TerraScale.Infrastructure/gitops/observability/resources/production/prometheus-rules.yaml:124|5ec0e8548a47dd15a659db626a84fe9116a1512490d882d29800fcf36d1c535d"},
	"WRK-011": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|AGENTS.md|08d99c7181085edc0678715ac7f3973577bbcbb8a7bc06214c7d9b9fa7d46bd5|archive:TerraScale.Infrastructure/AGENTS.md:69|8f8f7f6150ce721a043902faa349c1149cea6ec9f3495887b3a8cdd140bd6597"},
	"WRK-012": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/prometheus-rules.yaml|efac7ead84a30bb5b53725de3b23d5ff082739dd95f900be6be091bfcbe02215|archive:TerraScale.Infrastructure/gitops/observability/resources/production/prometheus-rules.yaml:253|091723c95dca86a1170f997ac62fe5cd28de11e9aaab1cff67018fd39575ea57"},
	"WRK-013": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/terrascale-service-dashboards.yaml|5f5ed9947f09663166c4abf658c5cdef1cdc00157f224758af505fc9277d3b834|archive:TerraScale.Infrastructure/gitops/observability/resources/production/terrascale-service-dashboards.yaml:7|f9c44d76011cbbc775e8e8aa1118166d7b9616225f671725d653e6c4bf52f6138"},
	"WRK-014": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|Pulumi.production-sfo.yaml|c2372cc5bcdf9f2950fa43bcd472fb0d4ceb9bfc93946fdaceee4dc5d8d22dc8|archive:TerraScale.Infrastructure/Pulumi.production-sfo.yaml:20|18fedfa76062642c684e536ad9d256cb01d4e1c2abe33ea756472782e1dcba46"},
	"WRK-015": {"TerraScale.TypeScript|cd7da11eac891ea2a39eb12014b3abc35d45a412|src/regions.ts|f9e518460351b571659996851a7fd2bd62ca4045eb34cc9a14b861a71bffdc57|archive:TerraScale.TypeScript/src/regions.ts:15|7c34f2c8ad226806e74ad059dec21eca12952b9224a2be6c244cc74a06eaf83c"},
	"WRK-016": {"TerraScale.Internals|88cc11fa9562b8c71dadfa6b0515a3d6ec32aacf|.terrascale/deploy.json|aab0bf12783784e19ae95df2c2513cf818001413b85e9e15e5c02f32a6a3e048|current+archive:TerraScale.Internals/.terrascale/deploy.json:17|360d386fc6ff18dfc06eb82163666bd0db260d7417133c3d94a157ccc61499ed"},
	"WRK-017": {"Terrascale.Documentation|03287808a23cadad5dd83309df8cc63b5d5c46d7|src/content/docs/en/reference/regions.svx|2c95e7cb4b8c730fab5e24b15d51787212dea0fc27a28634476e117f9f858066f|archive:Terrascale.Documentation/src/content/docs/en/reference/regions.svx:74|f3c66a5bdf719d4566668876917c0bc982c6ae8cd9d2a5e37c8b71340bf18cf"},
	"WRK-018": {"TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/Program.cs|f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/Program.cs:366|0096393fdcae599d1fa6e6fa7111b6ff51c3ef89bb999e718eba6a7bff4a41ca7"},
	"WRK-019": {"TerraScale.Deploy|6d56564e16308e2334f76a8635c01f7a621e76da|src/TerraScale.Deploy.Cli/Kubernetes/KubectlRetry.cs|e71cc30d0b673fbbcf72055f6f41c70b4c6e700fe470f8d4dda4abd3db531b58|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Kubernetes/KubectlRetry.cs:7|54e16f538e3fc0d4c4d4e7ed920ecd82de96e3dc49aeec49e5c453cbac6f49d9"},
	"WRK-021": {"Terrascale.Documentation|03287808a23cadad5dd83309df8cc63b5d5c46d7|src/content/docs/en/reference/api/index.svx|e1826ed2b231365b474c633ccc9e9de037946abad43efa0bb2181661287462|archive:Terrascale.Documentation/src/content/docs/en/reference/api/index.svx:20|a122d239d7e365b36957a5e206c0abc3f2fce7f3dffb310c6c1a45a4686f8e"},
	"WRK-022": {"TerraScale.TypeScript|cd7da11eac891ea2a39eb12014b3abc35d45a412|src/regions.ts|f9e518460351b571659996851a7fd2bd62ca4045eb34cc9a14b861a71bffdc57|archive:TerraScale.TypeScript/src/regions.ts:81|3e94bb98c794d747ecb1ad9a02ab88aab87c254b1e99afcc4fd98e213df7e476"},
}

var phase0WorkaroundIds = []string{
	"WRK-001", "WRK-002", "WRK-003", "WRK-004", "WRK-005", "WRK-007", "WRK-008", "WRK-009",
	"WRK-011", "WRK-012", "WRK-013", "WRK-014", "WRK-015", "WRK-016", "WRK-017", "WRK-018",
	"WRK-019", "WRK-021", "WRK-022",
}

func (phase0EvidenceCommand) Run(arguments []string) (int, error) {
	if len(arguments) != 0 {
		return 0, newToolValidationException([]string{"phase0-evidence accepts no arguments"})
	}
	inventory, err := ToolingSupport.ReadObject("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml")
	if err != nil {
		return 0, err
	}
	errors := Phase0EvidenceCommand.ValidateInventory(inventory)
	ledger, err := ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml")
	if err != nil {
		return 0, err
	}
	errors = append(errors, Phase0EvidenceCommand.ValidateWorkaroundLedger(ledger)...)
	if err := ToolingSupport.RequireNoErrors(errors); err != nil {
		return 0, err
	}
	fmt.Println("Phase 0 descriptor inventory and workaround ledger valid; evidence remains unclosed.")
	return 0, nil
}

// ValidateInventory mirrors Phase0EvidenceCommand.ValidateInventory.
func (phase0EvidenceCommand) ValidateInventory(document *JsonObject) []string {
	errors := Validation.JsonDocument(document, "descriptor inventory",
		"schema_version", "inventory_id", "evidence_title", "captured_at", "scope", "repositories", "gaps")
	if value, ok := tryInt(document.Get("schema_version")); !ok || value != 1 {
		errors = append(errors, "descriptor inventory: expected schema_version 1")
	}
	if value, ok := document.Get("inventory_id").(string); !ok || strings.TrimSpace(value) == "" {
		errors = append(errors, "descriptor inventory: inventory_id is required")
	}
	if value, ok := document.Get("evidence_title").(string); !ok || strings.TrimSpace(value) == "" {
		errors = append(errors, "descriptor inventory: evidence_title is required")
	}
	if value, ok := document.Get("captured_at").(string); !ok || !tryParseDateOnly(value) {
		errors = append(errors, "descriptor inventory: captured_at must be an ISO-8601 date")
	}
	scope, isScope := document.Get("scope").(*JsonObject)
	if !isScope || len(Validation.JsonDocument(scope, "descriptor inventory scope",
		"method", "production_contract_rule", "sensitive_data")) != 0 {
		errors = append(errors, "descriptor inventory: scope must contain required evidence metadata")
	}
	entries, isEntries := document.Get("repositories").(*JsonArray)
	if !isEntries {
		return errors
	}
	names := make([]string, 0, entries.Len())
	for _, entry := range entries.items {
		name := ""
		if object, ok := entry.(*JsonObject); ok {
			if value, isString := object.Get("repository").(string); isString {
				name = value
			}
		}
		names = append(names, name)
	}
	if !stringSlicesEqual(names, phase0Repositories) {
		errors = append(errors, "descriptor inventory: repository entries must be stable and ordered")
	}
	for entryIndex := 0; entryIndex < entries.Len(); entryIndex++ {
		entry, isObject := entries.Get(entryIndex).(*JsonObject)
		if !isObject {
			errors = append(errors, fmt.Sprintf("descriptor inventory: repository %d must be an object", entryIndex+1))
			continue
		}

		repository := ""
		if value, ok := entry.Get("repository").(string); ok {
			repository = value
		}
		for _, field := range phase0InventoryFields {
			if !entry.Has(field) {
				errors = append(errors, fmt.Sprintf("%s: missing field %s", repository, field))
			}
		}
		commit := ""
		if value, ok := entry.Get("source_commit").(string); ok {
			commit = value
		}
		if !phase0IsCommit(commit) {
			errors = append(errors, fmt.Sprintf("%s: source_commit must be a lower-case immutable commit ID", repository))
		} else {
			phase0VerifyCommit(repository, commit, "repository source_commit", &errors)
		}
		state, hasState := entry.Get("checkout_state").(string)
		if !hasState || (state != "clean" && state != "dirty") {
			errors = append(errors, fmt.Sprintf("%s: checkout_state must be clean or dirty", repository))
		}
		descriptors, hasDescriptors := entry.Get("descriptors").(*JsonArray)
		if !hasDescriptors || descriptors.Len() == 0 {
			errors = append(errors, fmt.Sprintf("%s: descriptors are required", repository))
			continue
		}

		for descriptorIndex := 0; descriptorIndex < descriptors.Len(); descriptorIndex++ {
			descriptor, isDescriptor := descriptors.Get(descriptorIndex).(*JsonObject)
			if !isDescriptor {
				errors = append(errors, fmt.Sprintf("%s: descriptor %d must be an object", repository, descriptorIndex+1))
				continue
			}

			for _, field := range phase0DescriptorFields {
				if !descriptor.Has(field) {
					errors = append(errors, fmt.Sprintf("%s: descriptor %d missing field %s", repository, descriptorIndex+1, field))
				}
			}
			path := ""
			if value, ok := descriptor.Get("path").(string); ok {
				path = value
			}
			sourceCommit := commit
			if value, ok := descriptor.Get("source_commit").(string); ok {
				sourceCommit = value
			}
			hash := ""
			if value, ok := descriptor.Get("source_sha256").(string); ok {
				hash = value
			}
			if !phase0IsPath(path) {
				errors = append(errors, fmt.Sprintf("%s: descriptor path must be a fixed repository-relative source path", repository))
			}
			if !phase0IsCommit(sourceCommit) {
				errors = append(errors, fmt.Sprintf("%s:%s: source_commit must be a lower-case immutable commit ID", repository, path))
			}
			if !phase0IsHash(hash) {
				errors = append(errors, fmt.Sprintf("%s:%s: source_sha256 must be a lower-case SHA-256", repository, path))
			}
			if phase0IsPath(path) && phase0IsCommit(sourceCommit) && phase0IsHash(hash) {
				phase0VerifySource(repository, sourceCommit, path, hash, &errors)
			}
		}
	}

	return errors
}

// ValidateWorkaroundLedger mirrors Phase0EvidenceCommand.ValidateWorkaroundLedger.
func (phase0EvidenceCommand) ValidateWorkaroundLedger(document *JsonObject) []string {
	errors := Validation.JsonDocument(document, "workaround ledger",
		"schema_version", "required_entry_fields", "closureEvidence", "archivalSourceEvidence", "entries", "gaps")
	if value, ok := tryInt(document.Get("schema_version")); !ok || value != 2 {
		errors = append(errors, "workaround ledger: expected schema_version 2")
	}
	required, hasRequired := document.Get("required_entry_fields").(*JsonArray)
	if !hasRequired || !phase0StringSequence(required, phase0WorkaroundFields) {
		errors = append(errors, "workaround ledger: required_entry_fields are incomplete")
	}
	expectedKeys := map[string]bool{}
	for _, id := range phase0WorkaroundIds {
		expectedKeys[id] = true
	}
	closures, hasClosures := document.Get("closureEvidence").(*JsonObject)
	if !hasClosures {
		errors = append(errors, "workaround ledger: closureEvidence must be a record map")
	} else if !objectKeysMatch(closures, expectedKeys) {
		errors = append(errors, "workaround ledger: closureEvidence must have exactly the active workaround keys")
	}
	archives, hasArchives := document.Get("archivalSourceEvidence").(*JsonObject)
	if !hasArchives {
		errors = append(errors, "workaround ledger: archivalSourceEvidence must be a record map")
	} else if !objectKeysMatch(archives, expectedKeys) {
		errors = append(errors, "workaround ledger: archivalSourceEvidence must have exactly the active workaround keys")
	}
	entries, hasEntries := document.Get("entries").(*JsonArray)
	if !hasEntries || entries.Len() != len(phase0WorkaroundIds) {
		return errors
	}
	for index := 0; index < entries.Len(); index++ {
		entry, isObject := entries.Get(index).(*JsonObject)
		if !isObject {
			errors = append(errors, fmt.Sprintf("workaround %d: record must be an object", index+1))
			continue
		}

		id := phase0WorkaroundIds[index]
		entryID := ""
		if value, ok := entry.Get("id").(string); ok {
			entryID = value
		}
		if entryID != id {
			errors = append(errors, fmt.Sprintf("workaround %d: IDs must be stable and ordered", index+1))
		}
		for _, field := range phase0WorkaroundFields {
			if !entry.Has(field) {
				errors = append(errors, fmt.Sprintf("%s: missing field %s", id, field))
			}
		}
		status, hasStatus := entry.Get("status").(string)
		var closure any
		if closures != nil {
			closure = closures.Get(id)
		}
		var archiveList *JsonArray
		if archives != nil {
			archiveList, _ = archives.Get(id).(*JsonArray)
		}
		anchors, _ := entry.Get("source_anchors").(*JsonArray)
		phase0ValidateArchiveSources(id, anchors, archiveList, &errors)
		if hasStatus && status == "identified" {
			if closure != nil {
				errors = append(errors, fmt.Sprintf("%s: identified work must have empty closureEvidence", id))
			}
		} else if hasStatus && (status == "retired" || status == "closed") {
			closureObject, _ := closure.(*JsonObject)
			phase0ValidateClosure(id, nodeStringValue(entry.Get("native_replacement_gate")), closureObject, &errors)
		} else {
			errors = append(errors, fmt.Sprintf("%s: status must be identified, retired, or closed", id))
		}
	}

	return errors
}

func phase0StringSequence(values *JsonArray, expected []string) bool {
	if values.Len() != len(expected) {
		return false
	}
	for index := 0; index < values.Len(); index++ {
		value, ok := values.Get(index).(string)
		if !ok || value != expected[index] {
			return false
		}
	}
	return true
}

func objectKeysMatch(object *JsonObject, expected map[string]bool) bool {
	if object.Len() != len(expected) {
		return false
	}
	for _, key := range object.Keys() {
		if !expected[key] {
			return false
		}
	}
	return true
}

func stringSlicesEqual(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func phase0VerifySource(repository string, commit string, path string, hash string, errors *[]string) {
	if !phase0IsKnownRepository(repository) {
		*errors = append(*errors, fmt.Sprintf("%s:%s: repository is not a known workspace product", repository, path))
		return
	}

	source, err := ToolingSupport.GitBytes(phase0RepositoryPath(repository), "show", fmt.Sprintf("%s:%s", commit, path))
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("%s:%s: pinned source is unavailable (%s)", repository, path, err.Error()))
		return
	}
	if ToolingSupport.Sha256Bytes(source) != hash {
		*errors = append(*errors, fmt.Sprintf("%s:%s: source_sha256 does not match git show %s:%s", repository, path, commit, path))
	}
}

func phase0ValidateClosure(id string, nativeReplacementGate string, closure *JsonObject, errors *[]string) {
	if closure == nil {
		*errors = append(*errors, fmt.Sprintf("%s: retired/closed work requires complete closureEvidence", id))
		return
	}

	for _, field := range phase0ClosureFields {
		if field == "affected_safe_paths" {
			paths, isPaths := closure.Get(field).(*JsonArray)
			invalid := !isPaths || paths.Len() == 0
			if !invalid {
				for _, pathNode := range paths.items {
					if !phase0IsPath(nodeStringValue(pathNode)) {
						invalid = true
						break
					}
				}
			}
			if invalid {
				*errors = append(*errors, fmt.Sprintf("%s: closureEvidence requires %s", id, field))
			}
		} else if strings.TrimSpace(nodeStringValue(closure.Get(field))) == "" {
			*errors = append(*errors, fmt.Sprintf("%s: closureEvidence requires %s", id, field))
		}
	}
	repository := nodeStringValue(closure.Get("repository"))
	commit := nodeStringValue(closure.Get("commit"))
	path := nodeStringValue(closure.Get("path"))
	hash := nodeStringValue(closure.Get("sha256"))
	if nodeStringValue(closure.Get("workaround_id")) != id {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence workaround_id must match the current work record", id))
	}
	if nodeStringValue(closure.Get("native_replacement_gate")) != nativeReplacementGate {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence native_replacement_gate must match the current work record", id))
	}
	if !phase0IsKnownRepository(repository) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence repository must be a known workspace product", id))
	}
	if !phase0IsCommit(commit) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence commit must be immutable", id))
	}
	if !phase0IsPath(path) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence path must be repository-relative", id))
	}
	if !phase0IsHash(hash) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence sha256 must be lower-case", id))
	}
	if timestamp, ok := closure.Get("timestamp").(string); !ok || !tryParseDateTimeOffset(timestamp) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence timestamp must be ISO-8601", id))
	}
	if phase0IsKnownRepository(repository) && phase0IsCommit(commit) && phase0IsPath(path) && phase0IsHash(hash) {
		phase0VerifyCommit(repository, commit, fmt.Sprintf("%s: closureEvidence commit", id), errors)
		phase0VerifySource(repository, commit, path, hash, errors)
		phase0VerifyClosureReceipt(id, closure, repository, commit, path, errors)
	}
}

func phase0VerifyClosureReceipt(id string, closure *JsonObject, repository string, commit string, path string, errors *[]string) {
	content, err := ToolingSupport.GitBytes(phase0RepositoryPath(repository), "show", fmt.Sprintf("%s:%s", commit, path))
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence immutable artifact is not valid receipt JSON (%s)", id, err.Error()))
		return
	}
	node, parseErr := parseJSONNode(content)
	receipt, isObject := node.(*JsonObject)
	if parseErr != nil || !isObject || nodeStringValue(receipt.Get("receipt_type")) != "terrascale.workaround-closure-receipt/v1" {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence immutable artifact must be a dedicated structured receipt", id))
		return
	}

	for _, field := range phase0ClosureFields {
		if field == "repository" {
			break
		}
		if field == "affected_safe_paths" {
			paths, isPaths := receipt.Get(field).(*JsonArray)
			invalid := !isPaths || paths.Len() == 0
			if !invalid {
				for _, pathNode := range paths.items {
					if !phase0IsPath(nodeStringValue(pathNode)) {
						invalid = true
						break
					}
				}
			}
			if invalid || !deepEqualJSON(paths, closure.Get(field)) {
				*errors = append(*errors, fmt.Sprintf("%s: closureEvidence affected_safe_paths must match the immutable receipt", id))
			}
		} else if nodeStringValue(receipt.Get(field)) != nodeStringValue(closure.Get(field)) {
			*errors = append(*errors, fmt.Sprintf("%s: closureEvidence %s must match the immutable receipt", id, field))
		}
	}
	if nodeStringValue(receipt.Get("timestamp")) != nodeStringValue(closure.Get("timestamp")) {
		*errors = append(*errors, fmt.Sprintf("%s: closureEvidence timestamp must match the immutable receipt", id))
	}
}

func phase0ValidateArchiveSources(id string, anchors *JsonArray, sources *JsonArray, errors *[]string) {
	if anchors == nil || anchors.Len() == 0 || sources == nil || sources.Len() == 0 {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence requires an immutable source record", id))
		return
	}

	declared := make([]string, 0, anchors.Len())
	for _, anchor := range anchors.items {
		declared = append(declared, nodeStringValue(anchor))
	}
	for index, anchor := range declared {
		if phase0ParseArchiveAnchor(anchor) == nil {
			*errors = append(*errors, fmt.Sprintf("%s: source_anchors[%d] must be a known archival repository path and positive line", id, index))
		}
	}

	recorded := make([]string, 0, sources.Len())
	for _, source := range sources.items {
		anchor := ""
		if receipt, ok := source.(*JsonObject); ok {
			anchor = nodeStringValue(receipt.Get("anchor"))
		}
		recorded = append(recorded, anchor)
	}
	if !stringSlicesEqual(recorded, declared) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence must exactly match declared source_anchors", id))
	}
	identities := make([]string, 0, sources.Len())
	for _, source := range sources.items {
		if receipt, ok := source.(*JsonObject); ok {
			identities = append(identities, strings.Join([]string{
				nodeStringValue(receipt.Get("repository")),
				nodeStringValue(receipt.Get("commit")),
				nodeStringValue(receipt.Get("path")),
				nodeStringValue(receipt.Get("sha256")),
				nodeStringValue(receipt.Get("anchor")),
				nodeStringValue(receipt.Get("anchor_sha256")),
			}, "|"))
			continue
		}
		identities = append(identities, "")
	}
	expected, hasExpected := phase0ArchivalReceiptIdentities[id]
	if !hasExpected || !stringSlicesEqual(identities, expected) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence must match its canonical immutable anchor receipts", id))
	}
	for _, source := range sources.items {
		receipt, isObject := source.(*JsonObject)
		if !isObject {
			*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence records must be objects", id))
			continue
		}

		phase0ValidateArchiveSource(id, receipt, errors)
	}
}

func phase0ValidateArchiveSource(id string, source *JsonObject, errors *[]string) {
	if source == nil {
		return
	}

	for _, field := range append(append([]string(nil), phase0ArchiveFields...), "anchor") {
		if strings.TrimSpace(nodeStringValue(source.Get(field))) == "" {
			*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence requires %s", id, field))
		}
	}
	repository := nodeStringValue(source.Get("repository"))
	commit := nodeStringValue(source.Get("commit"))
	path := nodeStringValue(source.Get("path"))
	hash := nodeStringValue(source.Get("sha256"))
	anchor := nodeStringValue(source.Get("anchor"))
	anchorHash := nodeStringValue(source.Get("anchor_sha256"))
	parsedAnchor := phase0ParseArchiveAnchor(anchor)
	if parsedAnchor == nil {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor is malformed", id))
	} else if parsedAnchor.Repository != repository || parsedAnchor.Path != path {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence repository/path must match its anchor", id))
	}
	if !phase0IsKnownRepository(repository) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence repository must be a known workspace product", id))
	}
	if !phase0IsCommit(commit) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence commit must be immutable", id))
	}
	if !phase0IsPath(path) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence path must be repository-relative", id))
	}
	if !phase0IsHash(hash) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence sha256 must be lower-case", id))
	}
	if !phase0IsHash(anchorHash) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor_sha256 must be lower-case", id))
	}
	if phase0IsKnownRepository(repository) && phase0IsCommit(commit) && phase0IsPath(path) &&
		phase0IsHash(hash) && phase0IsHash(anchorHash) {
		phase0VerifyCommit(repository, commit, fmt.Sprintf("%s: archivalSourceEvidence commit", id), errors)
		phase0VerifySource(repository, commit, path, hash, errors)
		if parsedAnchor != nil {
			phase0VerifyAnchorLine(id, repository, commit, path, parsedAnchor.Start, parsedAnchor.End, anchorHash, errors)
		}
	}
}

func phase0VerifyAnchorLine(id string, repository string, commit string, path string, start int, end int, hash string, errors *[]string) {
	content, err := ToolingSupport.GitBytes(phase0RepositoryPath(repository), "show", fmt.Sprintf("%s:%s", commit, path))
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor is not valid UTF-8 text (%s)", id, err.Error()))
		return
	}
	rawLines := getRawLines(content, start, end)
	if rawLines == nil {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor line is out of bounds or blank", id))
		return
	}
	if !utf8.Valid(rawLines) {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor is not valid UTF-8 text (invalid UTF-8 bytes)", id))
		return
	}
	if strings.TrimSpace(string(rawLines)) == "" {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor line is out of bounds or blank", id))
		return
	}
	if ToolingSupport.Sha256Bytes(rawLines) != hash {
		*errors = append(*errors, fmt.Sprintf("%s: archivalSourceEvidence anchor_sha256 does not match raw pinned line/range bytes", id))
	}
}

func getRawLines(content []byte, startLine int, endLine int) []byte {
	start := 0
	for current := 1; current < startLine; current++ {
		index := bytes.IndexByte(content[start:], '\n')
		if index < 0 {
			return nil
		}
		start += index + 1
	}

	end := start
	for current := startLine; current <= endLine; current++ {
		index := bytes.IndexByte(content[end:], '\n')
		if index < 0 {
			if current == endLine {
				return content[start:]
			}
			return nil
		}
		if current == endLine {
			return content[start : end+index]
		}
		end += index + 1
	}

	return nil
}

type archiveAnchor struct {
	Repository string
	Path       string
	Start      int
	End        int
}

var archiveAnchorPattern = regexp.MustCompile(
	`^(?:archive|current\+archive):([A-Za-z0-9.]+)/([A-Za-z0-9._/-]+):([1-9][0-9]*)(?:-([1-9][0-9]*))?$`)

func phase0ParseArchiveAnchor(anchor string) *archiveAnchor {
	match := archiveAnchorPattern.FindStringSubmatch(anchor)
	if match == nil || !phase0IsKnownRepository(match[1]) || !phase0IsPath(match[2]) {
		return nil
	}
	start, err := strconv.ParseInt(match[3], 10, 32)
	if err != nil {
		return nil
	}
	end := start
	if match[4] != "" {
		parsed, endErr := strconv.ParseInt(match[4], 10, 32)
		if endErr != nil {
			return nil
		}
		end = parsed
	}
	if end < start {
		return nil
	}
	return &archiveAnchor{Repository: match[1], Path: match[2], Start: int(start), End: int(end)}
}

// nodeStringValue mirrors the C# StringValue helper: the string scalar value
// or "" when the node is absent, null, or not a string.
func nodeStringValue(node any) string {
	if value, ok := node.(string); ok {
		return value
	}
	return ""
}

func phase0VerifyCommit(repository string, commit string, where string, errors *[]string) {
	if !phase0IsKnownRepository(repository) {
		*errors = append(*errors, fmt.Sprintf("%s: repository is not a known workspace product", where))
		return
	}

	if _, err := ToolingSupport.Git(phase0RepositoryPath(repository), "cat-file", "-e", fmt.Sprintf("%s^{commit}", commit)); err != nil {
		*errors = append(*errors, fmt.Sprintf("%s: %s is unavailable (%s)", repository, where, err.Error()))
	}
}

func phase0RepositoryPath(repository string) string {
	root := ToolingSupport.Root()
	parent := filepath.Dir(root)
	if parent == root {
		panic("workspace root is unavailable")
	}
	return filepath.Join(parent, repository)
}

func phase0IsKnownRepository(repository string) bool {
	for _, known := range phase0Repositories {
		if known == repository {
			return true
		}
	}
	return false
}

var phase0CommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var phase0HashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var phase0PathCharactersPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

func phase0IsCommit(value string) bool {
	return phase0CommitPattern.MatchString(value)
}

func phase0IsHash(value string) bool {
	return phase0HashPattern.MatchString(value)
}

// phase0IsPath mirrors the C# lookahead regex: rooted paths and "." or ".."
// segments are rejected while the character class is enforced.
func phase0IsPath(value string) bool {
	if !phase0PathCharactersPattern.MatchString(value) || strings.HasPrefix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
