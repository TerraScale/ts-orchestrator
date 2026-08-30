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

type adrReadinessCommand struct{}

// AdrReadinessCommand mirrors the C# static class.
var AdrReadinessCommand = adrReadinessCommand{}

var adrLanes = []string{
	"Integration/contract steward", "Core", "Messaging/security", "Runtime", "Cloud", "Storage",
	"TerraBase", "Delivery", "Operations", "Cross-repository cleanup", "Verification",
}

// Lanes mirrors AdrReadinessCommand.Lanes.
func (adrReadinessCommand) Lanes() map[string]bool {
	lanes := make(map[string]bool, len(adrLanes))
	for _, lane := range adrLanes {
		lanes[lane] = true
	}
	return lanes
}

var adrStatuses = func() map[string]bool {
	return map[string]bool{
		"draft-ready": true, "owner-input-required": true, "evidence-required": true, "accepted": true,
	}
}()

var adrRequiredFields = []string{
	"id", "slug", "title", "status", "ownerLane", "controllingInputs", "availableEvidence",
	"missingEvidence", "executableDependencies", "closureEvidence", "exitEvidence",
}

func (adrReadinessCommand) Run(arguments []string) (int, error) {
	path := adrOption(arguments, "--document")
	if path == "" {
		path = "docs/adr/readiness-index.yaml"
	}
	document, err := ToolingSupport.ReadObject(path)
	if err != nil {
		return 0, err
	}
	errors := AdrReadinessCommand.Validate(document)
	if err := ToolingSupport.RequireNoErrors(errors); err != nil {
		return 0, err
	}
	fmt.Println("ADR readiness index valid: 24 unique fail-closed records")
	return 0, nil
}

// Validate mirrors AdrReadinessCommand.Validate.
func (adrReadinessCommand) Validate(document *JsonObject) []string {
	errors := Validation.JsonDocument(document, "readiness", "schemaVersion", "status", "openOwnerQuestions", "entries")
	if value, ok := tryInt(document.Get("schemaVersion")); !ok || value != 1 {
		errors = append(errors, "schemaVersion: expected 1")
	}
	if value, ok := document.Get("status").(string); !ok || value != "readiness-map-not-decision-record" {
		errors = append(errors, "status: readiness map cannot claim a decision")
	}
	entries, hasEntries := document.Get("entries").(*JsonArray)
	if !hasEntries || entries.Len() != 24 {
		errors = append(errors, "entries: IDs 1 through 24 must occur exactly once")
	} else {
		ids := make([]int, 0, entries.Len())
		for _, item := range entries.items {
			ids = append(ids, entryInt(item, "id"))
		}
		ordered := len(ids) == 24
		for index := range ids {
			if ordered && ids[index] != index+1 {
				ordered = false
			}
		}
		if !ordered {
			errors = append(errors, "entries: IDs 1 through 24 must be ordered and unique")
		}
		for _, item := range entries.items {
			entry, isObject := item.(*JsonObject)
			if !isObject {
				continue
			}
			id := entryInt(entry, "id")
			for _, field := range adrRequiredFields {
				if !entry.Has(field) {
					errors = append(errors, fmt.Sprintf("ADR %d: missing field %s", id, field))
				}
			}

			if lane := entry.Get("ownerLane"); isScalar(lane) {
				if laneValue, ok := lane.(string); !ok || !AdrReadinessCommand.Lanes()[laneValue] {
					errors = append(errors, fmt.Sprintf("ADR %d: non-canonical owner lane", id))
				}
			}
			if status := entry.Get("status"); isScalar(status) {
				if statusValue, ok := status.(string); !ok || !adrStatuses[statusValue] {
					errors = append(errors, fmt.Sprintf("ADR %d: invalid status", id))
				}
			}
			errors = Validation.ValidateLocalAnchors(objectArray(entry.Get("availableEvidence")), fmt.Sprintf("ADR %d", id), errors)
			if entry.Has("accepted") {
				errors = append(errors, fmt.Sprintf("ADR %d: accepted is forbidden while owner inputs remain open", id))
			}
			if statusValue, ok := entry.Get("status").(string); ok {
				if statusValue == "accepted" {
					errors = append(errors, fmt.Sprintf("ADR %d: accepted is forbidden while owner/SLO inputs remain open", id))
				}
				if statusValue == "draft-ready" {
					evidence := objectArray(entry.Get("availableEvidence"))
					hasOrchestratorAnchor := false
					if evidence != nil {
						for _, value := range evidence.items {
							if anchor, ok := value.(string); ok &&
								strings.HasPrefix(anchor, "docs/architecture/orchestrator.md:") {
								hasOrchestratorAnchor = true
							}
						}
					}
					if !hasOrchestratorAnchor {
						errors = append(errors, fmt.Sprintf(
							"ADR %d: draft-ready requires a precise docs/architecture/orchestrator.md anchor", id))
					}
				}
			}
		}
	}

	packet, err := ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json")
	if err != nil {
		return append(errors, err.Error())
	}
	return append(errors, DecisionReadinessValidator.Validate(packet, document)...)
}

func isScalar(node any) bool {
	if node == nil {
		return false
	}
	switch node.(type) {
	case *JsonObject, *JsonArray:
		return false
	}
	return true
}

func entryInt(parent any, key string) int {
	if object, ok := parent.(*JsonObject); ok {
		if value, ok := tryInt(object.Get(key)); ok {
			return value
		}
	}
	return 0
}

func objectArray(node any) *JsonArray {
	array, _ := node.(*JsonArray)
	return array
}

func adrOption(arguments []string, name string) string {
	for index, argument := range arguments {
		if argument == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

type ownerDecisionCommand struct{}

// OwnerDecisionCommand mirrors the C# static class.
var OwnerDecisionCommand = ownerDecisionCommand{}

var ownerDecisionUnits = map[string]string{
	"team-size":                                        "people",
	"first-production-date":                            "ISO-8601-date-or-quarter",
	"maximum-three-region-pre-user-cost":               "BRL/day",
	"storage-minimum-iops-per-member":                  "IOPS",
	"storage-minimum-throughput-per-member":            "MiB/s",
	"storage-p95-read-latency":                         "ms",
	"storage-p99-read-latency":                         "ms",
	"storage-p95-write-latency":                        "ms",
	"storage-p99-write-latency":                        "ms",
	"regional-rpo":                                     "seconds",
	"regional-rto":                                     "minutes",
	"security-credential-revocation":                   "seconds",
	"security-workload-certificate-ttl":                "hours",
	"security-certificate-renewal-lead":                "hours",
	"security-break-glass-session-ttl":                 "minutes",
	"security-critical-remediation":                    "hours",
	"memory-orchestrator-rss-per-host":                 "MiB",
	"density-compact-post-failure-utilization-ceiling": "percent",
	"audit-hot-retention":                              "days",
	"audit-immutable-retention":                        "days",
	"maximum-regional-survival-window":                 "hours",
}

func (ownerDecisionCommand) Run(arguments []string) (int, error) {
	path := "docs/decisions/owner-decision-packet.json"
	if len(arguments) > 0 {
		path = arguments[0]
	}
	document, err := ToolingSupport.ReadObject(path)
	if err != nil {
		return 0, err
	}
	if err := ToolingSupport.RequireNoErrors(OwnerDecisionCommand.Validate(document)); err != nil {
		return 0, err
	}
	fmt.Println("owner decision packet valid: decisions 1A-10A accepted; measurable qualification targets remain unset")
	return 0, nil
}

// Validate mirrors OwnerDecisionCommand.Validate.
func (ownerDecisionCommand) Validate(document *JsonObject) []string {
	errors := Validation.JsonDocument(document, "packet", "schemaVersion", "status", "recordedResponse", "questions")
	if value, ok := document.Get("status").(string); !ok || value != "owner-choices-accepted-measurable-targets-pending" {
		errors = append(errors, "status: owner choices must be accepted while measurable targets remain pending")
	}
	response, isResponse := document.Get("recordedResponse").(*JsonObject)
	answer, hasAnswer := "", false
	priority, hasPriority := "", false
	if isResponse {
		answer, hasAnswer = response.Get("answer").(string)
		priority, hasPriority = response.Get("priority").(string)
	}
	if !isResponse || !hasAnswer || answer != "all A" || !hasPriority || priority != "reliability-first" {
		errors = append(errors, "recordedResponse: explicit all-A reliability-first response is required")
	}
	questions, hasQuestions := document.Get("questions").(*JsonArray)
	if !hasQuestions || questions.Len() != 10 {
		errors = append(errors, "questions: exactly ten owner questions are required")
	} else {
		ids := make([]int, 0, questions.Len())
		for _, question := range questions.items {
			ids = append(ids, entryInt(question, "id"))
		}
		ordered := len(ids) == 10
		for index := range ids {
			if ordered && ids[index] != index+1 {
				ordered = false
			}
		}
		if !ordered {
			errors = append(errors, "questions: IDs 1 through 10 must be ordered and complete")
		}
		specification := readFileLines(filepath.Join(ToolingSupport.Root(), "docs/architecture/orchestrator.md"))
		for _, item := range questions.items {
			question, isObject := item.(*JsonObject)
			if !isObject {
				continue
			}
			id := entryInt(question, "id")
			answer, _ := question.Get("answer").(string)
			if answer != "A" {
				errors = append(errors, fmt.Sprintf("question %d: answer must match the explicit owner selection A", id))
			}
			if question.Get("optionA") == nil || question.Get("optionB") == nil {
				errors = append(errors, fmt.Sprintf("question %d: exactly two options required", id))
			}
			sourceLine := entryInt(question, "sourceLine")
			if sourceLine <= 0 || sourceLine > len(specification) {
				errors = append(errors, fmt.Sprintf("question %d: invalid source line", id))
				continue
			}

			cells := specificationCells(specification[sourceLine-1])
			if len(cells) < 4 || cells[0] != strconv.Itoa(id) {
				errors = append(errors, fmt.Sprintf(
					"question %d: question differs from docs/architecture/orchestrator.md:%d", id, sourceLine))
				continue
			}

			if value, ok := question.Get("question").(string); !ok || value != cells[1] {
				errors = append(errors, fmt.Sprintf(
					"question %d: question differs from docs/architecture/orchestrator.md:%d", id, sourceLine))
			}
			if value, ok := question.Get("optionA").(string); !ok || value != cells[2] {
				errors = append(errors, fmt.Sprintf(
					"question %d: optionA differs from docs/architecture/orchestrator.md:%d", id, sourceLine))
			}
			if value, ok := question.Get("optionB").(string); !ok || value != cells[3] {
				errors = append(errors, fmt.Sprintf(
					"question %d: optionB differs from docs/architecture/orchestrator.md:%d", id, sourceLine))
			}
			if value, ok := question.Get("semanticSha256").(string); !ok ||
				value != ToolingSupport.Sha256Text(strings.Join(cells, "\x1f")) {
				errors = append(errors, fmt.Sprintf("question %d: source line/checksum mismatch", id))
			}
		}
	}

	inputs, hasInputs := document.Get("inputs").(*JsonArray)
	if !hasInputs || inputs.Len() != len(ownerDecisionUnits) {
		errors = append(errors, "required inputs must occur exactly once")
	} else {
		for _, item := range inputs.items {
			input, isObject := item.(*JsonObject)
			if !isObject {
				continue
			}
			id := ""
			if value, ok := input.Get("id").(string); ok {
				id = value
			}
			unit := ownerDecisionUnits[id]
			if unitValue, hasUnit := input.Get("unit").(string); !hasUnit || unitValue != unit {
				errors = append(errors, fmt.Sprintf("input %s: unit must be %s", id, unit))
			}
			if input.Get("value") != nil {
				errors = append(errors, fmt.Sprintf("input %s: unmeasured value must remain null", id))
			}
			expectedStage := "deployment-qualification"
			if id == "team-size" || id == "first-production-date" {
				expectedStage = "phase-0-planning"
			}
			if value, ok := input.Get("readinessStage").(string); !ok || value != expectedStage {
				errors = append(errors, fmt.Sprintf("input %s: readiness stage must be %s", id, expectedStage))
			}
			if value, ok := tryBool(input.Get("requiredBeforeContractFreeze")); !ok || value {
				errors = append(errors, fmt.Sprintf(
					"input %s: unmeasured qualification values cannot block pure contract freeze", id))
			}
		}
	}

	selections, hasSelections := document.Get("laterImplementationSelections").(*JsonArray)
	if !hasSelections || selections.Len() != 7 {
		errors = append(errors, "later implementation selections must occur exactly once")
	} else {
		for _, item := range selections.items {
			selection, isObject := item.(*JsonObject)
			if !isObject {
				continue
			}
			if selection.Get("selection") != nil {
				errors = append(errors, fmt.Sprintf("selection %s: checked-in selection must remain null",
					nodeDisplay(selection.Get("id"))))
			}
		}
	}

	readiness, err := ToolingSupport.ReadObject("docs/adr/readiness-index.yaml")
	if err != nil {
		return append(errors, err.Error())
	}
	return append(errors, DecisionReadinessValidator.Validate(document, readiness)...)
}

func specificationCells(line string) []string {
	trimmed := strings.TrimSpace(strings.Trim(strings.TrimSpace(line), "|"))
	cells := strings.Split(trimmed, "|")
	for index := range cells {
		cells[index] = strings.TrimSpace(cells[index])
	}
	return cells
}

// nodeDisplay mirrors C# string interpolation of a JsonNode (JsonValue<string>
// renders unquoted; other nodes render as JSON).
func nodeDisplay(node any) string {
	if node == nil {
		return ""
	}
	if value, ok := node.(string); ok {
		return value
	}
	encoded, err := json.Marshal(node)
	if err != nil {
		return ""
	}
	return string(encoded)
}

type decisionReadinessValidator struct{}

// DecisionReadinessValidator mirrors the C# static class.
var DecisionReadinessValidator = decisionReadinessValidator{}

var acceptedPolicyProvenance = []string{
	"docs/architecture/orchestrator.md:83-98", "docs/decisions/owner-decision-packet.json:13-49",
}

var openInputProvenance = []string{
	"docs/architecture/orchestrator.md:100-105", "docs/decisions/owner-decision-packet.json:51-122",
}

var laterSelectionIds = []string{
	"artifact-and-evidence-signing", "dns-implementation", "vpn-implementation", "operator-identity-provider",
	"regional-artifact-mirror", "arm64-host-image", "nats-n-minus-one-policy",
}

type decisionImpactMapping struct {
	Adrs  []int
	Gates []string
}

type decisionInputMapping struct {
	Validation string
	Adrs       []int
	Gates      []string
}

var questionMappings = map[int]decisionImpactMapping{
	1:  {[]int{1, 2}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S"}},
	2:  {[]int{1, 21}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"}},
	3:  {[]int{12, 21}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"}},
	4:  {[]int{6, 10}, []string{"contract-freeze", "phase-0-exit", "L0", "L1R", "L3S", "L4"}},
	5:  {[]int{9, 10}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"}},
	6:  {[]int{16, 19}, []string{"contract-freeze", "phase-0-exit", "L0", "L4", "L5"}},
	7:  {[]int{14}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S"}},
	8:  {[]int{2, 8}, []string{"contract-freeze", "phase-0-exit", "L0C", "L3S", "L4", "L5"}},
	9:  {[]int{17}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L5"}},
	10: {[]int{10}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S"}},
}

var inputMappings = map[string]decisionInputMapping{
	"team-size":                                        {`{"type":"integer","minimum":1}`, []int{19}, []string{"phase-0-planning"}},
	"first-production-date":                            {`{"type":"string","pattern":"^(\\d{4}-\\d{2}-\\d{2}|\\d{4}-Q[1-4])$"}`, []int{19}, []string{"phase-0-planning"}},
	"maximum-three-region-pre-user-cost":               {`{"type":"number","exclusiveMinimum":0}`, []int{5, 8, 19, 24}, []string{"contract-freeze", "phase-0-exit", "L5"}},
	"storage-minimum-iops-per-member":                  {`{"type":"integer","minimum":1}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"storage-minimum-throughput-per-member":            {`{"type":"number","exclusiveMinimum":0}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"storage-p95-read-latency":                         {`{"type":"number","minimum":0}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"storage-p99-read-latency":                         {`{"type":"number","minimum":0}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"storage-p95-write-latency":                        {`{"type":"number","minimum":0}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"storage-p99-write-latency":                        {`{"type":"number","minimum":0}`, []int{2, 3, 5, 8, 9, 10, 19}, []string{"contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"}},
	"regional-rpo":                                     {`{"type":"integer","minimum":0}`, []int{1, 3, 9, 10, 12, 19, 21, 24}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4", "L5"}},
	"regional-rto":                                     {`{"type":"integer","minimum":0}`, []int{1, 3, 9, 10, 12, 19, 21, 24}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"}},
	"security-credential-revocation":                   {`{"type":"integer","minimum":0}`, []int{11, 17}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"}},
	"security-workload-certificate-ttl":                {`{"type":"integer","minimum":1}`, []int{11}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"}},
	"security-certificate-renewal-lead":                {`{"type":"integer","minimum":1}`, []int{11}, []string{"contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"}},
	"security-break-glass-session-ttl":                 {`{"type":"integer","minimum":1}`, []int{17}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L5"}},
	"security-critical-remediation":                    {`{"type":"integer","minimum":0}`, []int{11, 17}, []string{"contract-freeze", "phase-0-exit"}},
	"memory-orchestrator-rss-per-host":                 {`{"type":"integer","minimum":1}`, []int{7, 8}, []string{"contract-freeze", "phase-0-exit", "L3S", "L4"}},
	"density-compact-post-failure-utilization-ceiling": {`{"type":"number","exclusiveMinimum":0,"maximum":100}`, []int{7, 8}, []string{"contract-freeze", "phase-0-exit", "L3S", "L4", "L5"}},
	"audit-hot-retention":                              {`{"type":"integer","minimum":1}`, []int{3}, []string{"contract-freeze", "phase-0-exit", "L0C", "L3S"}},
	"audit-immutable-retention":                        {`{"type":"integer","minimum":1}`, []int{3}, []string{"contract-freeze", "phase-0-exit", "L3S", "L4", "L5"}},
	"maximum-regional-survival-window":                 {`{"type":"integer","minimum":1}`, []int{11, 12, 21}, []string{"contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"}},
}

var laterSelectionMappings = map[string]decisionImpactMapping{
	"artifact-and-evidence-signing": {[]int{14, 23}, []string{"phase-0-exit", "L0"}},
	"dns-implementation":            {[]int{15}, []string{"phase-0-exit", "L3S", "L4"}},
	"vpn-implementation":            {[]int{16}, []string{"phase-0-exit", "L3S", "L4"}},
	"operator-identity-provider":    {[]int{17}, []string{"phase-0-exit", "L3S", "L5"}},
	"regional-artifact-mirror":      {[]int{21}, []string{"phase-0-exit", "L3S", "L4"}},
	"arm64-host-image":              {[]int{22}, []string{"phase-0-exit", "L1R", "L4"}},
	"nats-n-minus-one-policy":       {[]int{22}, []string{"phase-0-exit", "L0C", "L3S"}},
}

const (
	invariantGapId            = "P1-DECISION-REGISTER-TOOLING-ENFORCEMENT"
	invariantGapStatus        = "open-independent-review-required"
	invariantGapInvariant     = "P0-01V enforces accepted-policy provenance, alias expansion, ownership-reference coverage, required ADR record fields, and acyclic executable dependencies."
	invariantGapEvidenceLimit = "Validator success proves only checked-in schema consistency; it does not establish external owner assignment or approval, measured evidence, ADR acceptance, or independent P0-01/P0-01V review."
	invariantGapPrerequisite  = "Independent P0-01/P0-01V review remains required before any acceptance claim."
)

var atomicPolicyFields = []string{"id", "status", "kind", "sourceAnchors"}

var ownershipFields = []string{"id", "stableOwnerId", "accountableApprovalRole", "assignmentStatus", "decisionScope", "authorityDependency"}

var decisionEntryFields = []string{"id", "slug", "title", "status", "ownerLane", "decisionAdrReferences", "sourceAnchors", "evidenceLocations", "controllingInputs", "openInputOwnershipReferences", "availableEvidence", "missingEvidence", "executableDependencies", "closureEvidence", "exitEvidence"}

// Validate mirrors DecisionReadinessValidator.Validate.
func (decisionReadinessValidator) Validate(packet *JsonObject, readiness *JsonObject) []string {
	var errors []string
	inputs := decisionIds(packet.Get("inputs"), "packet inputs", 21, &errors)
	decisionValidateQuestions(objectArray(packet.Get("questions")), &errors)
	decisionValidateInputRecords(objectArray(packet.Get("inputs")), inputMappings, &errors)
	selections := decisionIds(packet.Get("laterImplementationSelections"), "later selections", 7, &errors)
	if !stringSetEqualsList(selections, laterSelectionIds) {
		errors = append(errors, "later selections: canonical ID set required")
	}
	if later := objectArray(packet.Get("laterImplementationSelections")); later != nil {
		for _, node := range later.items {
			selection, isObject := node.(*JsonObject)
			if !isObject {
				continue
			}
			decisionRequire(selection, "later selection", []string{"id", "selection", "readinessStage", "requiredBeforeContractFreeze"}, &errors)
			if decisionText(selection.Get("readinessStage"), "later selection readinessStage", &errors) != "later-phase0-selection" {
				errors = append(errors, "later selection: invalid readiness stage")
			}
			if selection.Get("selection") != nil {
				errors = append(errors, "later selection: selection must remain null")
			}
			if value, ok := tryBool(selection.Get("requiredBeforeContractFreeze")); !ok || value {
				errors = append(errors, "later selection: must not block contract freeze")
			}
		}
	}
	decisionValidateSelectionRecords(objectArray(packet.Get("laterImplementationSelections")), laterSelectionMappings, &errors)
	atomic := make(map[string]bool, len(inputs))
	for id := range inputs {
		atomic[id] = true
	}
	for id := range selections {
		atomic[id] = true
	}

	policies := objectArray(packet.Get("atomicPolicyRecords"))
	if policies == nil || policies.Len() != 1 {
		errors = append(errors, "atomicPolicyRecords: exactly one accepted policy record is required")
	} else {
		for _, node := range policies.items {
			policy, isObject := node.(*JsonObject)
			if !isObject {
				errors = append(errors, "atomicPolicyRecords: records must be objects")
				continue
			}
			decisionRequire(policy, "accepted policy", atomicPolicyFields, &errors)
			if id := decisionText(policy.Get("id"), "accepted policy id", &errors); id != "" {
				atomic[id] = true
			}
			if decisionText(policy.Get("status"), "accepted policy status", &errors) != "accepted" {
				errors = append(errors, "accepted policy: status must be accepted")
			}
			if decisionText(policy.Get("kind"), "accepted policy kind", &errors) != "owner-policy" {
				errors = append(errors, "accepted policy: kind must be owner-policy")
			}
			decisionValidateAcceptedPolicyProvenance(policy.Get("sourceAnchors"), "accepted policy", &errors)
		}
	}

	aliases, hasAliases := packet.Get("controllingInputAliases").(*JsonObject)
	if !hasAliases {
		errors = append(errors, "controllingInputAliases: required object")
	}
	if hasAliases {
		for _, alias := range aliases.Keys() {
			if atomic[alias] {
				errors = append(errors, fmt.Sprintf("controllingInputAliases: alias %s collides with an atomic ID", alias))
			}
		}
	}
	expanded := map[string]map[string]bool{}
	if hasAliases {
		expanded = decisionExpandAliases(aliases, atomic, &errors)
	}
	decisionValidateRegisters(packet, inputs, selections, &errors)
	decisionValidateInvariantGap(objectArray(packet.Get("unvalidatedInvariantGaps")), &errors)
	decisionValidateReadinessContext(packet, readiness, &errors)
	decisionValidateAcceptedRegister(packet, readiness, &errors)

	var owners *JsonArray
	if register, ok := packet.Get("openInputOwnershipRegister").(*JsonObject); ok {
		owners = objectArray(register.Get("records"))
	}
	ownershipRegister, hasRegister := packet.Get("openInputOwnershipRegister").(*JsonObject)
	if !hasRegister ||
		decisionText(ownershipRegister.Get("status"), "ownership register status", &errors) != "unassigned-owner-gaps" ||
		decisionText(ownershipRegister.Get("assignmentPrerequisite"), "ownership register assignmentPrerequisite", &errors) == "" {
		errors = append(errors, "ownership register: invalid status or prerequisite")
	}
	ownerIds := decisionObjectIds(owners, "ownership records", &errors, ownershipFields, -1)
	unresolved := make(map[string]bool, len(inputs)+len(selections))
	for id := range inputs {
		unresolved[id] = true
	}
	for id := range selections {
		unresolved[id] = true
	}
	if !stringSetEquals(ownerIds, unresolved) {
		errors = append(errors, "ownership records: must exactly cover every unresolved atomic input")
	}
	if owners != nil {
		for _, node := range owners.items {
			owner, isObject := node.(*JsonObject)
			if !isObject {
				continue
			}
			idDisplay := nodeDisplay(owner.Get("id"))
			for _, field := range ownershipFields[1:] {
				decisionText(owner.Get(field), fmt.Sprintf("ownership %s %s", idDisplay, field), &errors)
			}
			assigned := decisionText(owner.Get("assignmentStatus"), fmt.Sprintf("ownership %s assignmentStatus", idDisplay), &errors)
			stable := decisionText(owner.Get("stableOwnerId"), fmt.Sprintf("ownership %s stableOwnerId", idDisplay), &errors)
			if assigned != "unassigned" && assigned != "assigned" {
				errors = append(errors, fmt.Sprintf("ownership %s: invalid assignment status", idDisplay))
			}
			if assigned == "unassigned" && stable != "unassigned" {
				errors = append(errors, fmt.Sprintf("ownership %s: unassigned requires stableOwnerId unassigned", idDisplay))
			}
			if assigned == "assigned" && (stable == "unassigned" || stable == "") {
				errors = append(errors, fmt.Sprintf("ownership %s: assigned requires named stable owner", idDisplay))
			}
		}
	}

	entries := objectArray(readiness.Get("entries"))
	if entries == nil || entries.Len() != 24 {
		return errors
	}
	graph := map[int]map[int]bool{}
	for _, node := range entries.items {
		entry, isObject := node.(*JsonObject)
		if !isObject {
			errors = append(errors, "entries: every ADR record must be an object")
			continue
		}
		id := entryInt(entry, "id")
		decisionRequire(entry, fmt.Sprintf("ADR %d", id), decisionEntryFields, &errors)
		for _, field := range []string{"slug", "title", "ownerLane"} {
			decisionText(entry.Get(field), fmt.Sprintf("ADR %d %s", id, field), &errors)
		}
		status := decisionText(entry.Get("status"), fmt.Sprintf("ADR %d status", id), &errors)
		if status != "draft-ready" && status != "owner-input-required" && status != "evidence-required" {
			errors = append(errors, fmt.Sprintf("ADR %d: status is not an open readiness state", id))
		}
		refs := decisionStrings(entry.Get("decisionAdrReferences"), fmt.Sprintf("ADR %d decisionAdrReferences", id), &errors)
		if len(refs) != 1 || refs[0] != fmt.Sprintf("ADR-%04d", id) {
			errors = append(errors, fmt.Sprintf("ADR %d: decision ADR reference must be its canonical ADR id", id))
		}
		sources := decisionStrings(entry.Get("sourceAnchors"), fmt.Sprintf("ADR %d sourceAnchors", id), &errors)
		locations := decisionStrings(entry.Get("evidenceLocations"), fmt.Sprintf("ADR %d evidenceLocations", id), &errors)
		if !anyIntersection(sources, locations) {
			errors = append(errors, fmt.Sprintf("ADR %d: source anchor must be an evidence location", id))
		}
		errors = Validation.ValidateLocalAnchors(objectArray(entry.Get("sourceAnchors")), fmt.Sprintf("ADR %d source anchor", id), errors)
		errors = Validation.ValidateLocalAnchors(objectArray(entry.Get("evidenceLocations")), fmt.Sprintf("ADR %d evidence location", id), errors)
		for _, field := range []string{"availableEvidence", "missingEvidence", "exitEvidence"} {
			decisionStrings(entry.Get(field), fmt.Sprintf("ADR %d %s", id, field), &errors)
		}

		controls := decisionStrings(entry.Get("controllingInputs"), fmt.Sprintf("ADR %d controllingInputs", id), &errors)
		expected := map[string]bool{}
		for _, control := range controls {
			if values, ok := expanded[control]; ok {
				for value := range values {
					if ownerIds[value] {
						expected[value] = true
					}
				}
			} else if atomic[control] && ownerIds[control] {
				expected[control] = true
			} else {
				errors = append(errors, fmt.Sprintf("ADR %d: unknown controlling input %s", id, control))
			}
		}
		ownership := decisionStrings(entry.Get("openInputOwnershipReferences"), fmt.Sprintf("ADR %d openInputOwnershipReferences", id), &errors)
		if !stringSliceSetEquals(ownership, expected) {
			errors = append(errors, fmt.Sprintf("ADR %d: ownership references must equal controlling-input expansion", id))
		}
		for _, value := range ownership {
			if !ownerIds[value] {
				errors = append(errors, fmt.Sprintf("ADR %d: ownership reference has no accountable record", id))
			}
		}
		if status == "owner-input-required" && len(expected) == 0 {
			errors = append(errors, fmt.Sprintf("ADR %d: owner-input-required needs unresolved controlling inputs", id))
		}
		if status == "draft-ready" && len(expected) != 0 {
			errors = append(errors, fmt.Sprintf("ADR %d: draft-ready cannot retain unresolved inputs", id))
		}

		executable := decisionIntegerValues(entry.Get("executableDependencies"), fmt.Sprintf("ADR %d executableDependencies", id), &errors)
		executableSet := map[int]bool{}
		executableInvalid := false
		for _, target := range executable {
			if target < 1 || target > 24 || target == id || executableSet[target] {
				executableInvalid = true
			}
			executableSet[target] = true
		}
		if executableInvalid {
			errors = append(errors, fmt.Sprintf("ADR %d: executable dependencies must be unique existing non-self ADR ids", id))
		}
		graph[id] = executableSet
		closure := decisionIntegerValues(entry.Get("closureEvidence"), fmt.Sprintf("ADR %d closureEvidence", id), &errors)
		closureSet := map[int]bool{}
		closureInvalid := false
		for _, target := range closure {
			if target < 1 || target > 24 || closureSet[target] {
				closureInvalid = true
			}
			closureSet[target] = true
		}
		if closureInvalid {
			errors = append(errors, fmt.Sprintf("ADR %d: closure evidence must be unique ADR evidence ids, never executable edges", id))
		}
		for _, target := range executable {
			if closureSet[target] {
				errors = append(errors, fmt.Sprintf("ADR %d: closure evidence cannot also be executable dependency", id))
				break
			}
		}
	}
	if decisionHasCycle(graph) {
		errors = append(errors, "executableDependencies: graph must be acyclic")
	}
	decisionValidateInputReadinessMappings(entries, expanded, &errors)
	return errors
}

func decisionValidateQuestions(questions *JsonArray, errors *[]string) {
	if questions == nil {
		return
	}
	for _, item := range questions.items {
		question, isObject := item.(*JsonObject)
		if !isObject {
			continue
		}
		id := entryInt(question, "id")
		expected, hasExpected := questionMappings[id]
		if !hasExpected {
			*errors = append(*errors, fmt.Sprintf("question %d: canonical impact mapping required", id))
			continue
		}
		decisionValidateImpactMapping(question, fmt.Sprintf("question %d", id), expected.Adrs, expected.Gates, errors)
	}
}

func decisionValidateInputRecords(records *JsonArray, mappings map[string]decisionInputMapping, errors *[]string) {
	if records == nil {
		return
	}
	for _, item := range records.items {
		record, isObject := item.(*JsonObject)
		if !isObject {
			continue
		}
		id := decisionText(record.Get("id"), "input id", errors)
		mapping, hasMapping := mappings[id]
		if id == "" || !hasMapping {
			*errors = append(*errors, fmt.Sprintf("input %s: canonical impact mapping required", id))
			continue
		}
		expectedValidation, parseErr := parseJSONNode([]byte(mapping.Validation))
		if parseErr != nil || !deepEqualJSON(record.Get("validation"), expectedValidation) {
			*errors = append(*errors, fmt.Sprintf("input %s: canonical validation shape required", id))
		}
		decisionValidateImpactMapping(record, fmt.Sprintf("input %s", id), mapping.Adrs, mapping.Gates, errors)
	}
}

func decisionValidateSelectionRecords(records *JsonArray, mappings map[string]decisionImpactMapping, errors *[]string) {
	if records == nil {
		return
	}
	for _, item := range records.items {
		record, isObject := item.(*JsonObject)
		if !isObject {
			continue
		}
		id := decisionText(record.Get("id"), "input id", errors)
		mapping, hasMapping := mappings[id]
		if id == "" || !hasMapping {
			*errors = append(*errors, fmt.Sprintf("input %s: canonical impact mapping required", id))
			continue
		}
		decisionValidateImpactMapping(record, fmt.Sprintf("input %s", id), mapping.Adrs, mapping.Gates, errors)
	}
}

func decisionValidateImpactMapping(record *JsonObject, where string, adrs []int, gates []string, errors *[]string) {
	if !intSlicesEqual(decisionIntegerValues(record.Get("impactedAdrs"), where+" impactedAdrs", errors), adrs) {
		*errors = append(*errors, fmt.Sprintf("%s: canonical impactedAdrs required", where))
	}
	if !stringSlicesEqual(decisionStrings(record.Get("impactedGates"), where+" impactedGates", errors), gates) {
		*errors = append(*errors, fmt.Sprintf("%s: canonical impactedGates required", where))
	}
}

func decisionValidateInvariantGap(gaps *JsonArray, errors *[]string) {
	if gaps == nil || gaps.Len() != 1 {
		*errors = append(*errors, "unvalidatedInvariantGaps: exact required record missing")
		return
	}
	gap, isObject := gaps.Get(0).(*JsonObject)
	if !isObject || gap.Len() != 6 {
		*errors = append(*errors, "unvalidatedInvariantGaps: exact required record missing")
		return
	}
	decisionRequire(gap, "unvalidatedInvariantGaps",
		[]string{"id", "status", "invariant", "currentEvidenceLimit", "requiredFutureExactPaths", "prerequisite"}, errors)
	paths, isPaths := gap.Get("requiredFutureExactPaths").(*JsonArray)
	if decisionText(gap.Get("id"), "unvalidatedInvariantGaps id", errors) != invariantGapId ||
		decisionText(gap.Get("status"), "unvalidatedInvariantGaps status", errors) != invariantGapStatus ||
		decisionText(gap.Get("invariant"), "unvalidatedInvariantGaps invariant", errors) != invariantGapInvariant ||
		decisionText(gap.Get("currentEvidenceLimit"), "unvalidatedInvariantGaps currentEvidenceLimit", errors) != invariantGapEvidenceLimit ||
		!isPaths || paths.Len() != 0 ||
		decisionText(gap.Get("prerequisite"), "unvalidatedInvariantGaps prerequisite", errors) != invariantGapPrerequisite {
		*errors = append(*errors, "unvalidatedInvariantGaps: independent-review provenance required")
	}
}

func decisionValidateInputReadinessMappings(entries *JsonArray, expanded map[string]map[string]bool, errors *[]string) {
	validate := func(input string, expected []int) {
		actual := map[int]bool{}
		for _, item := range entries.items {
			entry, isObject := item.(*JsonObject)
			if !isObject {
				continue
			}
			for _, control := range decisionStrings(entry.Get("controllingInputs"), fmt.Sprintf("input %s readiness mapping", input), errors) {
				if control == input {
					actual[entryInt(entry, "id")] = true
				} else if values, ok := expanded[control]; ok && values[input] {
					actual[entryInt(entry, "id")] = true
				}
			}
		}
		for _, adr := range expected {
			if !actual[adr] {
				*errors = append(*errors, fmt.Sprintf("input %s: impacted ADR lacks readiness mapping", input))
				return
			}
		}
	}
	for _, input := range sortedInputMappingKeys(inputMappings) {
		validate(input, inputMappings[input].Adrs)
	}
	for _, input := range sortedImpactMappingKeys(laterSelectionMappings) {
		validate(input, laterSelectionMappings[input].Adrs)
	}
}

func sortedInputMappingKeys(mappings map[string]decisionInputMapping) []string {
	keys := make([]string, 0, len(mappings))
	for key := range mappings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedImpactMappingKeys(mappings map[string]decisionImpactMapping) []string {
	keys := make([]string, 0, len(mappings))
	for key := range mappings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func decisionExpandAliases(aliases *JsonObject, atomic map[string]bool, errors *[]string) map[string]map[string]bool {
	result := map[string]map[string]bool{}
	visiting := map[string]bool{}
	var expand func(name string) map[string]bool
	empty := func() map[string]bool { return map[string]bool{} }
	expand = func(name string) map[string]bool {
		if cached, ok := result[name]; ok {
			return cached
		}
		if visiting[name] {
			*errors = append(*errors, fmt.Sprintf("controllingInputAliases: cyclic alias %s", name))
			return empty()
		}
		visiting[name] = true
		values, isValues := aliases.Get(name).(*JsonArray)
		if !isValues || values.Len() == 0 {
			*errors = append(*errors, fmt.Sprintf("controllingInputAliases: %s must have a non-empty array", name))
			delete(visiting, name)
			return empty()
		}
		resolved := map[string]bool{}
		for _, value := range decisionStrings(values, fmt.Sprintf("controllingInputAliases %s", name), errors) {
			if value == name {
				*errors = append(*errors, fmt.Sprintf("controllingInputAliases: %s cannot reference itself", name))
			} else if atomic[value] {
				if resolved[value] {
					*errors = append(*errors, fmt.Sprintf("controllingInputAliases: %s expands duplicate %s", name, value))
				} else {
					resolved[value] = true
				}
			} else if aliases.Has(value) {
				for item := range expand(value) {
					if resolved[item] {
						*errors = append(*errors, fmt.Sprintf("controllingInputAliases: %s expands duplicate %s", name, item))
					} else {
						resolved[item] = true
					}
				}
			} else {
				*errors = append(*errors, fmt.Sprintf("controllingInputAliases: %s references unknown %s", name, value))
			}
		}
		delete(visiting, name)
		result[name] = resolved
		return resolved
	}
	for _, alias := range aliases.Keys() {
		if strings.TrimSpace(alias) == "" {
			*errors = append(*errors, "controllingInputAliases: alias names must be non-empty")
		} else {
			expand(alias)
		}
	}
	return result
}

func decisionValidateRegisters(packet *JsonObject, inputs map[string]bool, selections map[string]bool, errors *[]string) {
	register, isRegister := packet.Get("openInputRegister").(*JsonObject)
	if !isRegister {
		*errors = append(*errors, "openInputRegister: required object")
		return
	}
	if decisionText(register.Get("status"), "openInputRegister status", errors) != "open-no-defaults" {
		*errors = append(*errors, "openInputRegister: invalid status")
	}
	if !stringListSetEqualsList(decisionStrings(register.Get("sourceAnchors"), "openInputRegister sourceAnchors", errors), openInputProvenance) {
		*errors = append(*errors, "openInputRegister: canonical source anchors required")
	}
	*errors = Validation.ValidateLocalAnchors(objectArray(register.Get("sourceAnchors")), "openInputRegister", *errors)
	planningExpected := map[string]bool{}
	for id := range inputs {
		if id == "team-size" || id == "first-production-date" {
			planningExpected[id] = true
		}
	}
	if !stringSliceSetEquals(decisionStrings(register.Get("planning"), "openInputRegister planning", errors), planningExpected) {
		*errors = append(*errors, "openInputRegister: planning parity failure")
	}
	measurableExpected := map[string]bool{}
	for id := range inputs {
		if id != "team-size" && id != "first-production-date" {
			measurableExpected[id] = true
		}
	}
	if !stringSliceSetEquals(decisionStrings(register.Get("measurableQualification"), "openInputRegister measurableQualification", errors), measurableExpected) {
		*errors = append(*errors, "openInputRegister: measurable parity failure")
	}
	if !stringSliceSetEquals(decisionStrings(register.Get("laterSelections"), "openInputRegister laterSelections", errors), selections) {
		*errors = append(*errors, "openInputRegister: later selections parity failure")
	}
}

func decisionValidateReadinessContext(packet *JsonObject, readiness *JsonObject, errors *[]string) {
	if evidence := decisionText(readiness.Get("normalizationEvidence"), "readiness normalizationEvidence", errors); evidence != "" {
		anchors := &JsonArray{items: []any{evidence}}
		*errors = Validation.ValidateLocalAnchors(anchors, "readiness normalizationEvidence", *errors)
	}
	lanes := decisionStrings(readiness.Get("canonicalOwnerLanes"), "readiness canonicalOwnerLanes", errors)
	if !stringSliceSetEquals(lanes, AdrReadinessCommand.Lanes()) {
		*errors = append(*errors, "readiness canonicalOwnerLanes: exact canonical set required")
	}
	if decisionText(readiness.Get("normalizationEvidence"), "readiness normalizationEvidence", errors) != "docs/architecture/orchestrator.md:83-105" {
		*errors = append(*errors, "readiness normalizationEvidence: canonical decision context required")
	}
	left, _ := readiness.Get("openInputs").(*JsonObject)
	right, _ := packet.Get("openInputRegister").(*JsonObject)
	var leftPlanning, rightPlanning []string
	var leftMeasurable, rightMeasurable []string
	var leftSelections, rightSelections []string
	if left != nil {
		leftPlanning = decisionStrings(left.Get("planning"), "readiness openInputs planning", errors)
		leftMeasurable = decisionStrings(left.Get("measurableQualification"), "readiness openInputs measurableQualification", errors)
		leftSelections = decisionStrings(left.Get("laterSelections"), "readiness openInputs laterSelections", errors)
	}
	if right != nil {
		rightPlanning = decisionStrings(right.Get("planning"), "packet openInputRegister planning", errors)
		rightMeasurable = decisionStrings(right.Get("measurableQualification"), "packet openInputRegister measurableQualification", errors)
		rightSelections = decisionStrings(right.Get("laterSelections"), "packet openInputRegister laterSelections", errors)
	}
	parityFailure := left == nil || right == nil
	if !parityFailure {
		if decisionText(left.Get("status"), "readiness openInputs status", errors) != decisionText(right.Get("status"), "packet openInputRegister status", errors) ||
			!stringSlicesEqual(leftPlanning, rightPlanning) ||
			!stringSlicesEqual(leftMeasurable, rightMeasurable) ||
			!stringSlicesEqual(leftSelections, rightSelections) {
			parityFailure = true
		}
	}
	if parityFailure {
		*errors = append(*errors, "readiness openInputs: packet parity failure")
	}
	if left == nil ||
		decisionText(left.Get("source"), "readiness openInputs source", errors) != "docs/decisions/owner-decision-packet.json:51-122" ||
		decisionText(left.Get("ownershipRegister"), "readiness openInputs ownershipRegister", errors) != "docs/decisions/owner-decision-packet.json:91-123" ||
		decisionText(left.Get("unvalidatedInvariantGap"), "readiness openInputs unvalidatedInvariantGap", errors) != "docs/decisions/owner-decision-packet.json:125-127" {
		*errors = append(*errors, "readiness openInputs: mandated provenance paths required")
	}
	if left == nil ||
		decisionText(left.Get("source"), "readiness openInputs source", errors) != "docs/decisions/owner-decision-packet.json:51-122" ||
		decisionText(left.Get("ownershipRegister"), "readiness openInputs ownershipRegister", errors) != "docs/decisions/owner-decision-packet.json:91-123" ||
		decisionText(left.Get("unvalidatedInvariantGap"), "readiness openInputs unvalidatedInvariantGap", errors) != "docs/decisions/owner-decision-packet.json:125-127" {
		*errors = append(*errors, "readiness openInputs: mandated provenance paths required")
	}
}

func decisionValidateAcceptedRegister(packet *JsonObject, readiness *JsonObject, errors *[]string) {
	left, _ := packet.Get("acceptedDecisionRegister").(*JsonObject)
	right, _ := readiness.Get("acceptedDecisionRegister").(*JsonObject)
	var leftAnchors, rightAnchors []string
	if left != nil {
		leftAnchors = decisionStrings(left.Get("sourceAnchors"), "packet acceptedDecisionRegister sourceAnchors", errors)
	}
	if right != nil {
		rightAnchors = decisionStrings(right.Get("sourceAnchors"), "readiness acceptedDecisionRegister sourceAnchors", errors)
	}
	parityFailure := left == nil || right == nil
	if !parityFailure {
		if decisionText(left.Get("status"), "packet acceptedDecisionRegister status", errors) != decisionText(right.Get("status"), "readiness acceptedDecisionRegister status", errors) ||
			decisionText(left.Get("acceptedOn"), "packet acceptedDecisionRegister acceptedOn", errors) != decisionText(right.Get("acceptedOn"), "readiness acceptedDecisionRegister acceptedOn", errors) ||
			decisionText(left.Get("authority"), "packet acceptedDecisionRegister authority", errors) != decisionText(right.Get("authority"), "readiness acceptedDecisionRegister authority", errors) ||
			!stringSlicesEqual(leftAnchors, rightAnchors) {
			parityFailure = true
		}
	}
	if parityFailure {
		*errors = append(*errors, "acceptedDecisionRegister: packet/readiness parity failure")
	}
	if left != nil {
		if decisionText(left.Get("status"), "acceptedDecisionRegister status", errors) != "accepted-owner-policy" {
			*errors = append(*errors, "acceptedDecisionRegister: invalid status")
		}
		decisionValidateAcceptedPolicyProvenance(left.Get("sourceAnchors"), "packet acceptedDecisionRegister", errors)
	}
	if right != nil {
		decisionValidateAcceptedPolicyProvenance(right.Get("sourceAnchors"), "readiness acceptedDecisionRegister", errors)
	}
}

func decisionValidateAcceptedPolicyProvenance(node any, where string, errors *[]string) {
	anchors := decisionStrings(node, where+" sourceAnchors", errors)
	if !stringListSetEqualsList(anchors, acceptedPolicyProvenance) {
		*errors = append(*errors, fmt.Sprintf("%s: canonical accepted-policy provenance required", where))
	}
	*errors = Validation.ValidateLocalAnchors(objectArray(node), where, *errors)
}

func decisionIds(node any, name string, count int, errors *[]string) map[string]bool {
	return decisionObjectIds(objectArray(node), name, errors, []string{"id"}, count)
}

func decisionIntegerIds(node any, name string, count int, errors *[]string) map[int]bool {
	values := decisionIntegerValues(node, name, errors)
	valid := len(values) == count
	ordered := make([]int, 0, len(values))
	ordered = append(ordered, values...)
	sort.Ints(ordered)
	for index := range ordered {
		if ordered[index] != index+1 {
			valid = false
		}
	}
	if !valid {
		*errors = append(*errors, fmt.Sprintf("%s: exact ordered IDs required", name))
	}
	result := map[int]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}

func decisionObjectIds(array *JsonArray, name string, errors *[]string, required []string, count int) map[string]bool {
	result := map[string]bool{}
	if array == nil {
		*errors = append(*errors, fmt.Sprintf("%s: required array", name))
		return result
	}
	if count >= 0 && array.Len() != count {
		*errors = append(*errors, fmt.Sprintf("%s: expected %d", name, count))
	}
	for _, node := range array.items {
		object, isObject := node.(*JsonObject)
		if !isObject {
			*errors = append(*errors, fmt.Sprintf("%s: every item must be an object", name))
			continue
		}
		decisionRequire(object, name, required, errors)
		if id := decisionText(object.Get("id"), name+" id", errors); id != "" {
			if result[id] {
				*errors = append(*errors, fmt.Sprintf("%s: duplicate id %s", name, id))
			}
			result[id] = true
		}
	}
	return result
}

func decisionRequire(value *JsonObject, where string, fields []string, errors *[]string) {
	for _, field := range fields {
		if !value.Has(field) {
			*errors = append(*errors, fmt.Sprintf("%s: missing %s", where, field))
		}
	}
}

func decisionText(value any, where string, errors *[]string) string {
	if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
		return text
	}
	*errors = append(*errors, fmt.Sprintf("%s: non-empty string required", where))
	return ""
}

func decisionStrings(node any, where string, errors *[]string) []string {
	array, isArray := node.(*JsonArray)
	if !isArray {
		*errors = append(*errors, fmt.Sprintf("%s: array required", where))
		return nil
	}
	var values []string
	distinct := map[string]bool{}
	for _, value := range array.items {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			values = append(values, text)
			distinct[text] = true
		} else {
			*errors = append(*errors, fmt.Sprintf("%s: non-empty strings required", where))
		}
	}
	if len(distinct) != len(values) {
		*errors = append(*errors, fmt.Sprintf("%s: duplicate values", where))
	}
	return values
}

func decisionIntegerValues(node any, where string, errors *[]string) []int {
	array, isArray := node.(*JsonArray)
	if !isArray {
		*errors = append(*errors, fmt.Sprintf("%s: array required", where))
		return nil
	}
	var values []int
	for _, value := range array.items {
		if number, ok := tryInt(value); ok {
			values = append(values, number)
		} else {
			*errors = append(*errors, fmt.Sprintf("%s: integer values required", where))
		}
	}
	return values
}

func decisionHasCycle(graph map[int]map[int]bool) bool {
	state := map[int]int{}
	var visit func(value int) bool
	visit = func(value int) bool {
		if state[value] == 1 {
			return true
		}
		if state[value] == 2 {
			return false
		}
		state[value] = 1
		cycle := false
		for target := range graph[value] {
			if visit(target) {
				cycle = true
				break
			}
		}
		state[value] = 2
		return cycle
	}
	for key := range graph {
		if visit(key) {
			return true
		}
	}
	return false
}

func intSlicesEqual(actual, expected []int) bool {
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

func anyIntersection(left, right []string) bool {
	for _, value := range left {
		for _, other := range right {
			if value == other {
				return true
			}
		}
	}
	return false
}

func stringSetEqualsList(values map[string]bool, expected []string) bool {
	expectedSet := map[string]bool{}
	for _, value := range expected {
		expectedSet[value] = true
	}
	return stringSetEquals(values, expectedSet)
}

func stringListSetEqualsList(values []string, expected []string) bool {
	set := map[string]bool{}
	for _, value := range values {
		set[value] = true
	}
	return stringSetEqualsList(set, expected)
}

func stringSliceSetEquals(values []string, expected map[string]bool) bool {
	set := map[string]bool{}
	for _, value := range values {
		set[value] = true
	}
	return stringSetEquals(set, expected)
}

func stringSetEquals(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}
