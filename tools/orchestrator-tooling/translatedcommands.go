// Port of tools/TerraScale.Orchestrator.Tooling/TranslatedCommands.cs: the
// shared Validation helpers plus the adr-readiness and owner-decisions
// command validators.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
