// Turns TRX test results plus declared artifacts into the CI result manifest.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// CiResultManifestOptions holds the parsed ci-result-manifest options.
type CiResultManifestOptions struct {
	Job        string
	PlanDigest string
	Output     string
	TrxFiles   []string
	Artifacts  []CiResultArtifactOption
}

// CiResultArtifactOption is one declared artifact.
type CiResultArtifactOption struct {
	Artifact     string
	Architecture string
	Path         string
	Entrypoints  []string
}

type ciResultManifestCommand struct{}

// CiResultManifestCommand implements the ci-result-manifest command.
var CiResultManifestCommand = ciResultManifestCommand{}

const (
	ciMaximumTrxFiles = 32
	ciMaximumTrxBytes = int64(32) * 1024 * 1024
	ciMaximumTests    = 1_000_000
)

const trxNamespace = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"

var ciCounterNames = []string{
	"total", "executed", "passed", "failed", "error", "timeout", "aborted", "inconclusive",
	"passedButRunAborted", "notRunnable", "notExecuted", "disconnected", "warning", "completed",
	"inProgress", "pending",
}

// ciResultManifestDocument is the written manifest document.
type ciResultManifestDocument struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	Job               string                  `json:"job"`
	PlanDigest        string                  `json:"planDigest"`
	Succeeded         bool                    `json:"succeeded"`
	RequiredTestSkips int                     `json:"requiredTestSkips"`
	Artifacts         []ciResultArtifactEntry `json:"artifacts"`
}

type ciResultArtifactEntry struct {
	Artifact     string   `json:"artifact"`
	Architecture string   `json:"architecture"`
	Path         string   `json:"path"`
	Entrypoints  []string `json:"entrypoints"`
}

func (ciResultManifestCommand) Run(arguments []string) (int, error) {
	options, err := CiResultManifestCommand.Parse(arguments)
	if err != nil {
		return 0, err
	}
	requiredTestSkips := 0
	tests := 0
	for _, path := range options.TrxFiles {
		total, skipped, err := CiResultManifestCommand.ReadTrx(path)
		if err != nil {
			return 0, err
		}
		if total > ciMaximumTests-tests || skipped > ciMaximumTests-requiredTestSkips {
			return 0, newToolValidationException([]string{"TRX totals exceed the CI result manifest bound"})
		}
		tests += total
		requiredTestSkips += skipped
	}

	output, err := filepath.Abs(options.Output)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return 0, err
	}
	artifacts := make([]ciResultArtifactEntry, 0, len(options.Artifacts))
	for _, artifact := range options.Artifacts {
		entrypoints := artifact.Entrypoints
		if entrypoints == nil {
			entrypoints = []string{}
		}
		artifacts = append(artifacts, ciResultArtifactEntry{
			Artifact:     artifact.Artifact,
			Architecture: artifact.Architecture,
			Path:         artifact.Path,
			Entrypoints:  entrypoints,
		})
	}
	document := ciResultManifestDocument{
		SchemaVersion:     2,
		Job:               options.Job,
		PlanDigest:        options.PlanDigest,
		Succeeded:         true,
		RequiredTestSkips: requiredTestSkips,
		Artifacts:         artifacts,
	}
	var content bytes.Buffer
	encoder := json.NewEncoder(&content)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return 0, err
	}
	serialized := bytes.TrimSuffix(content.Bytes(), []byte("\n"))
	if err := os.WriteFile(output, serialized, 0o644); err != nil {
		return 0, err
	}
	if runtime.GOOS == "linux" {
		if err := os.Chmod(output, 0o600); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

// Parse parses and validates the command options.
func (ciResultManifestCommand) Parse(arguments []string) (CiResultManifestOptions, error) {
	job := ""
	planDigest := ""
	output := ""
	jobSet, planDigestSet, outputSet := false, false, false
	var trx []string
	var artifacts []CiResultArtifactOption
	for index := 0; index < len(arguments); index += 2 {
		if index+1 == len(arguments) {
			return CiResultManifestOptions{}, newToolValidationException([]string{"ci-result-manifest options require values"})
		}
		value := arguments[index+1]
		switch {
		case arguments[index] == "--job" && !jobSet:
			job, jobSet = value, true
		case arguments[index] == "--plan-digest" && !planDigestSet:
			planDigest, planDigestSet = value, true
		case arguments[index] == "--output" && !outputSet:
			output, outputSet = value, true
		case arguments[index] == "--trx" && len(trx) < ciMaximumTrxFiles:
			absolute, err := filepath.Abs(value)
			if err != nil {
				return CiResultManifestOptions{}, err
			}
			trx = append(trx, absolute)
		case arguments[index] == "--artifact" && len(artifacts) < 2:
			artifact, err := parseCiArtifact(value)
			if err != nil {
				return CiResultManifestOptions{}, err
			}
			artifacts = append(artifacts, artifact)
		default:
			return CiResultManifestOptions{}, newToolValidationException([]string{
				"ci-result-manifest contains an unknown, duplicate, or excessive option"})
		}
	}

	var validationErrors []string
	if !ciValidJob(job) {
		validationErrors = append(validationErrors, "ci-result-manifest job is invalid")
	}
	if !ciDigest(planDigest) {
		validationErrors = append(validationErrors, "ci-result-manifest plan digest is invalid")
	}
	if strings.TrimSpace(output) == "" {
		validationErrors = append(validationErrors, "ci-result-manifest output is required")
	}
	architectures := map[string]bool{}
	paths := map[string]bool{}
	overlapping := false
	for _, left := range artifacts {
		if architectures[left.Architecture] {
			overlapping = true
		}
		architectures[left.Architecture] = true
		if paths[left.Path] {
			overlapping = true
		}
		paths[left.Path] = true
	}
	for leftIndex := range artifacts {
		for rightIndex := range artifacts {
			if leftIndex != rightIndex && strings.HasPrefix(artifacts[rightIndex].Path, artifacts[leftIndex].Path+"/") {
				overlapping = true
			}
		}
	}
	if overlapping {
		validationErrors = append(validationErrors, "ci-result-manifest artifact roots must be distinct and non-overlapping")
	}
	if len(validationErrors) != 0 {
		return CiResultManifestOptions{}, newToolValidationException(validationErrors)
	}
	return CiResultManifestOptions{
		Job:        job,
		PlanDigest: planDigest,
		Output:     output,
		TrxFiles:   trx,
		Artifacts:  artifacts,
	}, nil
}

func parseCiArtifact(value string) (CiResultArtifactOption, error) {
	fields := strings.Split(value, "|")
	if len(fields) != 4 {
		return CiResultArtifactOption{}, newToolValidationException([]string{"ci-result-manifest artifact declaration is invalid"})
	}
	artifact, architecture, path, declaredEntrypoints := fields[0], fields[1], fields[2], fields[3]
	if !ciArtifactId(artifact) ||
		(architecture != "Any" && architecture != "LinuxX64" && architecture != "LinuxArm64") ||
		!ciRelativePath(path) {
		return CiResultArtifactOption{}, newToolValidationException([]string{"ci-result-manifest artifact declaration is invalid"})
	}
	var entrypoints []string
	if len(declaredEntrypoints) != 0 {
		entrypoints = strings.Split(declaredEntrypoints, ",")
	}
	distinct := map[string]bool{}
	duplicateEntry := false
	for _, entrypoint := range entrypoints {
		if distinct[entrypoint] {
			duplicateEntry = true
		}
		distinct[entrypoint] = true
		if !ciRelativePath(entrypoint) {
			return CiResultArtifactOption{}, newToolValidationException([]string{"ci-result-manifest artifact entrypoints are invalid"})
		}
	}
	ordered := true
	for index := 1; index < len(entrypoints); index++ {
		if entrypoints[index-1] > entrypoints[index] {
			ordered = false
		}
	}
	if (architecture == "Any" && len(entrypoints) != 0) ||
		(architecture != "Any" && (len(entrypoints) < 1 || len(entrypoints) > 8)) ||
		duplicateEntry || !ordered {
		return CiResultArtifactOption{}, newToolValidationException([]string{"ci-result-manifest artifact entrypoints are invalid"})
	}
	return CiResultArtifactOption{
		Artifact:     artifact,
		Architecture: architecture,
		Path:         path,
		Entrypoints:  entrypoints,
	}, nil
}

type trxDocument struct {
	XMLName       xml.Name
	Results       []trxResults       `xml:"http://microsoft.com/schemas/VisualStudio/TeamTest/2010 Results"`
	ResultSummary []trxResultSummary `xml:"http://microsoft.com/schemas/VisualStudio/TeamTest/2010 ResultSummary"`
}

type trxResults struct {
	UnitTestResults []trxUnitTestResult `xml:"http://microsoft.com/schemas/VisualStudio/TeamTest/2010 UnitTestResult"`
}

type trxUnitTestResult struct {
	ExecutionId string `xml:"executionId,attr"`
	TestName    string `xml:"testName,attr"`
	Outcome     string `xml:"outcome,attr"`
}

type trxResultSummary struct {
	Outcome  string        `xml:"outcome,attr"`
	Counters []trxCounters `xml:"http://microsoft.com/schemas/VisualStudio/TeamTest/2010 Counters"`
}

type trxCounters struct {
	Attributes []xml.Attr `xml:",any,attr"`
}

// ReadTrx reads one TRX file and returns (total, skipped).
func (ciResultManifestCommand) ReadTrx(path string) (int, int, error) {
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > ciMaximumTrxBytes {
		return 0, 0, newToolValidationException([]string{fmt.Sprintf("TRX result is missing, empty, or oversized: %s", path)})
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, newToolValidationException([]string{fmt.Sprintf("TRX result is missing, empty, or oversized: %s", path)})
	}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	decoder.Strict = true
	for {
		token, tokenErr := decoder.Token()
		if errors.Is(tokenErr, io.EOF) {
			break
		}
		if tokenErr != nil {
			return 0, 0, newToolValidationException([]string{fmt.Sprintf("TRX result is invalid XML: %s", tokenErr.Error())})
		}
		if directive, ok := token.(xml.Directive); ok {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(directive))), "DOCTYPE") {
				return 0, 0, newToolValidationException([]string{
					"TRX result is invalid XML: DTD is prohibited in this XML document."})
			}
		}
	}

	var document trxDocument
	if err := xml.Unmarshal(content, &document); err != nil {
		return 0, 0, newToolValidationException([]string{fmt.Sprintf("TRX result is invalid XML: %s", err.Error())})
	}

	var results *trxResults
	var summary *trxResultSummary
	var counters *trxCounters
	if len(document.Results) == 1 {
		results = &document.Results[0]
	}
	if len(document.ResultSummary) == 1 {
		summary = &document.ResultSummary[0]
	}
	if summary != nil && len(summary.Counters) == 1 {
		counters = &summary.Counters[0]
	}
	counterNames := make([]string, 0, len(counters.Attributes))
	if counters != nil {
		for _, attribute := range counters.Attributes {
			counterNames = append(counterNames, attribute.Name.Local)
		}
	}
	sortedCounterNames := append([]string(nil), ciCounterNames...)
	sort.Strings(sortedCounterNames)
	sort.Strings(counterNames)
	counterNamesMatch := len(counterNames) == len(sortedCounterNames)
	if counterNamesMatch {
		for index := range counterNames {
			if counterNames[index] != sortedCounterNames[index] {
				counterNamesMatch = false
				break
			}
		}
	}
	if document.XMLName.Space != trxNamespace || document.XMLName.Local != "TestRun" ||
		results == nil || summary == nil || counters == nil ||
		summary.Outcome != "Completed" || !counterNamesMatch {
		return 0, 0, newToolValidationException([]string{fmt.Sprintf("TRX result has an invalid summary: %s", path)})
	}

	values := map[string]int{}
	for _, name := range ciCounterNames {
		value, ok := ciCounterNumber(counters, name)
		if !ok {
			return 0, 0, newToolValidationException([]string{
				fmt.Sprintf("TRX result has an invalid %s counter: %s", name, path)})
		}
		values[name] = value
	}
	rows := results.UnitTestResults
	identities := map[string]bool{}
	passed := 0
	skipped := 0
	for _, row := range rows {
		execution, ok := parseGuidValue(row.ExecutionId)
		if !ok || identities[execution] || strings.TrimSpace(row.TestName) == "" {
			return 0, 0, newToolValidationException([]string{
				fmt.Sprintf("TRX result contains an invalid test identity: %s", path)})
		}
		identities[execution] = true
		switch row.Outcome {
		case "Passed":
			passed++
		case "NotExecuted":
			skipped++
		default:
			return 0, 0, newToolValidationException([]string{
				fmt.Sprintf("TRX result contains a non-successful outcome: %s", path)})
		}
	}

	invalid := false
	for _, name := range []string{
		"failed", "error", "timeout", "aborted", "inconclusive", "passedButRunAborted", "notRunnable",
		"disconnected", "warning", "completed", "inProgress", "pending",
	} {
		if values[name] != 0 {
			invalid = true
		}
	}
	if values["total"] < 1 || values["total"] > ciMaximumTests || len(rows) != values["total"] ||
		values["executed"] != passed || values["passed"] != passed ||
		values["notExecuted"] != skipped || passed+skipped != len(rows) || invalid {
		return 0, 0, newToolValidationException([]string{
			fmt.Sprintf("TRX result counters do not match successful test rows: %s", path)})
	}
	return values["total"], skipped, nil
}

func ciCounterNumber(counters *trxCounters, name string) (int, bool) {
	for _, attribute := range counters.Attributes {
		if attribute.Name.Local != name {
			continue
		}
		text := attribute.Value
		if len(text) == 0 {
			return 0, false
		}
		for index := 0; index < len(text); index++ {
			if text[index] < '0' || text[index] > '9' {
				return 0, false
			}
		}
		value, err := strconv.Atoi(text)
		if err != nil || value < 0 {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

// parseGuidValue accepts 32-digit, hyphened, braced, and parenthesized GUID
// spellings, returning the 32 lowercase hex digits.
func parseGuidValue(text string) (string, bool) {
	value := strings.Trim(text, "{}()")
	if len(value) == 36 {
		parts := strings.Split(value, "-")
		if len(parts) == 5 && len(parts[0]) == 8 && len(parts[1]) == 4 && len(parts[2]) == 4 && len(parts[3]) == 4 && len(parts[4]) == 12 {
			value = strings.Join(parts, "")
		}
	}
	if len(value) != 32 {
		return "", false
	}
	value = strings.ToLower(value)
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return "", false
		}
	}
	return value, true
}

func ciValidJob(job string) bool {
	length := 0
	for _, character := range job {
		length++
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return length >= 1 && length <= 512
}

func ciDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	nonZero := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '0' {
			continue
		}
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
		nonZero = true
	}
	return nonZero
}

func ciArtifactId(value string) bool {
	if len(value) < 1 || len(value) > 256 || value[0] == '/' || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isCiPathCharacter(value[index]) {
			return false
		}
	}
	return ciSegmentsValid(value)
}

func ciRelativePath(value string) bool {
	if len(value) < 1 || len(value) > 1024 || value[0] == '/' ||
		strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isCiPathCharacter(value[index]) {
			return false
		}
	}
	return ciSegmentsValid(value)
}

func isCiPathCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '.' || character == '_' || character == '-' || character == '/'
}

func ciSegmentsValid(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
