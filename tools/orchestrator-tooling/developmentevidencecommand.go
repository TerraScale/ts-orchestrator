// Port of tools/TerraScale.Orchestrator.Tooling/DevelopmentEvidenceCommand.cs.
// Toolchain mapping for the Go migration of this repository: the solution
// restore/build become `go mod download` / `go build -p 1 -o bin/ ./...`, the
// five .NET test-module executables become `go test` runs over the mapped
// package areas, and the hashed binary artifact is the built runtime
// executable under bin/ (gitignored like the C# bin/Debug tree). Command
// names, evidence schema, exit codes, and output strings stay identical.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DevelopmentRequiredProfile mirrors DevelopmentEvidenceCommand.RequiredProfile.
const DevelopmentRequiredProfile = "regional"

// DevelopmentEvidenceSchemaVersion mirrors the C# constant.
const DevelopmentEvidenceSchemaVersion = 2

// DevelopmentMaximumParallelTestModules mirrors the C# constant.
const DevelopmentMaximumParallelTestModules = 1

// DevelopmentMaximumParallelTests mirrors the C# constant.
const DevelopmentMaximumParallelTests = 4

// DevelopmentDefaultTestModuleTimeoutMinutes mirrors the C# constant.
const DevelopmentDefaultTestModuleTimeoutMinutes = 5

// DevelopmentIntegrationTestModuleTimeoutMinutes mirrors the C# constant.
const DevelopmentIntegrationTestModuleTimeoutMinutes = 15

// DevelopmentMaximumValidationProcesses mirrors the C# constant.
const DevelopmentMaximumValidationProcesses = 512

// DevelopmentAggregateMemoryLimitBytes mirrors the C# constant.
const DevelopmentAggregateMemoryLimitBytes = int64(24) * 1024 * 1024 * 1024

// DevelopmentExecutionMemoryLimitBytes mirrors the C# constant.
const DevelopmentExecutionMemoryLimitBytes = int64(20) * 1024 * 1024 * 1024

// DevelopmentReservedHeadroomBytes mirrors the C# constant.
const DevelopmentReservedHeadroomBytes = DevelopmentAggregateMemoryLimitBytes - DevelopmentExecutionMemoryLimitBytes

// DevelopmentTestModule mirrors the C# TestModule record: the C# test project
// name maps to the Go package pattern that now owns those tests.
type DevelopmentTestModule struct {
	Name              string
	RelativeDirectory string
	TimeoutMinutes    int
}

// DevelopmentTestModules mirrors the C# five-module inventory, mapped onto the
// Go package areas: ControlPlane -> control, Model -> contracts, Protocol ->
// protocol, Scheduler -> scheduling, and the integration suite covers the
// whole module.
var DevelopmentTestModules = []DevelopmentTestModule{
	{Name: "src/orchestrator/control", RelativeDirectory: "src/orchestrator/control", TimeoutMinutes: DevelopmentDefaultTestModuleTimeoutMinutes},
	{Name: "src/orchestrator/contracts", RelativeDirectory: "src/orchestrator/contracts", TimeoutMinutes: DevelopmentDefaultTestModuleTimeoutMinutes},
	{Name: "src/orchestrator/protocol", RelativeDirectory: "src/orchestrator/protocol", TimeoutMinutes: DevelopmentDefaultTestModuleTimeoutMinutes},
	{Name: "src/orchestrator/scheduling", RelativeDirectory: "src/orchestrator/scheduling", TimeoutMinutes: DevelopmentDefaultTestModuleTimeoutMinutes},
	{Name: "./...", RelativeDirectory: ".", TimeoutMinutes: DevelopmentIntegrationTestModuleTimeoutMinutes},
}

// DevelopmentEvidenceOptions mirrors the C# Options record.
type DevelopmentEvidenceOptions struct {
	Output     string
	Binary     string
	ValidHours int
}

type developmentEvidenceCommand struct{}

// DevelopmentEvidenceCommand mirrors the C# static class.
var DevelopmentEvidenceCommand = developmentEvidenceCommand{}

func (developmentEvidenceCommand) Run(arguments []string) (int, error) {
	options, err := DevelopmentEvidenceCommand.Parse(arguments)
	if err != nil {
		return 0, err
	}
	lease, err := AcquireLocalValidationLease("")
	if err != nil {
		return 0, err
	}
	defer lease.Close()
	root := ToolingSupport.Root()
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return 0, err
	}
	binary := options.Binary
	if binary == "" {
		binary = filepath.Join(root, "bin", "orchestrator")
	} else if binary, err = filepath.Abs(binary); err != nil {
		return 0, err
	}

	if isWithinPath(output, root) {
		return 0, newToolValidationException([]string{
			"development evidence must be written outside the Orchestrator repository"})
	}

	if err := requireCleanWorktree(root); err != nil {
		return 0, err
	}
	type observationEntry struct {
		Name  string
		Value ProcessObservation
	}
	var observations []observationEntry
	// Locked restore must precede the no-restore build so dependency adds
	// refresh go.sum on the exact tree before compilation.
	restoreResult, err := runRequiredValidation("go", []string{"mod", "download"}, root, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	observations = append(observations, observationEntry{"solution-restore", restoreResult.Observation})
	// The Go build compiles every package in the module and emits the runtime
	// binary under bin/ like the C# solution build did.
	buildResult, err := runRequiredValidation("go", []string{"build", "-p", "1", "-o", "bin/", "./..."}, root, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	observations = append(observations, observationEntry{"solution-build", buildResult.Observation})
	inventory := &JsonArray{}
	for _, module := range DevelopmentTestModules {
		result, err := runRequiredValidation(
			"go",
			[]string{"test", "-count=1", "-parallel", strconv.Itoa(DevelopmentMaximumParallelTests), "-v", module.Name},
			root,
			time.Duration(module.TimeoutMinutes)*time.Minute)
		if err != nil {
			return 0, err
		}
		total, err := DevelopmentEvidenceCommand.ParseTestTotal(module.Name, result.StandardOutput)
		if err != nil {
			return 0, err
		}
		observations = append(observations, observationEntry{module.Name, result.Observation})
		moduleInventory := newJsonObject()
		moduleInventory.Set("module", module.Name)
		moduleInventory.Set("tests", total)
		moduleInventory.Set("maximumParallelTests", DevelopmentMaximumParallelTests)
		inventory.Append(moduleInventory)
	}
	// The C# run re-executed the freshly built tooling executable; the Go
	// attestation re-executes this same tooling binary.
	toolingExecutable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	toolingResult, err := runRequiredValidation(toolingExecutable, []string{"test"}, root, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	observations = append(observations, observationEntry{"orchestrator-policy-tooling-tests", toolingResult.Observation})
	if err := requireCleanWorktree(root); err != nil {
		return 0, err
	}

	if info, statErr := os.Stat(binary); statErr != nil || info.IsDir() {
		return 0, newToolValidationException([]string{fmt.Sprintf("Orchestrator binary is unavailable: %s", binary)})
	}

	now := time.Now().UTC()
	sourceCommit, err := ToolingSupport.Git(root, "rev-parse", "HEAD")
	if err != nil {
		return 0, err
	}
	binaryDigest, err := ToolingSupport.Sha256(resolveCodeArtifact(binary))
	if err != nil {
		return 0, err
	}

	checks := &JsonArray{}
	checks.Append("orchestrator-solution-restore")
	checks.Append("orchestrator-solution-build")
	checks.Append("orchestrator-test-modules-sequential")
	checks.Append("orchestrator-policy-tooling-tests")

	resourcePolicy := newJsonObject()
	resourcePolicy.Set("aggregateMemoryLimitBytes", DevelopmentAggregateMemoryLimitBytes)
	resourcePolicy.Set("executionMemoryLimitBytes", DevelopmentExecutionMemoryLimitBytes)
	resourcePolicy.Set("reservedHeadroomBytes", DevelopmentReservedHeadroomBytes)
	resourcePolicy.Set("maximumParallelTestModules", DevelopmentMaximumParallelTestModules)
	resourcePolicy.Set("maximumParallelTests", DevelopmentMaximumParallelTests)
	resourcePolicy.Set("maximumValidationProcesses", DevelopmentMaximumValidationProcesses)

	processObservations := &JsonArray{}
	for _, item := range observations {
		entry := newJsonObject()
		entry.Set("name", item.Name)
		entry.Set("processId", item.Value.ProcessId)
		entry.Set("peakMemoryBytes", item.Value.PeakMemoryBytes)
		entry.Set("peakProcessCount", item.Value.PeakProcessCount)
		entry.Set("durationMilliseconds", item.Value.DurationMilliseconds)
		processObservations.Append(entry)
	}

	document := newJsonObject()
	document.Set("schemaVersion", DevelopmentEvidenceSchemaVersion)
	document.Set("result", "pass")
	document.Set("sourceCommit", strings.TrimSpace(sourceCommit))
	document.Set("binarySha256", binaryDigest)
	document.Set("authorizedProfile", DevelopmentRequiredProfile)
	document.Set("issuedAt", now)
	document.Set("expiresAt", now.Add(time.Duration(options.ValidHours)*time.Hour))
	document.Set("checks", checks)
	document.Set("resourcePolicy", resourcePolicy)
	document.Set("testInventory", inventory)
	document.Set("processObservations", processObservations)

	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return 0, err
	}
	temporary := fmt.Sprintf("%s.%d.tmp", output, os.Getpid())
	serialized, err := ToolingSupport.Serialize(document)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(temporary, []byte(serialized), 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(temporary, output); err != nil {
		return 0, err
	}
	fmt.Printf("authorized %s for exact commit and binary until %s\n",
		DevelopmentRequiredProfile,
		now.Add(time.Duration(options.ValidHours)*time.Hour).Format("2006-01-02T15:04:05.0000000-07:00"))
	fmt.Println(output)
	return 0, nil
}

// Parse mirrors the C# internal option parser.
func (developmentEvidenceCommand) Parse(arguments []string) (DevelopmentEvidenceOptions, error) {
	usage := func() (DevelopmentEvidenceOptions, error) {
		return DevelopmentEvidenceOptions{}, newToolValidationException([]string{
			"development-attest requires --output <outside-repository-path> [--binary <path>] [--valid-hours 1..24]"})
	}
	output := ""
	binary := ""
	validHours := 8
	for index := 0; index < len(arguments); index++ {
		if index+1 >= len(arguments) {
			return usage()
		}
		value := arguments[index+1]
		flag := arguments[index]
		index++
		switch flag {
		case "--output":
			output = value
		case "--binary":
			binary = value
		case "--valid-hours":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed >= 1 && parsed <= 24 {
				validHours = parsed
			} else {
				return usage()
			}
		default:
			return usage()
		}
	}
	if strings.TrimSpace(output) == "" {
		return usage()
	}
	return DevelopmentEvidenceOptions{Output: output, Binary: binary, ValidHours: validHours}, nil
}

func requireCleanWorktree(root string) error {
	status, err := ToolingSupport.Git(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return newToolValidationException([]string{
			"development attestation requires a clean Orchestrator worktree"})
	}
	return nil
}

func runRequiredValidation(fileName string, arguments []string, workingDirectory string, timeout time.Duration) (ObservedProcessResult, error) {
	result, err := BoundedProcessRunner.Run(
		fileName,
		arguments,
		workingDirectory,
		timeout,
		DevelopmentExecutionMemoryLimitBytes,
		DevelopmentMaximumValidationProcesses)
	if err != nil {
		return ObservedProcessResult{}, err
	}
	if result.ExitCode != 0 {
		return ObservedProcessResult{}, newToolValidationException([]string{
			fmt.Sprintf("%s validation failed", fileName),
			strings.TrimSpace(result.StandardOutput),
			strings.TrimSpace(result.StandardError)})
	}
	return result, nil
}

var developmentTestTotalPattern = regexp.MustCompile(`(?m)^\s*total:\s*(\d+)\s*$`)
var developmentGoTestResultPattern = regexp.MustCompile(`(?m)^--- (?:PASS|FAIL|SKIP): \S+`)

// ParseTestTotal mirrors the C# helper: a `total: N` line wins, otherwise the
// `go test -v` top-level result lines are counted (the toolchain-mapped
// equivalent of the test-module inventory line).
func (developmentEvidenceCommand) ParseTestTotal(module string, output string) (int, error) {
	if match := developmentTestTotalPattern.FindStringSubmatch(output); match != nil {
		if total, err := strconv.Atoi(match[1]); err == nil && total > 0 {
			return total, nil
		}
	} else if count := len(developmentGoTestResultPattern.FindAllString(output, -1)); count > 0 {
		return count, nil
	}
	return 0, newToolValidationException([]string{
		fmt.Sprintf("%s did not report a nonzero test inventory", module)})
}

func isWithinPath(path string, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}
	return relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!filepath.IsAbs(relative)
}

// resolveCodeArtifact mirrors the C# helper: the .dll sidecar no longer
// exists, so the executable itself is the code artifact.
func resolveCodeArtifact(executable string) string {
	return executable
}
