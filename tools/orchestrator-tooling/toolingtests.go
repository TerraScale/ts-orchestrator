package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type toolingTests struct{}

var ToolingTests = toolingTests{}

type toolingTest struct {
	Name string
	Body func()
}

func (toolingTests) Run(arguments []string) (int, error) {
	if len(arguments) != 0 && !(len(arguments) == 1 && arguments[0] == "--repository-only") {
		return 0, newToolValidationException([]string{"test accepts only --repository-only"})
	}

	var failures []string
	for _, test := range toolingTestSuite() {
		if err := runToolingTestBody(test.Body); err != nil {
			failures = append(failures, fmt.Sprintf("FAIL %s: %s", test.Name, err.Error()))
		} else {
			fmt.Printf("PASS %s\n", test.Name)
		}
	}

	if len(failures) != 0 {
		return 0, newToolValidationException(failures)
	}
	fmt.Printf("Passed %d Go tooling tests.\n", len(toolingTestSuite()))
	return 0, nil
}

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
	assertEqualValue("pipeline:job", testString(document.Get("job"), "job"))
	assertEqualValue(digest, testString(document.Get("planDigest"), "planDigest"))
	assertEqualValue(true, testBool(document, "succeeded"))
	assertEqualValue(1, testInt(document, "requiredTestSkips"))
	artifacts := testArray(document.Get("artifacts"), "artifacts")
	artifact := artifacts.Get(0).(*JsonObject)
	assertEqualValue("TerraScale/Orchestrator", testString(artifact.Get("artifact"), "artifact"))
	assertEqualValue("LinuxX64", testString(artifact.Get("architecture"), "architecture"))
	assertEqualValue("linux-x64", testString(artifact.Get("path"), "path"))
	entrypoints := testArray(artifact.Get("entrypoints"), "entrypoints")
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

func developmentWorkspaceTopologyLease() {
	previousNamespace, hadPrevious := os.LookupEnv(workspaceTopologyNamespaceVariable)
	leaseNamespace := "tooling-" + randomTestToken()
	defer func() {
		if hadPrevious {
			_ = os.Setenv(workspaceTopologyNamespaceVariable, previousNamespace)
		} else {
			_ = os.Unsetenv(workspaceTopologyNamespaceVariable)
		}
	}()

	if err := os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace); err != nil {
		panic(err)
	}
	first, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if _, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 50*time.Millisecond); err == nil {
		panic(errors.New("expected a timeout while the topology lease is held"))
	}
	if err := first.Close(); err != nil {
		panic(err)
	}
	second, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if err := second.Close(); err != nil {
		panic(err)
	}
}

func assertEqualValue(expected any, actual any) {
	if expected != actual {
		panic(fmt.Errorf("expected %v, observed %v", expected, actual))
	}
}

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

func testArray(node any, key string) *JsonArray {
	value, ok := node.(*JsonArray)
	if !ok {
		panic(fmt.Errorf("%s is not an array", key))
	}
	return value
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
