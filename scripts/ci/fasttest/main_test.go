package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fixtureModule = "fixture.example/orchestrator"

type invocation struct {
	Args       []string
	Start, End time.Time
	Cases      []string
	CPU        string
	HelperCPU  string
}

func fixturePackages() map[string][]string {
	packages := map[string][]string{
		fixtureModule + "/unknown": {"TestUnknown", "ExamplevolumeSizeGB", "FuzzSeed"},
		fixtureModule + "/empty":   nil,
	}
	for _, suffix := range []string{"/internal/app", "/internal/natscell/mesh", "/internal/region", "/tests/deploy"} {
		for i := range 12 {
			packages[fixtureModule+suffix] = append(packages[fixtureModule+suffix], fmt.Sprintf("TestCase%02d", i))
		}
	}
	if os.Getenv("FAST_CONTRACT_MODE") == "shared-name" {
		pkg := fixtureModule + "/internal/app"
		packages[pkg] = append(packages[pkg], "TestCase00")
	}
	return packages
}

// The fake tool is this test executable. Its TestMain also supports an
// arbitrary helper command, as app/deploy TestMain binaries must continue to do.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--runtime-helper" {
		fmt.Print(os.Getenv("GOMAXPROCS"))
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "--fake-go" {
		fakeGo(os.Args[2:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeGo(args []string) {
	packages := fixturePackages()
	mode := os.Getenv("FAST_CONTRACT_MODE")
	if args[0] == "list" {
		for _, pkg := range sortedKeys(packages) {
			fmt.Println(pkg)
		}
		return
	}
	emit := func(e event) { _ = json.NewEncoder(os.Stdout).Encode(e) }
	if slices.Contains(args, "-list") {
		if mode == "invalid-json" {
			fmt.Println("invalid JSON")
			return
		}
		for _, pkg := range sortedKeys(packages) {
			emit(event{Action: "start", Package: pkg})
			for _, name := range packages[pkg] {
				emit(event{Action: "output", Package: pkg, Output: name + "\n"})
			}
			emit(event{Action: "output", Package: pkg, Output: "BenchmarkNotACase\n"})
			if mode != "incomplete-list" {
				emit(event{Action: "pass", Package: pkg})
			}
		}
		if mode == "list-failure" {
			os.Exit(1)
		}
		return
	}
	call := invocation{Args: args, Start: time.Now(), CPU: os.Getenv("GOMAXPROCS")}
	pkg := args[len(args)-1]
	pattern := args[slices.Index(args, "-run")+1]
	filter := regexp.MustCompile(pattern)
	failure := false
	emit(event{Action: "start", Package: pkg})
	for _, name := range packages[pkg] {
		if !filter.MatchString(name) {
			continue
		}
		if mode == "missing-case" && name == "TestUnknown" {
			continue
		}
		call.Cases = append(call.Cases, pkg+"/"+name)
		emit(event{Action: "run", Package: pkg, Test: name})
		if name == "FuzzSeed" {
			emit(event{Action: "run", Package: pkg, Test: name + "/seed#0"})
			emit(event{Action: "pass", Package: pkg, Test: name + "/seed#0"})
		}
		status := "pass"
		if name == "TestUnknown" {
			output, err := exec.Command(os.Args[0], "--runtime-helper").Output()
			if err != nil {
				os.Exit(2)
			}
			call.HelperCPU = string(output)
			if mode == "test-failure" || mode == "masked-failure" {
				status, failure = "fail", true
			}
			if mode == "duplicate-run" {
				emit(event{Action: "run", Package: pkg, Test: name})
			}
		}
		if name == "TestCase00" {
			status = "skip"
		}
		emit(event{Action: status, Package: pkg, Test: name})
	}
	if mode == "unexpected-case" {
		emit(event{Action: "run", Package: pkg, Test: "TestUnlisted"})
		emit(event{Action: "pass", Package: pkg, Test: "TestUnlisted"})
	}
	// Long enough for the concurrency contract to observe overlapping processes.
	time.Sleep(70 * time.Millisecond)
	call.End = time.Now()
	data, _ := json.Marshal(call)
	if err := os.WriteFile(filepath.Join(os.Getenv("FAST_CONTRACT_STATE"), fmt.Sprintf("call-%d.json", os.Getpid())), data, 0o600); err != nil {
		panic(err)
	}
	status := "pass"
	if failure {
		status = "fail"
	}
	emit(event{Action: status, Package: pkg})
	if failure && mode != "masked-failure" {
		os.Exit(1)
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func fixtureRun(t *testing.T, mode string) ([]invocation, []result, error) {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("FAST_CONTRACT_MODE", mode)
	t.Setenv("FAST_CONTRACT_STATE", directory)
	var output bytes.Buffer
	err := run(t.Context(), []string{os.Args[0], "--fake-go"}, nil, directory, &output)
	var calls []invocation
	paths, _ := filepath.Glob(filepath.Join(directory, "call-*.json"))
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var call invocation
		if err := json.Unmarshal(data, &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	var receipts []result
	if data, readErr := os.ReadFile(filepath.Join(directory, "receipts.json")); readErr == nil {
		if err := json.Unmarshal(data, &receipts); err != nil {
			t.Fatal(err)
		}
	}
	if err != nil {
		t.Log(output.String())
	}
	return calls, receipts, err
}

func TestFullShortTierCoverageAndConcurrency(t *testing.T) {
	t.Setenv("GOMAXPROCS", "17")
	calls, receipts, err := fixtureRun(t, "")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int)
	var boundaries []struct {
		at    time.Time
		delta int
	}
	for _, call := range calls {
		if call.CPU != "2" || slices.Contains(call.Cases, fixtureModule+"/unknown/TestUnknown") && call.HelperCPU != "2" {
			t.Fatalf("shard/helper escaped CPU budget: %+v", call)
		}
		for _, name := range call.Cases {
			seen[name]++
		}
		if !slices.Contains(call.Args, "-short") || !slices.Contains(call.Args, "-count=1") ||
			!slices.Contains(call.Args, "-p=1") || !slices.Contains(call.Args, "-parallel=2") ||
			!slices.Contains(call.Args, "-cpu=2") || slices.Contains(call.Args, "-race") {
			t.Fatalf("wrong tier command: %v", call.Args)
		}
		boundaries = append(boundaries, struct {
			at    time.Time
			delta int
		}{call.Start, 1}, struct {
			at    time.Time
			delta int
		}{call.End, -1})
	}
	for pkg, names := range fixturePackages() {
		for _, name := range names {
			key := pkg + "/" + name
			if seen[key] != 1 {
				t.Errorf("%s executed %d times", key, seen[key])
			}
			delete(seen, key)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("unlisted executions: %v", seen)
	}
	slices.SortFunc(boundaries, func(a, b struct {
		at    time.Time
		delta int
	}) int {
		return a.at.Compare(b.at)
	})
	active, maximum := 0, 0
	for _, boundary := range boundaries {
		active += boundary.delta
		maximum = max(maximum, active)
	}
	if active != 0 || maximum < 2 || maximum > jobs {
		t.Fatalf("active=%d maximum=%d, want parallel and bounded by %d", active, maximum, jobs)
	}
	actual := make(map[string]int)
	for _, receipt := range receipts {
		if len(receipt.Problems) != 0 {
			t.Fatal(receipt.Problems)
		}
		for _, e := range receipt.Cases {
			actual[e.Package+"/"+e.Test]++
		}
	}
	for _, key := range []string{fixtureModule + "/unknown/ExamplevolumeSizeGB", fixtureModule + "/unknown/FuzzSeed", fixtureModule + "/unknown/FuzzSeed/seed#0"} {
		if actual[key] != 1 {
			t.Errorf("actual JSON receipt %s = %d, want 1", key, actual[key])
		}
	}
	if len(calls) != len(receipts) {
		t.Fatalf("calls=%d receipts=%d", len(calls), len(receipts))
	}
}

func TestInvalidListingRunsNothing(t *testing.T) {
	for _, mode := range []string{"invalid-json", "incomplete-list", "list-failure"} {
		t.Run(mode, func(t *testing.T) {
			calls, _, err := fixtureRun(t, mode)
			if err == nil || len(calls) != 0 {
				t.Fatalf("error=%v calls=%d, want rejected discovery before execution", err, len(calls))
			}
		})
	}
}

func TestInternalAndExternalTestsWithSharedName(t *testing.T) {
	calls, receipts, err := fixtureRun(t, "shared-name")
	if err != nil {
		t.Fatal(err)
	}
	key := fixtureModule + "/internal/app/TestCase00"
	runs, terminals := 0, 0
	for _, call := range calls {
		for _, name := range call.Cases {
			if name == key {
				runs++
			}
		}
	}
	for _, receipt := range receipts {
		for _, e := range receipt.Cases {
			if e.Package+"/"+e.Test == key {
				terminals++
			}
		}
	}
	if runs != 2 || terminals != 2 {
		t.Fatalf("shared name runs=%d terminals=%d, want both occurrences", runs, terminals)
	}
	packages := map[string][]string{"fixture/package": {"TestShared", "TestShared"}}
	if err := validatePlan(packages, []shard{{Package: "fixture/package", Tests: []string{"TestShared"}}, {Package: "fixture/package", Tests: []string{"TestShared"}}}); err == nil {
		t.Fatal("shared name split across shards")
	}
}

func TestFailuresAndActualCoverageAreFinal(t *testing.T) {
	for _, mode := range []string{"test-failure", "masked-failure", "missing-case", "duplicate-run", "unexpected-case"} {
		t.Run(mode, func(t *testing.T) {
			calls, receipts, err := fixtureRun(t, mode)
			if err == nil {
				t.Fatal("invalid actual execution succeeded")
			}
			seen := 0
			for _, call := range calls {
				for _, name := range call.Cases {
					if strings.HasSuffix(name, "/TestUnknown") {
						seen++
					}
				}
			}
			if seen > 1 {
				t.Fatalf("failed test retried %d times", seen)
			}
			want := len(plan(fixturePackages(), nil))
			if len(calls) != want || len(receipts) != want {
				t.Fatalf("stopped remaining cases: calls=%d receipts=%d want=%d", len(calls), len(receipts), want)
			}
		})
	}
}

func TestPlanRejectsMissingAndDuplicateCoverage(t *testing.T) {
	packages := map[string][]string{"fixture/package": {"TestOne", "FuzzSeed"}, "fixture/empty": nil}
	valid := []shard{{Package: "fixture/package", Tests: []string{"TestOne", "FuzzSeed"}}, {Package: "fixture/empty"}}
	if err := validatePlan(packages, valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]shard{
		valid[:1],
		{{Package: "fixture/package", Tests: []string{"TestOne"}}, {Package: "fixture/empty"}},
		append(slices.Clone(valid), shard{Package: "fixture/package", Tests: []string{"TestOne"}}),
		append(slices.Clone(valid), shard{Package: "fixture/unknown"}),
		{{Package: "fixture/package", Tests: []string{"TestOne", "TestUnlisted"}}, {Package: "fixture/empty"}},
	} {
		if err := validatePlan(packages, invalid); err == nil {
			t.Fatalf("invalid coverage accepted: %+v", invalid)
		}
	}
}

func TestCancellationReapsAnUnresponsiveShard(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("FAST_CONTRACT_STATE", directory)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	r := execute(ctx, []string{"sh", "-c", `trap '' TERM; printf '%s' "$$" > "$FAST_CONTRACT_STATE/held"; exec sleep 30`},
		shard{Package: "fixture/package", Tests: []string{"TestHeld"}}, directory)
	if ctx.Err() == nil || len(r.Problems) == 0 || time.Since(started) > 3*time.Second {
		t.Fatalf("cancellation: context=%v problems=%v elapsed=%v", ctx.Err(), r.Problems, time.Since(started))
	}
	data, err := os.ReadFile(filepath.Join(directory, "held"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("cancelled shard %d still exists: %v", pid, err)
	}
}
