// Package racetest holds the contract test of the CI race scheduler,
// race-test.sh. It embeds the script and its estimates instead of reading
// the repository, so Go's test cache re-runs it only when they change.
package racetest_test

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

//go:embed race-test.sh
var raceScript []byte

//go:embed race-durations.txt
var committedDurations []byte

var schedulerLabs = []string{
	"TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss",
	"TestControllerThreeProcessBootstrapAndRestart",
	"TestLabTLSHostSessionRecoversAfterBlackholedController",
	"TestLabTLSHostSessionRecoversAfterControllerLoss",
	"TestAuthenticatedOperatorToHostDeliveryWithControllerLoss",
}

const solo = "TestOfflineReadbackMismatchDiscardsCandidate"

// noraceTest is the fixture test estimated as norace.
const noraceTest = "TestRetry"

// The fixture estimates make cost order differ from name order: round-robin
// by name would pair TestThree with TestFail and TestOne with Example.
const fixtureDurations = `# fixture estimates
rest - 5
./internal/app TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss 95/1 idle
./internal/app TestControllerThreeProcessBootstrapAndRestart 80/1 idle
./internal/app TestLabTLSHostSessionRecoversAfterBlackholedController 65/1 idle
./internal/app TestLabTLSHostSessionRecoversAfterControllerLoss 38/1 idle
./internal/app TestAuthenticatedOperatorToHostDeliveryWithControllerLoss 32/1 idle
./internal/app TestThree 20
./internal/app TestOne 12
./internal/app Test* 1
./internal/bootstrapstart TestStart 30
./internal/bootstrapstart TestRetry 4 norace
./tests/deploy TestOfflineReadbackMismatchDiscardsCandidate 300/60 solo
./tests/deploy * 10
`

type schedulerState struct {
	Active, Maximum         int
	IdleActive, IdleMaximum int
	CPUActive, CPUMaximum   int
	Commands                [][]string
	GORACE                  []string
}

// The scheduler executes this helper as its Go wrapper. It observes process
// concurrency per pool under an OS file lock, then delegates to the real Go
// toolchain.
func TestSchedulerGoWrapper(t *testing.T) {
	if os.Getenv("TS_SCHEDULER_WRAPPER") != "1" {
		return
	}
	marker := slices.Index(os.Args, "--")
	if marker < 0 || marker+1 >= len(os.Args) {
		os.Exit(2)
	}
	args := os.Args[marker+1:]
	running := args[0] == "test" && !slices.Contains(args, "-list")
	idle := false
	if i := slices.Index(args, "-run"); i >= 0 && i+1 < len(args) {
		for _, lab := range schedulerLabs {
			idle = idle || args[i+1] == "^("+lab+")$"
		}
	}
	update := func(delta int) {
		f, err := os.OpenFile(os.Getenv("SCHEDULER_STATE"), os.O_RDWR, 0)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			panic(err)
		}
		data, err := os.ReadFile(f.Name())
		if err != nil {
			panic(err)
		}
		var state schedulerState
		if err := json.Unmarshal(data, &state); err != nil {
			panic(err)
		}
		state.Active += delta
		state.Maximum = max(state.Maximum, state.Active)
		if idle {
			state.IdleActive += delta
			state.IdleMaximum = max(state.IdleMaximum, state.IdleActive)
		} else if running {
			state.CPUActive += delta
			state.CPUMaximum = max(state.CPUMaximum, state.CPUActive)
		}
		if delta >= 0 {
			state.Commands = append(state.Commands, args)
			if running {
				state.GORACE = append(state.GORACE, os.Getenv("GORACE"))
			}
		}
		data, err = json.Marshal(state)
		if err != nil {
			panic(err)
		}
		if _, err := f.WriteAt(data, 0); err != nil {
			panic(err)
		}
		if err := f.Truncate(int64(len(data))); err != nil {
			panic(err)
		}
	}
	if running {
		update(1)
	} else {
		update(0)
	}
	if slices.Contains(args, "-list") && os.Getenv("FAIL_LIST") != "" {
		fmt.Println("intentional discovery failure")
		os.Exit(1)
	}
	cmd := exec.Command(os.Getenv("REAL_GO"), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if running {
		update(-1)
	}
	if err != nil {
		if cmd.ProcessState == nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(cmd.ProcessState.ExitCode())
	}
	os.Exit(0)
}

type schedulerFixture struct {
	root, script, state, record string
	expected                    []string
	env                         map[string]string
}

func newScheduler(t *testing.T) schedulerFixture {
	t.Helper()
	root := t.TempDir()
	tools := t.TempDir()
	script.Write(t, filepath.Join(root, "go.mod"), []byte("module example.test/scheduler\n\ngo 1.27.0\n"), 0o644)
	f := schedulerFixture{root: root, script: filepath.Join(tools, "race-test.sh"), state: filepath.Join(tools, "state.json"), record: filepath.Join(tools, "tests.txt")}
	script.Write(t, f.script, raceScript, 0o755)
	durations := filepath.Join(tools, "race-durations.txt")
	script.Write(t, durations, []byte(fixtureDurations), 0o644)
	for pkg, names := range map[string][]string{"app": append(slices.Clone(schedulerLabs), "TestOne", "TestTwo", "TestFail", "TestThree"), "bootstrapstart": {"TestStart", "TestRetry", "TestMaterial"}, "0000000000V4MRM46HP1SNGDYW": {"TestOrdinary"}, "deploy": {solo, "TestOfflineOrdinary"}} {
		source := `package fixture
import("fmt";"os";"testing")
func record(name string){f,err:=os.OpenFile(os.Getenv("TEST_RECORD"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if err!=nil{panic(err)};defer f.Close();if _,err:=fmt.Fprintln(f,name);err!=nil{panic(err)}}
`
		for _, name := range names {
			identity := pkg + "/" + name
			f.expected = append(f.expected, identity)
			source += fmt.Sprintf("func %s(t *testing.T){record(%q);", name, identity)
			if name == "TestFail" {
				source += `if os.Getenv("FAIL_TEST")!=""{t.Fatal("intentional gate failure")};`
			}
			source += "}\n"
		}
		if pkg == "app" {
			source += `func Example(){record("app/Example");fmt.Println("example")
// Output: example
}
func FuzzSeed(f *testing.F){f.Add(1);f.Fuzz(func(t *testing.T,n int){record("app/FuzzSeed")})}
`
			f.expected = append(f.expected, "app/Example", "app/FuzzSeed")
		}
		parent := "internal"
		if pkg == "deploy" {
			parent = "tests"
		}
		script.Write(t, filepath.Join(root, parent, pkg, "fixture_test.go"), []byte(source), 0o644)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	// A shell adapter keeps paths with spaces safe; the test binary itself owns
	// state accounting and invokes Go directly, without Python test helpers.
	wrapper := filepath.Join(tools, "go-wrapper")
	script.Write(t, wrapper, []byte("#!/usr/bin/env bash\nexec \"$SCHEDULER_TEST_BINARY\" -test.run='^TestSchedulerGoWrapper$' -- \"$@\"\n"), 0o755)
	// Every setting is explicit: CI's own TS_TEST_TIER and race settings
	// must not leak into the scheduler under test.
	f.env = map[string]string{"GO": wrapper, "REAL_GO": realGo, "SCHEDULER_TEST_BINARY": executable, "TS_SCHEDULER_WRAPPER": "1", "GOFLAGS": "-p=2", "GOMAXPROCS": "2", "GORACE": "halt_on_error=1",
		"TS_RACE_SHARDS": "3", "TS_RACE_JOBS": "2", "TS_RACE_IDLE_JOBS": "1", "TS_RACE_PACKAGE_JOBS": "2", "TS_RACE_TEST_JOBS": "2", "TS_TEST_TIER": "full", "TS_RACE_DURATIONS": durations,
		"SCHEDULER_STATE": f.state, "TEST_RECORD": f.record}
	slices.Sort(f.expected)
	return f
}

func (f schedulerFixture) run(t *testing.T, extra map[string]string) script.Result {
	t.Helper()
	wire, err := json.Marshal(schedulerState{})
	if err != nil {
		t.Fatal(err)
	}
	script.Write(t, f.state, wire, 0o600)
	env := map[string]string{}
	for k, v := range f.env {
		env[k] = v
	}
	for k, v := range extra {
		env[k] = v
	}
	return script.Exec(t, f.root, env, "bash", f.script)
}

func (f schedulerFixture) readState(t *testing.T) schedulerState {
	t.Helper()
	var state schedulerState
	if err := json.Unmarshal(script.Read(t, f.state), &state); err != nil {
		t.Fatal(err)
	}
	return state
}

// shards returns the -run expression of every running test command.
func shards(commands [][]string) []string {
	var expressions []string
	for _, args := range commands {
		if i := slices.Index(args, "-run"); i >= 0 {
			expressions = append(expressions, args[i+1])
		}
	}
	return expressions
}

func lines(text, prefix string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			out = append(out, rest)
		}
	}
	return out
}

func (f schedulerFixture) complete(t *testing.T, r script.Result, short bool) {
	t.Helper()
	tests := strings.Fields(string(script.Read(t, f.record)))
	slices.Sort(tests)
	if !reflect.DeepEqual(tests, f.expected) {
		t.Fatalf("tests/examples/fuzz seeds must run once: got %v want %v", tests, f.expected)
	}
	state := f.readState(t)
	if state.Active != 0 || state.CPUMaximum > 2 || state.IdleMaximum > 1 || state.Maximum > 3 {
		t.Fatalf("concurrency active=%d maximum=%d cpu=%d idle=%d", state.Active, state.Maximum, state.CPUMaximum, state.IdleMaximum)
	}
	var commands [][]string
	for _, args := range state.Commands {
		if args[0] == "test" {
			commands = append(commands, args)
		}
	}
	discovery := 0
	for _, args := range commands {
		// Only the norace shard runs without the race detector, and it
		// runs exactly the norace test.
		norace := slices.Contains(args, "^("+noraceTest+")$")
		if slices.Contains(args, "-race") == norace || !slices.Contains(args, "-vet=off") {
			t.Fatalf("wrong race/vet flags: %v", args)
		}
		if slices.Contains(args, "-list") {
			discovery++
		} else if slices.Contains(args, "-short") != short {
			t.Fatalf("tier forwarded -short=%v wrongly: %v", short, args)
		}
	}
	if discovery != 3 || len(commands) < 3 || !slices.Contains(commands[0], "-list") || !slices.Contains(commands[1], "-list") || !slices.Contains(commands[2], "-list") {
		t.Fatalf("discovery should precede all shards: %v", commands)
	}
	for _, gorace := range state.GORACE {
		if gorace != "halt_on_error=1 atexit_sleep_ms=0" {
			t.Fatalf("GORACE=%q: the exit sleep must be off and existing options kept", gorace)
		}
	}
	// Solo and idle tests own a shard, and cost, not name order, packs the
	// rest: the two costly app tests do not share a shard.
	for _, owner := range append(slices.Clone(schedulerLabs), solo, "TestThree", "TestOne", "TestStart", noraceTest) {
		var matching []string
		for _, expression := range shards(commands) {
			ok, err := regexp.MatchString(expression, owner)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				matching = append(matching, expression)
			}
		}
		if !reflect.DeepEqual(matching, []string{"^(" + owner + ")$"}) {
			t.Fatalf("%s must own one shard: %v", owner, matching)
		}
	}
	if !slices.Contains(shards(commands), "^(Example|FuzzSeed|TestFail|TestTwo)$") {
		t.Fatalf("cheap app tests were not packed together in name order: %v", shards(commands))
	}
	// The queue is ordered by estimate, longest first.
	queue := lines(r.Stdout, "race queue ")
	var estimates []int
	for _, entry := range queue {
		var name, pool string
		var seconds int
		if _, err := fmt.Sscanf(entry, "%s pool=%s estimate=%ds", &name, &pool, &seconds); err != nil {
			t.Fatalf("queue entry %q: %v", entry, err)
		}
		estimates = append(estimates, seconds)
	}
	requireText(t, r.Stdout, "race queue bootstrapstart-norace-0 pool=norace estimate=4s")
	if len(queue) != 14 || !slices.IsSortedFunc(estimates, func(a, b int) int { return b - a }) {
		t.Fatalf("queue is not longest first: %v", queue)
	}
}

func TestRaceScheduler(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		t.Parallel()
		f := newScheduler(t)
		r := f.run(t, nil)
		if r.Code != 0 {
			t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
		}
		f.complete(t, r, false)
		// The longest CPU shard and the longest lab start together; a full
		// idle pool does not hold back the next CPU shard.
		starts := lines(r.Stdout, "race start ")
		want := []string{"deploy-" + solo + " pool=cpu", "app-" + schedulerLabs[0] + " pool=idle", "bootstrapstart-0 pool=cpu"}
		if len(starts) != 14 || !reflect.DeepEqual(starts[:3], want) {
			t.Fatalf("starts %v, want prefix %v", starts, want)
		}
		requireText(t, r.Stdout, "race queue deploy-"+solo+" pool=cpu estimate=300s")
		forbidText(t, r.Stderr, "race durations:")
	})
	// A stale literal estimate, a shadowed duplicate and an entry for a
	// package that is not sharded all fail the run before any shard starts.
	for name, tc := range map[string]struct{ extra, message string }{
		"stale_test":      {"./internal/app TestRemoved 9\n", "race durations: ./internal/app TestRemoved matches no listed test"},
		"shadowed":        {"./internal/app TestOne 4\n", "race durations: ./internal/app TestOne matches no listed test"},
		"not_sharded":     {"./internal/other TestNotSharded 7\n", "race durations: ./internal/other is not a sharded package"},
		"package_renamed": {"./internal/apps TestOne 7\n", "race durations: ./internal/apps is not a sharded package"},
	} {
		t.Run("durations_"+name, func(t *testing.T) {
			t.Parallel()
			f := newScheduler(t)
			path := filepath.Join(t.TempDir(), "race-durations.txt")
			// The extra line follows every fixture line, so the earlier
			// TestOne entry shadows the duplicate.
			script.Write(t, path, []byte(fixtureDurations+tc.extra), 0o644)
			r := f.run(t, map[string]string{"TS_RACE_DURATIONS": path})
			if r.Code != 1 {
				t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
			}
			requireText(t, r.Stderr, tc.message)
			if _, err := os.Stat(f.record); !os.IsNotExist(err) {
				t.Fatal("shards ran despite stale estimates")
			}
		})
	}
	t.Run("pr", func(t *testing.T) {
		t.Parallel()
		f := newScheduler(t)
		r := f.run(t, map[string]string{"TS_TEST_TIER": "pr"})
		if r.Code != 0 {
			t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
		}
		f.complete(t, r, true)
		// Under -short the labs skip, so their short estimates queue them last.
		starts := lines(r.Stdout, "race start ")
		want := []string{"deploy-" + solo + " pool=cpu", "bootstrapstart-0 pool=cpu", "app-" + schedulerLabs[4] + " pool=idle"}
		if len(starts) != 14 || !reflect.DeepEqual(starts[:3], want) {
			t.Fatalf("starts %v, want prefix %v", starts, want)
		}
		requireText(t, r.Stdout, "race plan tier=pr ")
		requireText(t, r.Stdout, "race queue deploy-"+solo+" pool=cpu estimate=60s")
	})
	t.Run("test_failure", func(t *testing.T) {
		t.Parallel()
		f := newScheduler(t)
		r := f.run(t, map[string]string{"FAIL_TEST": "1"})
		if r.Code == 0 {
			t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
		}
		requireText(t, r.Stdout, "intentional gate failure")
		f.complete(t, r, false)
	})
	t.Run("discovery_failure", func(t *testing.T) {
		t.Parallel()
		f := newScheduler(t)
		r := f.run(t, map[string]string{"FAIL_LIST": "1"})
		if r.Code == 0 {
			t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
		}
		requireText(t, r.Stderr, "intentional discovery failure")
		if _, err := os.Stat(f.record); !os.IsNotExist(err) {
			t.Fatal("partial suite ran after discovery failure")
		}
	})
	t.Run("committed_durations", func(t *testing.T) {
		t.Parallel()
		f := newScheduler(t)
		committed := filepath.Join(t.TempDir(), "race-durations.txt")
		script.Write(t, committed, committedDurations, 0o644)
		// The fixture module lacks the real tests, so the committed named
		// estimates are stale here and fail the run after the plan prints.
		r := f.run(t, map[string]string{"TS_RACE_DURATIONS": committed})
		if r.Code != 1 || !strings.Contains(r.Stderr, "matches no listed test") {
			t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
		}
		forbidText(t, r.Stderr, "is not a sharded package")
		for _, lab := range schedulerLabs {
			requireText(t, r.Stdout, "race queue app-"+lab+" pool=idle ")
		}
		requireText(t, r.Stdout, "race queue deploy-"+solo+" pool=cpu estimate=60s")
	})
	for setting, value := range map[string]string{"TS_RACE_SHARDS": "0", "TS_RACE_NORACE_SHARDS": "0", "TS_RACE_JOBS": "0", "TS_RACE_IDLE_JOBS": "0", "TS_RACE_PACKAGE_JOBS": "0", "TS_RACE_TEST_JOBS": "0", "TS_TEST_TIER": "qualification"} {
		t.Run("invalid_"+setting, func(t *testing.T) {
			t.Parallel()
			f := newScheduler(t)
			r := f.run(t, map[string]string{setting: value})
			if r.Code != 2 {
				t.Fatalf("exit %d", r.Code)
			}
			message := setting + " must be a positive integer"
			if setting == "TS_TEST_TIER" {
				message = "TS_TEST_TIER must be pr or full"
			}
			requireText(t, r.Stderr, message)
			if len(f.readState(t).Commands) != 0 {
				t.Fatal("invalid settings invoked Go")
			}
		})
	}
	for name, durations := range map[string]string{"malformed": "./internal/app TestOne soon\n", "unknown_pool": "./internal/app TestOne 3 gpu\n", "missing": "",
		"octal": "./internal/app TestOne 08\n", "octal_short": "./internal/app TestOne 8/010\n"} {
		t.Run("durations_"+name, func(t *testing.T) {
			t.Parallel()
			f := newScheduler(t)
			path := filepath.Join(t.TempDir(), "race-durations.txt")
			if durations != "" {
				script.Write(t, path, []byte(durations), 0o644)
			}
			r := f.run(t, map[string]string{"TS_RACE_DURATIONS": path})
			if r.Code != 2 || !strings.Contains(r.Stderr, "race-durations.txt") {
				t.Fatalf("exit %d: %s", r.Code, r.Stderr)
			}
			if len(f.readState(t).Commands) != 0 {
				t.Fatal("invalid estimates invoked Go")
			}
		})
	}
}

func requireText(t *testing.T, text, fragment string) {
	t.Helper()
	if !strings.Contains(text, fragment) {
		t.Errorf("missing %q in:\n%s", fragment, text)
	}
}

func forbidText(t *testing.T, text, fragment string) {
	t.Helper()
	if strings.Contains(text, fragment) {
		t.Errorf("unexpected %q", fragment)
	}
}

// A signal to the scheduler alone must not orphan a shard's go test and
// test binary: cleanup stops each shard's whole process group.
func TestRaceSchedulerCleanupStopsShardProcessTrees(t *testing.T) {
	tools := t.TempDir()
	scheduler := filepath.Join(tools, "race-test.sh")
	script.Write(t, scheduler, raceScript, 0o755)
	durations := filepath.Join(tools, "race-durations.txt")
	script.Write(t, durations, []byte("rest - 1\n"), 0o644)
	child := filepath.Join(tools, "child.pid")
	// go test forks the test binary; the fake forks a long sleep the same way.
	goTool := filepath.Join(tools, "go")
	script.Write(t, goTool, []byte(`#!/usr/bin/env bash
case "$1 $2" in
	"list -m") echo example.test/cleanup ;;
	"list ./...") echo example.test/cleanup/other ;;
	*) sleep 300 & echo $! > "$CHILD_PID"; wait ;;
esac
`), 0o755)
	cmd := exec.Command("bash", scheduler)
	cmd.Dir = tools
	cmd.Env = append(os.Environ(), "GO="+goTool, "CHILD_PID="+child, "TS_RACE_DURATIONS="+durations, "TS_TEST_TIER=full")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if data, err := os.ReadFile(child); err == nil && strings.HasSuffix(string(data), "\n") {
			if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("the shard never started")
		}
	}
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	for deadline := time.Now().Add(10 * time.Second); processRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("shard child %d outlived the scheduler", pid)
		}
	}
}

// processRunning reports whether pid names a process that has not exited.
// Kill(pid, 0) also succeeds for a zombie, and an orphaned shard child
// stays one in a CI container whose PID 1 never reaps adopted children.
func processRunning(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// The state follows the parenthesised command name, which may itself
	// contain spaces or parentheses.
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	return len(fields) == 0 || (fields[0] != "Z" && fields[0] != "X")
}
