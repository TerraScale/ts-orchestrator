package ci_test

import (
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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

var schedulerLabs = []string{
	"TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss",
	"TestControllerThreeProcessBootstrapAndRestart",
	"TestLabTLSHostSessionRecoversAfterBlackholedController",
	"TestLabTLSHostSessionRecoversAfterControllerLoss",
	"TestAuthenticatedOperatorToHostDeliveryWithControllerLoss",
}

type schedulerState struct {
	Active, Maximum int
	Commands        [][]string
}

// The scheduler executes this helper as its Go wrapper. It observes process
// concurrency under an OS file lock, then delegates to the real Go toolchain.
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
		if delta >= 0 {
			state.Commands = append(state.Commands, args)
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
	root, state, record string
	expected            []string
	env                 map[string]string
}

func newScheduler(t *testing.T) schedulerFixture {
	t.Helper()
	root := t.TempDir()
	script.Write(t, filepath.Join(root, "go.mod"), []byte("module example.test/scheduler\n\ngo 1.27.0\n"), 0o644)
	f := schedulerFixture{root: root, state: filepath.Join(root, "state.json"), record: filepath.Join(root, "tests.txt")}
	for pkg, names := range map[string][]string{"app": append(slices.Clone(schedulerLabs), "TestOne", "TestTwo", "TestFail", "TestThree"), "bootstrapstart": {"TestStart", "TestRetry", "TestMaterial"}, "other": {"TestOrdinary"}} {
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
		script.Write(t, filepath.Join(root, "internal", pkg, "fixture_test.go"), []byte(source), 0o644)
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
	wrapper := filepath.Join(root, "go-wrapper")
	script.Write(t, wrapper, []byte("#!/usr/bin/env bash\nexec \"$SCHEDULER_TEST_BINARY\" -test.run='^TestSchedulerGoWrapper$' -- \"$@\"\n"), 0o755)
	f.env = map[string]string{"GO": wrapper, "REAL_GO": realGo, "SCHEDULER_TEST_BINARY": executable, "TS_SCHEDULER_WRAPPER": "1", "GOFLAGS": "-p=2", "GOMAXPROCS": "2", "TS_RACE_SHARDS": "3", "TS_RACE_JOBS": "2", "SCHEDULER_STATE": f.state, "TEST_RECORD": f.record}
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
	return script.Run(t, f.root, env, "bash", filepath.Join(script.Root(t), "scripts/ci/race-test.sh"))
}
func (f schedulerFixture) complete(t *testing.T) {
	t.Helper()
	tests := strings.Fields(string(script.Read(t, f.record)))
	slices.Sort(tests)
	if !reflect.DeepEqual(tests, f.expected) {
		t.Fatalf("tests/examples/fuzz seeds must run once: got %v want %v", tests, f.expected)
	}
	var state schedulerState
	if err := json.Unmarshal(script.Read(t, f.state), &state); err != nil {
		t.Fatal(err)
	}
	if state.Active != 0 || state.Maximum > 2 {
		t.Fatalf("concurrency active=%d maximum=%d", state.Active, state.Maximum)
	}
	var commands [][]string
	for _, args := range state.Commands {
		if args[0] == "test" {
			commands = append(commands, args)
		}
	}
	discovery := 0
	for _, args := range commands {
		if !slices.Contains(args, "-race") || !slices.Contains(args, "-vet=off") {
			t.Fatalf("missing race/vet flags: %v", args)
		}
		if slices.Contains(args, "-list") {
			discovery++
		}
	}
	if discovery != 2 || len(commands) < 2 || !slices.Contains(commands[0], "-list") || !slices.Contains(commands[1], "-list") {
		t.Fatalf("discovery should precede all shards: %v", commands)
	}
	for _, lab := range schedulerLabs {
		var matching []string
		for _, args := range commands {
			if i := slices.Index(args, "-run"); i >= 0 {
				expression := args[i+1]
				ok, err := regexp.MatchString(expression, lab)
				if err != nil {
					t.Fatal(err)
				}
				if ok {
					matching = append(matching, expression)
				}
			}
		}
		if !reflect.DeepEqual(matching, []string{"^(" + lab + ")$"}) {
			t.Fatalf("lab %s must own one shard: %v", lab, matching)
		}
	}
}
func TestRaceScheduler(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		success bool
	}{{"complete", nil, true}, {"test_failure", map[string]string{"FAIL_TEST": "1"}, false}, {"discovery_failure", map[string]string{"FAIL_LIST": "1"}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScheduler(t)
			r := f.run(t, tc.env)
			if (r.Code == 0) != tc.success {
				t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
			}
			if tc.name == "discovery_failure" {
				requireText(t, r.Stderr, "intentional discovery failure")
				if _, err := os.Stat(f.record); !os.IsNotExist(err) {
					t.Fatal("partial suite ran after discovery failure")
				}
			} else {
				if !tc.success {
					requireText(t, r.Stdout, "intentional gate failure")
				}
				f.complete(t)
			}
		})
	}
	for _, setting := range []string{"TS_RACE_SHARDS", "TS_RACE_JOBS"} {
		t.Run("invalid_"+setting, func(t *testing.T) {
			f := newScheduler(t)
			r := f.run(t, map[string]string{setting: "0"})
			if r.Code != 2 {
				t.Fatalf("exit %d", r.Code)
			}
			requireText(t, r.Stderr, setting+" must be a positive integer")
			var state schedulerState
			if err := json.Unmarshal(script.Read(t, f.state), &state); err != nil {
				t.Fatal(err)
			}
			if len(state.Commands) != 0 {
				t.Fatal("invalid concurrency invoked Go")
			}
		})
	}
}
