"""Exercise the race scheduler with real Go tests, including gate failures."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/ci/race-test.sh"
LABS = (
    "TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss",
    "TestControllerThreeProcessBootstrapAndRestart",
    "TestLabTLSHostSessionRecoversAfterBlackholedController",
    "TestLabTLSHostSessionRecoversAfterControllerLoss",
    "TestAuthenticatedOperatorToHostDeliveryWithControllerLoss",
)

# Count running test commands, then execute the real toolchain. flock makes
# the observation independent of the scheduler implementation and ordering.
WRAPPER = '''import fcntl, json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
state = Path(os.environ["SCHEDULER_STATE"])
running = args[0] == "test" and "-list" not in args
def update(delta):
    with state.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        data = json.load(f)
        data["active"] += delta
        data["maximum"] = max(data["maximum"], data["active"])
        if delta >= 0:
            data["commands"].append(args)
        f.seek(0)
        json.dump(data, f)
        f.truncate()
update(1 if running else 0)
if "-list" in args and os.environ.get("FAIL_LIST"):
    print("intentional discovery failure")
    raise SystemExit(1)
try:
    status = subprocess.run([os.environ["REAL_GO"], *args], check=False).returncode
finally:
    if running:
        update(-1)
raise SystemExit(status)
'''

GO_TEST = '''package fixture
import (
    "fmt"
    "os"
    "testing"
)
func record(name string) {
    f, err := os.OpenFile(os.Getenv("TEST_RECORD"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil { panic(err) }
    defer f.Close()
    if _, err := fmt.Fprintln(f, name); err != nil { panic(err) }
}
'''


class RaceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="race-scheduler-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "go.mod").write_text("module example.test/scheduler\n\ngo 1.27.0\n")
        self.expected = set()
        for package, names in (
            ("app", (*LABS, "TestOne", "TestTwo", "TestFail", "TestThree")),
            ("bootstrapstart", ("TestStart", "TestRetry", "TestMaterial")),
            ("other", ("TestOrdinary",)),
        ):
            directory = self.root / "internal" / package
            directory.mkdir(parents=True)
            source = GO_TEST
            for name in names:
                self.expected.add(f"{package}/{name}")
                source += f'func {name}(t *testing.T) {{ record("{package}/{name}"); '
                if name == "TestFail":
                    source += 'if os.Getenv("FAIL_TEST") != "" { t.Fatal("intentional gate failure") }; '
                source += '}\n'
            if package == "app":
                source += 'func Example() { record("app/Example"); fmt.Println("example")\n// Output: example\n}\n'
                source += 'func FuzzSeed(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, n int) { record("app/FuzzSeed") }) }\n'
                self.expected.update(("app/Example", "app/FuzzSeed"))
            (directory / "fixture_test.go").write_text(source)
        wrapper = self.root / "go-wrapper.py"
        wrapper.write_text(WRAPPER)
        self.state = self.root / "state.json"
        self.record = self.root / "tests.txt"
        self.env = dict(os.environ, GO=f"python3 {wrapper}", REAL_GO=shutil.which("go"),
                        GOFLAGS="-p=2", GOMAXPROCS="2", TS_RACE_SHARDS="3", TS_RACE_JOBS="2",
                        SCHEDULER_STATE=str(self.state), TEST_RECORD=str(self.record))

    def run_scheduler(self, **env):
        self.state.write_text(json.dumps({"active": 0, "maximum": 0, "commands": []}))
        return subprocess.run(["bash", str(RUNNER)], cwd=self.root, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=180, check=False)

    def assert_complete(self):
        tests = self.record.read_text().splitlines()
        self.assertEqual(set(tests), self.expected)
        self.assertEqual(len(tests), len(self.expected), "each test/example/fuzz seed must run exactly once")
        state = json.loads(self.state.read_text())
        self.assertEqual(state["active"], 0)
        self.assertLessEqual(state["maximum"], 2)
        commands = [args for args in state["commands"] if args[0] == "test"]
        self.assertTrue(all("-race" in args for args in commands))
        # One discovery per sharded package, before any tests start; the
        # separate module-wide vet gate owns vet, rather than each shard.
        self.assertEqual(sum("-list" in args for args in commands), 2)
        self.assertTrue(all("-list" in args for args in commands[:2]))
        self.assertTrue(all("-vet=off" in args for args in commands))
        for lab in LABS:
            matching = [args for args in commands if "-run" in args and
                        re.fullmatch(args[args.index("-run") + 1], lab)]
            self.assertEqual(len(matching), 1, lab)
            self.assertEqual(matching[0][matching[0].index("-run") + 1], f"^({lab})$")

    def test_all_tests_and_labs_run_once_with_race_and_bounded_concurrency(self):
        result = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_complete()

    def test_failed_assertion_fails_ci_after_remaining_shards_finish(self):
        result = self.run_scheduler(FAIL_TEST="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intentional gate failure", result.stdout)
        self.assert_complete()

    def test_failed_discovery_fails_ci_without_running_partial_suite(self):
        result = self.run_scheduler(FAIL_LIST="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intentional discovery failure", result.stderr)
        self.assertFalse(self.record.exists())

    def test_invalid_concurrency_fails_before_invoking_go(self):
        for setting in ("TS_RACE_SHARDS", "TS_RACE_JOBS"):
            with self.subTest(setting=setting):
                result = self.run_scheduler(**{setting: "0"})
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"{setting} must be a positive integer", result.stderr)
                self.assertEqual(json.loads(self.state.read_text())["commands"], [])


if __name__ == "__main__":
    unittest.main()
