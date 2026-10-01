package runtimepriority

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func TestAlphaTransportPinsAndRemoteCompile(t *testing.T) {
	manifest := fullyPinnedAllocationManifest(t)
	suite := filepath.Join(script.Root(t), "tests/runtime_priority")
	path := filepath.Join(suite, "alpha_adapter.py")
	request := object{"transport": manifest["transport"], "adapter_source_path": path, "adapter_source_sha256": digest(script.Read(t, path))}
	got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", request, `m._verify_transport(a)
compile(m.REMOTE_ACTIONS, "<alpha remote action>", "exec")
result = {"verified": True}`))
	assertEqual(t, got["verified"], true)
	field(field(request, "transport"), "https")["ca_bundle_path"] = filepath.Join(t.TempDir(), "missing-ca.pem")
	got = decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", request, `result = m._verify_transport(a)`))
	assertPressureError(t, got, "TLS CA bundle pinned source file is unavailable")
}

const httpsPinObservation = `
from unittest import mock
events, requests, certificates = [], [], []
class Socket:
    def getpeercert(self, *, binary_form):
        certificates.append(binary_form)
        return a["certificate"].encode()
class Connection:
    sock = None
    def connect(self):
        events.append("connect")
        self.sock = Socket()
    def request(self, *args, **kwargs):
        events.append("request")
        requests.append([args, kwargs])
    def close(self):
        events.append("close")
connection = Connection()
with mock.patch.object(m.http.client, "HTTPSConnection", return_value=connection), mock.patch.object(m, "_credential_token") as credential, mock.patch.object(m.ssl, "create_default_context", return_value=mock.Mock()):
    try:
        m._https_request(a["request"], a["label"], a["method"], a["path"], a["body"].encode())
        result = {}
    except Exception as error:
        result = {"error": str(error), "error_type": type(error).__name__}
    result.update({"credential_calls": credential.call_count, "events": events, "requests": requests, "certificates": certificates})
`

func TestHTTPSLeafPinPrecedesSecretsAndBody(t *testing.T) {
	request := object{"transport": object{"https": object{"source_base_url": "https://source.example.test", "ca_bundle_path": "/pinned/ca.pem", "source_credential_file": "/private/source-token"}}, "deadline_seconds": 10, "managed_member": object{"source": object{"authority": object{"tls_leaf_sha256": strings.Repeat("0", 64)}}}}
	got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", object{"request": request, "certificate": "CA-valid but not the pinned leaf", "label": "source", "method": "POST", "path": "/transactions", "body": "sensitive transaction body"}, httpsPinObservation))
	assertPressureError(t, got, "peer certificate differs")
	assertEqual(t, got["events"], []string{"connect", "close"})
	assertEqual(t, got["requests"], []any{})
	assertEqual(t, got["credential_calls"], 0)
	assertEqual(t, got["certificates"], []bool{true})
}

const remoteActionObservation = `
import io, json, os, sys, textwrap
from pathlib import Path
from unittest import mock
stubs = '''
def safe_cgroup(report_path):
    return Path("/sys/fs/cgroup") / report_path.lstrip("/")
def safe_cgroup_absolute(path):
    return Path(path)
def expected_scope_path():
    return Path(payload["pressure_path"])
_original_native_role_cgroups = native_role_cgroups
def native_role_cgroups(target, native_path, database_path):
    reported, native, database = _original_native_role_cgroups(target, native_path, database_path)
    if "fake_cgroup_root" not in payload:
        return reported, native, database
    root = Path(payload["fake_cgroup_root"])
    return tuple(root / str(path).removeprefix("/sys/fs/cgroup/") for path in (reported, native, database))
def process_witness(pid):
    if payload.get("missing_process"):
        raise FileNotFoundError(pid)
    return payload["witness"]
def pressure_module():
    return None, None
'''
program = m.REMOTE_ACTIONS.replace("\ntry:\n    main()\n", textwrap.dedent(stubs) + "\ntry:\n    main()\n", 1)
output, stderr = io.StringIO(), io.StringIO()
original_open = os.open
raced = False
def race_open(path, flags, mode=0o777, *, dir_fd=None):
    global raced
    if a["race"] and not raced and path == "memory.max" and flags & os.O_WRONLY and dir_fd is not None:
        database = Path(a["request"]["remote_payload"]["fake_database_path"])
        database.rename(database.with_name("terrabase-original"))
        database.mkdir()
        for name, raw in a["replacement_files"].items():
            (database / name).write_text(raw)
        raced = True
    return original_open(path, flags, mode, dir_fd=dir_fd)
with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(a["request"]))), mock.patch.object(sys, "stdout", output), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "argv", ["remote", a["action"]]), mock.patch.object(os, "kill") as kill, mock.patch.object(os, "open", race_open):
    code = 0
    try:
        exec(program, {"__name__": "__main__"})
    except SystemExit as error:
        code = error.code
result = {"code": code, "stderr": stderr.getvalue(), "kill_calls": kill.call_count, "raced": raced}
if output.getvalue():
    result["output"] = json.loads(output.getvalue())
`

func rawStat(pid, start int) string {
	return fmt.Sprintf("%d (d15 worker) S %s%d", pid, strings.Repeat("0 ", 18), start)
}
func remoteAction(t *testing.T, request object, action string, race bool, replacements object) object {
	t.Helper()
	got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", object{"request": request, "action": action, "race": race, "replacement_files": replacements}, remoteActionObservation))
	if got["error"] != nil {
		t.Fatal(got)
	}
	return got
}
func TestRemoteSigkillRejectsChangedRoleBeforeKill(t *testing.T) {
	native := "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/runner"
	changed := native + "/another-role"
	target := object{"kind": "terrabase", "pid": 77, "process_start": "9001", "process_nonce": strings.Repeat("b", 32), "cgroup": changed, "host_boot_id": sampleBoot}
	request := object{"transport": object{"runtime": object{}}, "target_process": target, "native_runner_cgroup_path": native, "protected_database_cgroup_path": native + "/terrabase", "remote_payload": object{"witness": object{"stat_raw": rawStat(77, 9001), "cgroup_raw": "0::" + changed + "\n", "host_boot_id": sampleBoot}}}
	got := remoteAction(t, request, "failure_inject", false, object{})
	assertEqual(t, got["code"], 2)
	assertContains(t, fmt.Sprint(got["stderr"]), "RuntimeError")
	assertEqual(t, got["kill_calls"], 0)
}
func cgroupInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}
func remoteCgroupFixture(t *testing.T) (object, string) {
	t.Helper()
	temp := t.TempDir()
	root := filepath.Join(temp, "cgroup-root")
	relative := "system.slice/terrascale-host.service/supervisor/runner"
	database := filepath.Join(root, relative, "terrabase")
	native := "/sys/fs/cgroup/" + relative
	report := "/" + relative + "/terrabase"
	script.Write(t, filepath.Join(database, "memory.max"), []byte("1000\n"), 0600)
	script.Write(t, filepath.Join(database, "memory.current"), []byte("800\n"), 0600)
	script.Write(t, filepath.Join(database, "cgroup.procs"), []byte("77\n"), 0600)
	target := object{"kind": "terrabase", "pid": 77, "process_start": "9001", "process_nonce": strings.Repeat("b", 32), "cgroup": report, "host_boot_id": sampleBoot}
	intent := object{"target": target, "native_runner_cgroup_path": native, "database_cgroup_path": native + "/terrabase", "cgroup_inode": cgroupInode(t, database), "prior_memory_max_bytes": 1000, "temporary_memory_max_bytes": 500}
	request := object{"transport": object{"runtime": object{}}, "run_id": "cleanup-test", "pressure": object{"io_directory": filepath.Join(temp, "io"), "oom_fault": object{"target_memory_max_bytes": 500, "deadline_seconds": 1}}, "qualification": object{"database_memory_max_bytes": 1000}, "oom_target": target, "oom_restore_intent": intent, "native_runner_cgroup_path": native, "protected_database_cgroup_path": native + "/terrabase", "journal_watermark": object{"cursor": "before"}, "remote_payload": object{"fake_cgroup_root": root, "fake_database_path": database, "pressure_path": filepath.Join(temp, "pressure.scope"), "witness": object{"stat_raw": rawStat(77, 9001), "cgroup_raw": "0::" + report + "\n", "host_boot_id": sampleBoot}}}
	return request, database
}
func validateRemoteCleanup(t *testing.T, request, cleanup object) object {
	t.Helper()
	manifest := exampleManifest(t)
	field(manifest, "qualification")["database_memory_max_bytes"] = 1000
	return decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_runner.py", object{"manifest": manifest, "intent": request["oom_restore_intent"], "cleanup": cleanup, "observed": sampleTimestamp(time.Now()), "evidence": t.TempDir()}, `from pathlib import Path
runner = m.AdapterRunner(a["manifest"], "a" * 64, Path(a["evidence"]))
runner.oom_restore_intent = a["intent"]
try:
    runner._validate_role("cleanup_verify", "cleanup", {}, {"observed_at_utc": a["observed"], "evidence": {"cleanup": a["cleanup"]}})
    result = {}
except Exception as error:
    result = {"error": str(error), "error_type": type(error).__name__}
result.update({"verified": runner.oom_restore_cleanup_verified, "unresolved": runner.oom_restore_unresolved_reason})`))
}
func TestRemoteCleanupRestoresOnlyExactKnownCgroup(t *testing.T) {
	for _, tc := range []struct {
		name, cap, reason string
		replacement, race bool
	}{{"unknown", "700\n", "unknown cap", false, false}, {"temporary", "500\n", "", false, false}, {"replaced", "500\n", "cgroup identity changed", true, false}, {"replacement_race", "500\n", "exact TerraBase role memory.max restore could not be verified", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			request, database := remoteCgroupFixture(t)
			field(request, "remote_payload")["missing_process"] = true
			script.Write(t, filepath.Join(database, "memory.max"), []byte(tc.cap), 0600)
			if tc.replacement {
				if err := os.Rename(database, database+"-original"); err != nil {
					t.Fatal(err)
				}
				script.Write(t, filepath.Join(database, "memory.max"), []byte(tc.cap), 0600)
				if cgroupInode(t, database) == field(request, "oom_restore_intent")["cgroup_inode"] {
					t.Fatal("cgroup inode unchanged")
				}
			}
			got := remoteAction(t, request, "cleanup_verify", tc.race, object{"memory.max": "500"})
			assertEqual(t, got["code"], 0)
			cleanup := field(field(got, "output"), "cleanup")
			if tc.reason == "" {
				assertEqual(t, cleanup["oom_restore_verified"], true)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database, "memory.max")))), "1000")
			} else {
				assertEqual(t, cleanup["oom_restore_verified"], false)
				assertContains(t, fmt.Sprint(cleanup["oom_restore_unresolved_reason"]), tc.reason)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database, "memory.max")))), strings.TrimSpace(tc.cap))
			}
			runner := validateRemoteCleanup(t, request, cleanup)
			if tc.reason == "" {
				assertEqual(t, runner["verified"], true)
			} else {
				assertPressureError(t, runner, "restore obligation unresolved")
				assertEqual(t, runner["verified"], false)
				if runner["unresolved"] == nil {
					t.Fatal(runner)
				}
			}
			if tc.race {
				assertEqual(t, got["raced"], true)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database+"-original", "memory.max")))), "1000")
			}
		})
	}
}
func TestRemoteOOMCannotLowerReplacementCgroup(t *testing.T) {
	request, database := remoteCgroupFixture(t)
	got := remoteAction(t, request, "oom_fault", true, object{"memory.max": "700\n", "memory.current": "800\n", "cgroup.procs": "77\n"})
	assertEqual(t, got["code"], 2)
	assertContains(t, fmt.Sprint(got["stderr"]), "RuntimeError")
	assertEqual(t, got["raced"], true)
	assertEqual(t, string(script.Read(t, filepath.Join(database, "memory.max"))), "700\n")
	assertEqual(t, string(script.Read(t, filepath.Join(database+"-original", "memory.max"))), "1000\n")
}
