package firecracker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

// Adapters only invoke the Python driver and expose effects. Fixtures, case
// matrices, and assertions are owned by these native Go tests.
const driverPrelude = `from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from datetime import datetime, timezone
import json, subprocess, stat, ipaddress
lab = object.__new__(m.Lab)
def attempt(fn):
    try:
        return {"value": fn(), "error": "", "error_type": ""}
    except Exception as exc:
        return {"error": str(exc), "error_type": type(exc).__name__}
def calls(mock):
    return [{"args": list(c.args), "kwargs": c.kwargs} for c in mock.call_args_list]
`

func observe(t *testing.T, a any, body string) map[string]any {
	t.Helper()
	data := script.Python(t, filepath.Join(script.Root(t), "tests/firecracker/qualify.py"), a, driverPrelude+body+`
def normalize(value):
    if isinstance(value, (datetime, Path)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if isinstance(value, dict):
        return {k:normalize(v) for k,v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    return value
result = normalize(result)`)
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}
func equal(t *testing.T, got, want any) {
	t.Helper()
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var normalizedGot, normalizedWant any
	if err := json.Unmarshal(gb, &normalizedGot); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wb, &normalizedWant); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizedGot, normalizedWant) {
		t.Fatalf("got %s, want %s", gb, wb)
	}
}
func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}
func excludes(t *testing.T, got, bad string) {
	t.Helper()
	if strings.Contains(got, bad) {
		t.Fatalf("%q contains forbidden %q", got, bad)
	}
}
func rejection(t *testing.T, got map[string]any, typ, message string) {
	t.Helper()
	equal(t, got["error_type"], typ)
	contains(t, fmt.Sprint(got["error"]), message)
}
func obj(v any) map[string]any { return v.(map[string]any) }
func arr(v any) []any          { return v.([]any) }
func encoded(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func hashPrefix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:32]
}

func TestDeployRetryContract(t *testing.T) {
	// Use the public fence constant as the response fixture, as in the original
	// suite; the Go matrix pins when it may retry and which operation IDs it uses.
	constant := observe(t, nil, `result = {"fence": m.PRE_ACCEPTANCE_FENCED}`)["fence"].(string)
	submitted := func(id, fingerprint string) map[string]any {
		return map[string]any{"operationId": id, "fingerprint": fingerprint, "status": "submitted"}
	}
	for _, tc := range []struct {
		name      string
		responses []any
		names     []string
		notes     []string
		err       string
	}{
		{"pre_acceptance_fence_retries_once", []any{submitted("fc-one-node-loss-2", "first"), map[string]any{"status": "rejected", "error": constant, "authorityEpoch": 1}, submitted("fc-one-node-loss-epoch-retry-2", "second"), map[string]any{"status": "accepted", "authorityEpoch": 2}}, []string{"one-node-loss", "one-node-loss-epoch-retry"}, []string{"fc-one-node-loss-2"}, ""},
		{"other_rejection_is_terminal", []any{submitted("fc-one-node-loss-2", "first"), map[string]any{"status": "rejected", "error": "artifact is not admitted"}}, []string{"one-node-loss"}, []string{"fc-one-node-loss-2"}, "artifact is not admitted"},
		{"second_fence_is_terminal", []any{submitted("fc-one-node-loss-2", "first"), map[string]any{"status": "rejected", "error": constant}, submitted("fc-one-node-loss-epoch-retry-2", "second"), map[string]any{"status": "rejected", "error": constant}}, []string{"one-node-loss", "one-node-loss-epoch-retry"}, []string{"fc-one-node-loss-2", "fc-one-node-loss-epoch-retry-2"}, constant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, tc.responses, `lab.operator = Mock(side_effect=a)
lab.intent = Mock(side_effect=lambda record, generation, name: Path(name))
lab.wait = Mock(side_effect=lambda label, probe, **options: probe())
lab.note = Mock()
lab.capture_cluster_diagnostics = Mock()
result = attempt(lambda: lab.deploy({}, 2, "one-node-loss"))
result.update(names=[c.args[2] for c in lab.intent.call_args_list], operator_calls=lab.operator.call_count, notes=[c.kwargs["operation_id"] for c in lab.note.call_args_list if c.args[0] == "terminal_receipt"])
`)
			equal(t, got["names"], tc.names)
			equal(t, got["operator_calls"], len(tc.responses))
			equal(t, got["notes"], tc.notes)
			if tc.err == "" {
				equal(t, got["error"], "")
			} else {
				rejection(t, got, "RuntimeError", tc.err)
			}
		})
	}
}
func TestRetryIntentOmitsEpoch(t *testing.T) {
	directory := t.TempDir()
	got := observe(t, map[string]any{"directory": directory, "record": map[string]any{"source": map[string]any{}, "digest": "artifact", "manifestDigest": "manifest"}}, `lab.stage = Path(a["directory"])
path = lab.intent(a["record"], 2, "one-node-loss-epoch-retry")
result = json.loads(path.read_text())`)
	equal(t, got["operationId"], "fc-one-node-loss-epoch-retry-2")
	if _, ok := got["authorityEpoch"]; ok {
		t.Fatal("retry pins stale epoch")
	}
}
func TestHostStatusCuratesSecretsAndSessionCurrency(t *testing.T) {
	captured := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		delta   time.Duration
		current bool
	}{{"current", 20 * time.Second, true}, {"expired", -time.Second, false}} {
		t.Run(tc.name, func(t *testing.T) {
			expiry := captured.Add(tc.delta).Format(time.RFC3339)
			statuses := []any{map[string]any{"registration": map[string]any{"node": "host-a", "environment": "test", "roles": []string{"terrabase"}, "generation": 1, "capacity": map[string]any{"cpu": 2, "memory_bytes": 256, "disk_bytes": 512}, "public_key": "secret-public-key"}, "session_expires_at": expiry, "verified": false, "reports": []any{map[string]any{"role": "terrabase", "generation": 1, "state": "running", "digest": strings.Repeat("a", 64), "epoch": 2, "observed_at": expiry, "session_id": "secret-session-id", "error": "free text"}}}}
			got := observe(t, map[string]any{"statuses": statuses, "at": captured.Format(time.RFC3339)}, `result = {"statuses":m.curated_host_statuses(a["statuses"], datetime.fromisoformat(a["at"]))}`)
			first := obj(arr(got["statuses"])[0])
			equal(t, first["session_current"], tc.current)
			equal(t, obj(arr(first["reports"])[0])["digest_prefix"], strings.Repeat("a", 12))
			excludes(t, encoded(got), "secret")
		})
	}
}
func TestOperatorFailureDiagnosticOmitsOutput(t *testing.T) {
	dir := t.TempDir()
	got := observe(t, dir, `lab.logs = Path(a)
lab.binary = Path(a)/"terrascale-orchestrator"
lab.operator_config = Path(a)/"operator.json"
lab.host_status_diagnostics_captured = set()
lab.note = Mock()
with patch.object(m, "run", return_value=SimpleNamespace(returncode=1,stdout="secret-output",stderr="secret-error")):
    lab.capture_host_status("early-pending")
result = json.loads((lab.logs/"host-status-early-pending.json").read_text())`)
	equal(t, got["status"], "operator_failed")
	equal(t, got["exit_code"], 1)
	excludes(t, encoded(got), "secret")
}

const operatorSetup = `lab.binary = Path("/tmp/unused-fc-operator")
lab.operator_config = Path("/tmp/unused-fc-config")
lab.note = Mock()
`

func TestOperatorHostsHashSessionID(t *testing.T) {
	statuses := []any{map[string]any{"registration": map[string]any{"node": "host-a"}, "session_expires_at": time.Now().Add(25 * time.Second).UTC().Format(time.RFC3339), "reports": []any{map[string]any{"role": "terrabase", "session_id": "secret-session-id"}}}}
	got := observe(t, statuses, operatorSetup+`with patch.object(m, "run", return_value=SimpleNamespace(returncode=0,stdout=json.dumps(a),stderr="")):
    returned = lab.operator("hosts")
result = {"returned":returned, "event":lab.note.call_args.kwargs}`)
	equal(t, got["returned"], statuses)
	excludes(t, encoded(got["event"]), "secret-session-id")
	contains(t, encoded(got["event"]), "session_id_hash")
}
func TestOperatorFailureRecordsStageAndBoundedTimeout(t *testing.T) {
	for _, tc := range []struct{ name, mode, typ, failure string }{{"exit", "exit", "RuntimeError", "exit_nonzero"}, {"timeout", "timeout", "TimeoutExpired", "subprocess_timeout"}} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, tc.mode, operatorSetup+`response = SimpleNamespace(returncode=1, stdout='{"session_id":"secret-session-id"}', stderr="context deadline exceeded")
kwargs = {"return_value":response} if a == "exit" else {"side_effect":subprocess.TimeoutExpired(["operator","hosts"],5,stderr=b"context deadline exceeded")}
with patch.object(m, "run", **kwargs) as command:
    result = attempt(lambda: lab.host_session("v1",timeout=4.5,stage="same-process-host-session-renewal") if a == "exit" else lab.operator("hosts",timeout=5,stage="same-process-host-session-renewal"))
result.update(event_args=list(lab.note.call_args.args),event=lab.note.call_args.kwargs,command=calls(command))`)
			rejection(t, got, tc.typ, "")
			if tc.mode == "exit" {
				contains(t, got["error"].(string), "context deadline exceeded")
			}
			event := obj(got["event"])
			equal(t, event["failure"], tc.failure)
			equal(t, event["stderr"], "context deadline exceeded")
			excludes(t, encoded(event), "secret-session-id")
			if tc.mode == "exit" {
				equal(t, got["event_args"], []string{"operator"})
				equal(t, event["stage"], "same-process-host-session-renewal")
				equal(t, event["exit_code"], 1)
				equal(t, obj(arr(got["command"])[0])["kwargs"], map[string]any{"timeout": 4.5, "allow_failure": true})
				if event["elapsed_seconds"].(float64) < 0 {
					t.Fatal("negative elapsed time")
				}
			} else {
				equal(t, event["timeout_seconds"], 5)
			}
		})
	}
}
func TestConnectedControllerParsesFourColumns(t *testing.T) {
	got := observe(t, map[string]any{"addresses": map[string]string{"host": "198.19.7.14", "c1": "198.19.7.11", "c2": "198.19.7.12", "c3": "198.19.7.13"}, "stdout": "0 0 198.19.7.14:48232 198.19.7.11:4222\n0 0 198.19.7.14:22 198.19.7.1:49300\n"}, `lab.addresses = a["addresses"]
lab.ssh = Mock(return_value=SimpleNamespace(stdout=a["stdout"]))
result = {"controller":lab.connected_controller(),"ssh":calls(lab.ssh)}`)
	equal(t, got["controller"], "c1")
	equal(t, got["ssh"], []any{map[string]any{"args": []string{"host", "ss -Hnt state established"}, "kwargs": map[string]any{"timeout": 10}}})
}
func TestGuestUnitsEnforceSupervisorBoundary(t *testing.T) {
	got := observe(t, nil, `result = {"host":m.Lab.guest_unit("host","host"),"controller":m.Lab.guest_unit("c1","run"),"ready":m.CLOCK_READY}`)
	gate := "/bin/sh -c 'while ! test -f " + got["ready"].(string) + "; do sleep 0.1; done'"
	unit := got["host"].(string)
	service := strings.Split(strings.Split(unit, "[Service]\n")[1], "\n[Install]")[0]
	directives := map[string]string{}
	var prestarts []string
	for line := range strings.SplitSeq(service, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			directives[key] = value
			if key == "ExecStartPre" {
				prestarts = append(prestarts, value)
			}
		}
	}
	for _, key := range []string{"User", "Group"} {
		if _, ok := directives[key]; ok {
			t.Fatalf("host has %s", key)
		}
	}
	for key, want := range map[string]string{"NoNewPrivileges": "yes", "Delegate": "yes", "DelegateSubgroup": "supervisor", "AmbientCapabilities": "", "TimeoutStartSec": "180"} {
		equal(t, directives[key], want)
	}
	capabilities := strings.Fields(directives["CapabilityBoundingSet"])
	equal(t, capabilities, []string{"CAP_CHOWN", "CAP_KILL", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"})
	numbers := map[string]int{"CAP_CHOWN": 0, "CAP_KILL": 5, "CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_SETPCAP": 8}
	mask := 0
	for _, name := range capabilities {
		mask += 1 << numbers[name]
	}
	equal(t, mask, 0x1e1)
	equal(t, prestarts, []string{"/usr/bin/install -d -o 2000 -g 2000 -m 0700 /run/ts-orch-workload", gate})
	controller := got["controller"].(string)
	excludes(t, controller, "CapabilityBoundingSet=")
	excludes(t, controller, "DelegateSubgroup=")
	contains(t, controller, "TimeoutStartSec=180\n")
	prestarts = nil
	for line := range strings.SplitSeq(controller, "\n") {
		if value, ok := strings.CutPrefix(line, "ExecStartPre="); ok {
			prestarts = append(prestarts, value)
		}
	}
	equal(t, prestarts, []string{gate})
}
func TestReadOnlyHostStatusRequiresSessionBoundReport(t *testing.T) {
	for _, id := range []string{"opaque-id", ""} {
		t.Run("session="+id, func(t *testing.T) {
			statuses := []any{map[string]any{"verified": false, "session_expires_at": time.Now().UTC().Add(25 * time.Second).Format(time.RFC3339), "reports": []any{map[string]any{"role": "terrabase", "state": "running", "generation": 2, "session_id": id, "epoch": 4}}}}
			got := observe(t, statuses, `lab.operator = Mock(return_value=a)
result = attempt(lambda: lab.host_session("v2"))`)
			if id == "" {
				rejection(t, got, "RuntimeError", "bound to a session")
			} else {
				equal(t, obj(got["value"])["session_id"], id)
				equal(t, obj(got["value"])["reader_verified"], false)
			}
		})
	}
}

const cleanupSetup = `lab.session_probe_process = None
lab.created_nft_tables = []
lab.created_links = []
lab.mounted = []
lab.vms = {}
lab.images = Path(a["root"])/"images"
lab.secrets = Path(a["root"])/"secrets"
lab.stage = Path(a["root"])/"stage"
lab.chrony_process = None
lab.chrony_control_dir = None
lab.note = Mock()
`

func TestBlackholeOwnsScopedTableThroughPartialFailure(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			got := observe(t, map[string]any{"root": t.TempDir(), "partial": partial, "addresses": map[string]string{"host": "198.19.7.14", "c1": "198.19.7.11"}}, cleanupSetup+`lab.addresses = a["addresses"]
lab.sudo = Mock(side_effect=[SimpleNamespace(returncode=0),RuntimeError("rule failed")]) if a["partial"] else Mock(return_value=SimpleNamespace(returncode=0,stderr=""))
with patch.object(m.secrets,"token_hex",return_value="abcde12345"), patch.object(m.shutil,"rmtree"):
    result = attempt(lambda: lab.blackhole_host_controller("c1"))
    result["tables_before_cleanup"] = list(lab.created_nft_tables)
    if not a["partial"]:
        result["cleanup"] = lab.cleanup()
result.update(tables=lab.created_nft_tables,commands=calls(lab.sudo))`)
			equal(t, got["tables_before_cleanup"], []string{"tsfcabcde12345"})
			if partial {
				rejection(t, got, "RuntimeError", "rule failed")
				equal(t, got["tables"], []string{"tsfcabcde12345"})
				return
			}
			equal(t, got["value"], "tsfcabcde12345")
			equal(t, got["cleanup"], []any{})
			equal(t, got["tables"], []any{})
			commands := arr(got["commands"])
			equal(t, obj(commands[0])["args"], []string{"nft", "add", "table", "bridge", "tsfcabcde12345"})
			rules := 0
			deleted := false
			for _, call := range commands {
				args := arr(obj(call)["args"])
				if len(args) >= 3 && encoded(args[:3]) == encoded([]string{"nft", "add", "rule"}) {
					rules++
					contains(t, encoded(args), "198.19.7.14")
					contains(t, encoded(args), "198.19.7.11")
				}
				if encoded(args) == encoded([]string{"nft", "delete", "table", "bridge", "tsfcabcde12345"}) {
					deleted = true
				}
			}
			equal(t, rules, 2)
			equal(t, deleted, true)
		})
	}
}
func journalEntry(at time.Time, message string) map[string]any {
	return map[string]any{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "MESSAGE": message}
}
func TestVerifiedLeaseParserRejectsNeighborEvents(t *testing.T) {
	at := time.Date(2026, 9, 24, 12, 0, 1, 0, time.UTC)
	expiry := at.Add(30 * time.Second)
	hash := hashPrefix("opaque-id")
	renewal := fmt.Sprintf("2026/09/24 12:00:01 INFO host session accepted phase=renew session_id_hash=%s epoch=2 expires_at=%s", hash, expiry.Format(time.RFC3339))
	messages := []string{renewal, strings.Replace(renewal, "INFO host session accepted", "WARN host session accepted", 1), strings.Replace(renewal, "host session accepted", "host session exchange recovered", 1), strings.Replace(renewal, "2026/09/24 12:00:01", "2026/02/31 12:00:01", 1), strings.Replace(renewal, "session_id_hash="+hash, "session_id_hash=not-a-digest", 1), strings.Replace(renewal, "epoch=2", "epoch=2 epoch=3", 1), strings.Replace(renewal, "session_id_hash="+hash+" ", "", 1), fmt.Sprintf("time=2026-09-24T12:00:01Z level=INFO msg=\"host session accepted\" phase=renew session_id_hash=%s epoch=2 expires_at=%s", hash, expiry.Format(time.RFC3339))}
	var entries []string
	for _, message := range messages {
		entries = append(entries, encoded(journalEntry(at, message)))
	}
	entries = append(entries, encoded(journalEntry(at.Add(-2*time.Second), renewal)))
	got := observe(t, map[string]any{"stdout": strings.Join(entries, "\n") + "\n", "since": at.Add(-time.Second).Format(time.RFC3339)}, `lab.ssh = Mock(return_value=SimpleNamespace(stdout=a["stdout"]))
events = lab.verified_lease_events(datetime.fromisoformat(a["since"]))
result = {"events":[dict(e, at=e["at"].isoformat(),expires_at=e["expires_at"].isoformat()) for e in events]}`)
	events := arr(got["events"])
	equal(t, len(events), 1)
	event := obj(events[0])
	equal(t, event["expires_at"], expiry.Format("2006-01-02T15:04:05+00:00"))
	equal(t, event["session_id_hash"], hash)
	equal(t, event["phase"], "renew")
	excludes(t, strings.Join(entries, "\n"), "opaque-id")
}
func TestFenceBindsLatestSignedLeaseBeforeExpiry(t *testing.T) {
	expiry := time.Date(2026, 9, 24, 12, 0, 30, 0, time.UTC)
	since := expiry.Add(-20 * time.Second)
	hash := hashPrefix("opaque-id")
	fenceAt := expiry.Add(-4500 * time.Millisecond)
	failed := journalEntry(expiry.Add(-15*time.Second), "2026/09/24 12:00:15 WARN host session exchange deferred stage=renew cause_class=unavailable endpoint=host.lab.fc remaining_seconds=15")
	fenced := fmt.Sprintf("2026/09/24 12:00:25 INFO host session fenced session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted", hash, expiry.Format(time.RFC3339))
	wrongHash := strings.Replace(fenced, hash, strings.Repeat("0", 32), 1)
	wrongEpoch := strings.Replace(fenced, "epoch=3", "epoch=4", 1)
	legacy := fmt.Sprintf("time=2026-09-24T12:00:25Z level=INFO msg=\"host session fenced\" session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted", hash, expiry.Format(time.RFC3339))
	for _, tc := range []struct {
		name           string
		messages       []string
		expectedExpiry time.Time
		valid          bool
	}{{"matching", []string{wrongHash, wrongEpoch, legacy, fenced}, expiry, true}, {"wrong_hash", []string{wrongHash}, expiry, false}, {"wrong_epoch", []string{wrongEpoch}, expiry, false}, {"wrong_expiry", []string{fenced}, expiry.Add(time.Second), false}, {"legacy", []string{legacy}, expiry, false}} {
		t.Run(tc.name, func(t *testing.T) {
			entries := []string{encoded(failed)}
			for _, message := range tc.messages {
				entries = append(entries, encoded(journalEntry(fenceAt, message)))
			}
			got := observe(t, map[string]any{"stdout": strings.Join(entries, "\n") + "\n", "since": since.Format(time.RFC3339), "hash": hash, "expiry": tc.expectedExpiry.Format(time.RFC3339)}, `lab.note = Mock()
lab.ssh = Mock(return_value=SimpleNamespace(returncode=0,stdout=a["stdout"]))
result = attempt(lambda: lab.host_renewal_failure_evidence(datetime.fromisoformat(a["since"]), a["hash"],3,datetime.fromisoformat(a["expiry"])))
result["events"] = calls(lab.note)`)
			if !tc.valid {
				rejection(t, got, "RuntimeError", "matching fence")
				return
			}
			equal(t, got["error"], "")
			event := obj(obj(arr(got["events"])[len(arr(got["events"]))-1])["kwargs"])
			equal(t, event["fence_cause_class"], "reserve_exhausted")
			equal(t, event["actual_fence_started_at"], fenceAt.Format("2006-01-02T15:04:05.000000+00:00"))
		})
	}
}

const nativeService = "/system.slice/ts-orch.service"
const nativePath = nativeService + "/terrascale-host-f2f2e59c89f0cea0/terrabase"

func TestNativeCgroupPathBoundToUnitAndPopulated(t *testing.T) {
	for _, tc := range []struct {
		stdout string
		empty  bool
		err    string
	}{{"populated 1\nfrozen 0\n", false, ""}, {"populated 0\nfrozen 0\n", true, ""}, {"populated 0\npopulated 1\n", false, "no populated state"}} {
		t.Run(strings.TrimSpace(tc.stdout), func(t *testing.T) {
			got := observe(t, map[string]any{"path": nativePath, "service": nativeService, "stdout": tc.stdout}, `m.validate_native_cgroup_path(a["path"],a["service"])
lab.ssh = Mock(return_value=SimpleNamespace(stdout=a["stdout"]))
result = attempt(lambda: lab.cgroup_empty(a["path"],a["service"]))
result["command"] = lab.ssh.call_args.args[1]`)
			if tc.err != "" {
				rejection(t, got, "RuntimeError", tc.err)
				return
			}
			equal(t, got["value"], tc.empty)
			command := got["command"].(string)
			for _, fragment := range []string{"systemctl show ts-orch.service -p ControlGroup --value", `test ! -L "$entry"`, "grep -qw memory /sys/fs/cgroup" + nativeService + "/cgroup.controllers", `test ! -s "$parent/cgroup.procs"`, `grep -qw memory "$parent/cgroup.subtree_control"`, "/sys/fs/cgroup" + strings.TrimSuffix(nativePath, "/terrabase"), nativePath + "/cgroup.events", "elif test -e /sys/fs/cgroup" + nativePath + "; then exit 5"} {
				contains(t, command, fragment)
			}
		})
	}
}
func TestNativeCgroupPathRejectsTraversalAndOtherRoles(t *testing.T) {
	cases := [][2]string{{strings.Replace(nativePath, "/system.slice/", "/system.slice/../", 1), nativeService}, {strings.Replace(nativePath, "/ts-orch.service/", "/ts-orch.service/./", 1), nativeService}, {strings.Replace(nativePath, "terrascale-host-", "terrascale.host-", 1), nativeService}, {strings.Replace(nativePath, "f2f2e59c89f0cea0", "g2f2e59c89f0cea0", 1), nativeService}, {strings.Replace(nativePath, "/terrabase", "/other", 1), nativeService}, {strings.Replace(nativePath, "/terrascale-host-", "/supervisor/terrascale-host-", 1), nativeService}, {nativePath + "/child", nativeService}, {nativePath, "/system.slice/other.service"}, {nativePath, "/system.slice/../ts-orch.service"}}
	for _, tc := range cases {
		t.Run(tc[0]+tc[1], func(t *testing.T) {
			got := observe(t, tc, `result = attempt(lambda: m.validate_native_cgroup_path(a[0],a[1]))`)
			rejection(t, got, "ValueError", "invalid native workload cgroup path")
		})
	}
}
func TestNativeObservationBindsPIDAndAgentUnit(t *testing.T) {
	output := "agent_pid=1353\nagent_state=S:3500\nagent_cgroup=" + nativeService + "/supervisor\nservice_cgroup=" + nativeService + "\ninvocation=valid-invocation\nworkload_pid=1391\nworkload_state_before=S:3537\nworkload_state=S:3537\nworkload_cgroup=" + nativePath + "\nmarker=v1\n"
	cases := []struct {
		name, output, typ, err string
		alive                  bool
	}{{"running", output, "", "", true}, {"exited", strings.Replace(output, "workload_state=S:3537", "workload_state=missing", 1), "", "", false}, {"missing_before", strings.Replace(output, "workload_state_before=S:3537", "workload_state_before=missing", 1), "RuntimeError", "PID changed", false}, {"changed_pid", strings.Replace(output, "workload_state=S:3537", "workload_state=S:9999", 1), "RuntimeError", "PID changed", false}, {"wrong_workload", strings.Replace(output, "workload_cgroup="+nativePath, "workload_cgroup="+nativeService+"/supervisor/terrabase", 1), "ValueError", "invalid native workload cgroup path", false}}
	for _, wrong := range []string{nativeService, nativeService + "/other", "/system.slice/other.service/supervisor"} {
		cases = append(cases, struct {
			name, output, typ, err string
			alive                  bool
		}{"agent=" + wrong, strings.Replace(output, "agent_cgroup="+nativeService+"/supervisor", "agent_cgroup="+wrong, 1), "RuntimeError", "not in its systemd supervisor subgroup", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, tc.output, `lab.ssh = Mock(return_value=SimpleNamespace(stdout=a))
result = attempt(lab.native_observation)`)
			if tc.err != "" {
				rejection(t, got, tc.typ, tc.err)
				return
			}
			value := obj(got["value"])
			equal(t, value["workload_alive"], tc.alive)
			equal(t, value["agent_cgroup"], nativeService+"/supervisor")
			if tc.alive {
				equal(t, value["workload_cgroup"], nativePath)
			} else {
				equal(t, value["workload_cgroup"], "")
			}
		})
	}
}

func TestClockMeasurementUsesMonotonicUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name, guest         string
		real, mono          []int64
		offset, uncertainty int64
		err                 string
		sync                bool
	}{{"measurement", "100150000000", []int64{100_000_000_000, 100_300_000_000}, []int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 151_500_000, "", false}, {"realtime_back", "100000000000", []int64{100_000_000_000, 98_000_000_000}, []int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 0, "lab host clock changed", true}, {"realtime_forward", "100000000000", []int64{100_000_000_000, 102_000_000_000}, []int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 0, "lab host clock changed", true}, {"invalid_monotonic", "100000000000", []int64{100_000_000_000, 100_000_000_000}, []int64{0, 1_000_000, 500_000, 2_000_000}, 0, 0, "monotonic clock changed", false}} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, map[string]any{"guest": tc.guest, "real": tc.real, "mono": tc.mono, "sync": tc.sync}, `lab.ssh = Mock(return_value=SimpleNamespace(stdout=a["guest"]))
lab.wait = Mock(return_value=True)
lab.guest_clock_upper_ns = {}
lab.note = Mock()
with patch.object(m.time,"time_ns",side_effect=a["real"]), patch.object(m.time,"monotonic_ns",side_effect=a["mono"]):
    result = attempt(lambda: lab.wait_synchronized_guest_clock("c1") if a["sync"] else lab.measure_guest_clock("c1"))
result.update(upper=lab.guest_clock_upper_ns,ssh_calls=lab.ssh.call_count)`)
			if tc.err != "" {
				rejection(t, got, "RuntimeError", tc.err)
				equal(t, got["upper"], map[string]any{})
				if tc.sync {
					equal(t, got["ssh_calls"], 1)
				}
				return
			}
			equal(t, got["value"], []int64{tc.offset, tc.uncertainty})
			equal(t, obj(got["upper"])["c1"], tc.uncertainty)
		})
	}
}

const clockSetup = `lab.ssh = Mock(return_value=SimpleNamespace(returncode=0))
lab.measure_guest_clock = Mock(side_effect=a["measurements"])
lab.note = Mock()
`

func TestClockReleaseRequiresNTPKernelHealthAndFreshService(t *testing.T) {
	for _, tc := range []struct {
		name         string
		measurements [][2]int64
		responses    []map[string]any
		err, typ     string
		calls        int
	}{{"healthy", [][2]int64{{-100_000_000, 100_000_000}, {-100_000_000, 100_000_000}}, []map[string]any{{"returncode": 0}, {"returncode": 0, "stdout": `{"healthy":true,"kernel_maxerror_us":1000}`}, {"returncode": 0}}, "", "", 3}, {"unhealthy", nil, []map[string]any{{"returncode": 0}, {"returncode": 1, "stdout": `{"healthy":false}`}}, "NTP clock", "TimeoutError", 2}, {"already_running", [][2]int64{{-1_414_932_418, 139_698_286}}, []map[string]any{{"returncode": 1}}, "before NTP clock readiness", "RuntimeError", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, map[string]any{"measurements": tc.measurements, "responses": tc.responses, "mode": tc.name}, clockSetup+`lab.ssh.side_effect = [SimpleNamespace(**r) for r in a["responses"]]
def readiness(label,probe,**options):
    value = probe()
    if a["mode"] == "unhealthy" and not value:
        raise TimeoutError("NTP clock stayed unhealthy")
    return value
lab.wait = Mock(side_effect=readiness)
result = attempt(lambda: lab.release_synchronized_guest_clock("c1"))
result.update(commands=[c.args[1] for c in lab.ssh.call_args_list],measurements=lab.measure_guest_clock.call_count,ready=m.CLOCK_READY)`)
			equal(t, len(arr(got["commands"])), tc.calls)
			if tc.err != "" {
				rejection(t, got, tc.typ, tc.err)
				if tc.name == "already_running" {
					equal(t, got["measurements"], 0)
				}
				return
			}
			equal(t, got["error"], "")
			commands := arr(got["commands"])
			contains(t, commands[1].(string), "systemd-timesyncd.service")
			contains(t, commands[1].(string), "ts-orch-clockprobe")
			equal(t, commands[2], "/usr/bin/install -m 0600 /dev/null "+got["ready"].(string))
			for _, command := range commands {
				excludes(t, command.(string), "date -u --set=")
			}
		})
	}
}
func TestClockDiagnosticFailurePreservesOriginalTimeout(t *testing.T) {
	got := observe(t, map[string]any{"measurements": [][2]int64{}}, clockSetup+`lab.wait = Mock(side_effect=TimeoutError("NTP clock remained unsynchronized"))
lab.capture_clock_diagnostics = Mock(side_effect=OSError("diagnostic storage unavailable"))
result = attempt(lambda: lab.wait_synchronized_guest_clock("c1"))
result.update(captures=calls(lab.capture_clock_diagnostics),notes=calls(lab.note))`)
	rejection(t, got, "TimeoutError", "remained unsynchronized")
	equal(t, got["captures"], []any{map[string]any{"args": []string{"c1"}, "kwargs": map[string]any{}}})
	equal(t, got["notes"], []any{map[string]any{"args": []string{"clock_diagnostics"}, "kwargs": map[string]any{"guest": "c1", "status": "capture_failed", "error_type": "OSError"}}})
}
func TestSSHWaitOrdersClockBeforeRuntime(t *testing.T) {
	got := observe(t, nil, `order = []
lab.wait = Mock(side_effect=lambda label,probe,**options:order.append(label))
lab.release_synchronized_guest_clock = Mock(side_effect=lambda name:order.append("ntp-"+name))
lab.wait_ssh("c1")
result = {"order":order}`)
	equal(t, got["order"], []string{"ssh-c1", "ntp-c1", "service-c1"})
}
func TestClockCheckKeepsStrictOneSecondBound(t *testing.T) {
	got := observe(t, map[string]any{"measurements": [][2]int64{{900_000_000, 100_000_001}}}, clockSetup+`result = attempt(lab.check_guest_clocks)
result["ssh_calls"] = lab.ssh.call_count`)
	rejection(t, got, "RuntimeError", "over one second")
	equal(t, got["ssh_calls"], 0)
}
func TestBrokerClockFaultBudgetIncludesSSH(t *testing.T) {
	dir := t.TempDir()
	got := observe(t, map[string]any{"root": dir, "date_duration": 12, "health_duration": 10}, `lab.logs = Path(a["root"])
lab.secrets = Path(a["root"])
lab.natsdiag = Path(a["root"])/"natsdiag"
lab.addresses = {"c1":"198.19.1.11"}
lab.note = Mock()
lab.wait = Mock(return_value=True)
elapsed = [0.0]
def ssh(name,command,**options):
    if "date -u --set=" in command:
        elapsed[0] += a["date_duration"]
        return SimpleNamespace(returncode=0)
    if "ts-orch-clockprobe" in command:
        elapsed[0] += a["health_duration"]
        return SimpleNamespace(returncode=1,stdout='{"healthy":false}')
    return SimpleNamespace(returncode=0)
lab.ssh = Mock(side_effect=ssh)
with patch.object(m.subprocess,"Popen",return_value=Mock()),patch.object(m.time,"monotonic",side_effect=lambda:elapsed[0]):
    result = attempt(lab.verify_broker_clock_gate)
result.update(ssh_calls=lab.ssh.call_count,wait_calls=lab.wait.call_count)`)
	rejection(t, got, "TimeoutError", "20-second fault budget")
	equal(t, got["ssh_calls"], 2)
	equal(t, got["wait_calls"], 1)
}
func TestAssetPinsAndHashMismatch(t *testing.T) {
	got := observe(t, nil, `result = {"kernel":m.KERNEL_SHA,"rootfs":m.ROOTFS_SHA}`)
	equal(t, got["kernel"], "586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523")
	equal(t, got["rootfs"], "a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6")
	dir := t.TempDir()
	script.Write(t, filepath.Join(dir, "kernel"), []byte("unverified kernel"), 0o600)
	script.Write(t, filepath.Join(dir, "rootfs"), []byte("unverified rootfs"), 0o600)
	got = observe(t, dir, `result = attempt(lambda: m.preflight(SimpleNamespace(kernel=Path(a)/"kernel",rootfs=Path(a)/"rootfs")))`)
	rejection(t, got, "RuntimeError", "SHA-256 mismatch")
}
func TestAPISocketPathIsPrivateShortAndBounded(t *testing.T) {
	dir := t.TempDir()
	durable := filepath.Join(dir, "durable-"+strings.Repeat("x", 180))
	sockets := filepath.Join(dir, "tsfc-a1b2c3")
	for _, path := range []string{durable, sockets} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := observe(t, map[string]any{"durable": durable, "sockets": sockets, "rootfs": filepath.Join(dir, "rootfs.ext4")}, `vm = m.VM(SimpleNamespace(root=Path(a["durable"]),socket_dir=Path(a["sockets"])),"host","198.19.1.14","tap0",Path(a["rootfs"]))
result = {"socket":str(vm.socket),"limit":m.MAX_UNIX_SOCKET_PATH_BYTES}`)
	equal(t, got["socket"], filepath.Join(sockets, "host.sock"))
	limit := int(got["limit"].(float64))
	if len([]byte(got["socket"].(string))) > limit {
		t.Fatal("socket exceeds Unix path limit")
	}
	if len([]byte(filepath.Join(durable, "vms/host/api.sock"))) <= limit {
		t.Fatal("long fixture no longer exercises path limit")
	}
	got = observe(t, filepath.Join("/tmp", strings.Repeat("x", limit)), `result = attempt(lambda: str(m.firecracker_socket_path(Path(a),"host")))`)
	rejection(t, got, "ValueError", "socket path is too long")
}
func TestSocketCleanupOnlyUnlinksOwnedStoppedSockets(t *testing.T) {
	for _, running := range []bool{false, true} {
		t.Run(fmt.Sprint(running), func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "host.sock")
			unrelated := filepath.Join(dir, "leave-me")
			script.Write(t, socket, nil, 0o600)
			script.Write(t, unrelated, nil, 0o600)
			got := observe(t, map[string]any{"dir": dir, "socket": socket, "running": running}, `vm = SimpleNamespace(name="host",process=SimpleNamespace(pid=1234) if a["running"] else None,socket=Path(a["socket"]))
result = {"errors":m.cleanup_owned_sockets({"host":vm},Path(a["dir"]))}`)
			_, err := os.Stat(socket)
			equal(t, err == nil, running)
			if _, err := os.Stat(unrelated); err != nil {
				t.Fatal("unrelated path removed", err)
			}
			errors := arr(got["errors"])
			equal(t, len(errors), 1)
			if running {
				equal(t, errors[0], "keep Firecracker API sockets until host is confirmed stopped")
			} else {
				contains(t, errors[0].(string), "empty Firecracker API socket directory")
			}
		})
	}
}
func TestFailedCleanupRetainsGuestImages(t *testing.T) {
	dir := t.TempDir()
	got := observe(t, map[string]any{"root": dir}, cleanupSetup+`with patch.object(m.shutil,"rmtree") as removed:
    errors = lab.cleanup(preserve_images=True)
result = {"errors":errors,"removed":[str(c.args[0]) for c in removed.call_args_list],"notes":calls(lab.note)}`)
	equal(t, got["errors"], []any{})
	for _, path := range arr(got["removed"]) {
		if path == filepath.Join(dir, "images") {
			t.Fatal("failure removed images")
		}
	}
	equal(t, got["notes"], []any{map[string]any{"args": []string{"guest_images_retained"}, "kwargs": map[string]any{"path": filepath.Join(dir, "images"), "reason": "qualification_failed"}}})
}

func TestProcessGroupSignalsPrecedeLeaderReap(t *testing.T) {
	got := observe(t, nil, `operations = []
process = Mock(pid=1234,returncode=None)
process.wait.side_effect = lambda **options: operations.append(["reap",options])
with patch.object(m.os,"getpgid",return_value=1234), patch.object(m.os,"killpg",side_effect=lambda pgid,sig: operations.append(["signal",pgid,int(sig)])), patch.object(m,"wait_child_without_reaping",side_effect=lambda child,timeout: operations.append(["wait",child.pid,timeout])), patch.object(m,"wait_for_process_group_quiescence",side_effect=lambda pgid,timeout: operations.append(["quiescent",pgid,timeout])):
    m.stop_process_group(process,timeout=1)
result = {"operations":operations}`)
	equal(t, got["operations"], []any{[]any{"signal", 1234, 15}, []any{"wait", 1234, 1}, []any{"signal", 1234, 9}, []any{"quiescent", 1234, 1}, []any{"reap", map[string]any{"timeout": 1}}})
}
func TestProcessGroupRejectsReapedLeaderAndRetainsLiveGroup(t *testing.T) {
	for _, reaped := range []bool{true, false} {
		t.Run(fmt.Sprint(reaped), func(t *testing.T) {
			got := observe(t, reaped, `process = Mock(pid=1234,returncode=0 if a else None)
with patch.object(m.os,"getpgid",return_value=1234) as getpgid, patch.object(m.os,"killpg") as killpg, patch.object(m,"wait_child_without_reaping",return_value=True), patch.object(m,"live_process_group_members",return_value=[5678]), patch.object(m.time,"monotonic",side_effect=[10,11]), patch.object(m.time,"sleep"):
    result = attempt(lambda:m.stop_process_group(process,timeout=1))
result.update(getpgid_calls=getpgid.call_count,signals=[list(c.args) for c in killpg.call_args_list],wait_calls=process.wait.call_count,returncode=process.returncode)`)
			equal(t, got["wait_calls"], 0)
			if reaped {
				rejection(t, got, "RuntimeError", "reaped before group cleanup")
				equal(t, got["getpgid_calls"], 0)
				equal(t, got["signals"], []any{})
			} else {
				rejection(t, got, "TimeoutError", "still has live members")
				equal(t, got["signals"], [][2]int{{1234, 15}, {1234, 9}})
				equal(t, got["returncode"], nil)
			}
		})
	}
}
func TestChildExitProbeObservesWithoutReaping(t *testing.T) {
	got := observe(t, nil, `process = Mock(pid=1234,returncode=None)
with patch.object(m.os,"waitid",return_value=SimpleNamespace(si_pid=1234)) as waitid:
    value = m.child_exited_without_reaping(process)
result = {"value":value,"waitid":calls(waitid),"flags":[int(m.os.P_PID),int(m.os.WEXITED|m.os.WNOHANG|m.os.WNOWAIT)],"wait_calls":process.wait.call_count}`)
	equal(t, got["value"], true)
	equal(t, got["wait_calls"], 0)
	flags := arr(got["flags"])
	equal(t, got["waitid"], []any{map[string]any{"args": []any{flags[0], 1234, flags[1]}, "kwargs": map[string]any{}}})
}
func TestProcessGroupKillsTermIgnoringChildBeforeReapingLeader(t *testing.T) {
	// This is a real process-group integration observation. The Python boundary
	// is required because the production API takes a subprocess.Popen object.
	got := observe(t, map[string]any{"child": "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(60)", "leader": "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c',sys.argv[1]], stdout=subprocess.PIPE,text=True); ready=child.stdout.readline().strip(); print(ready, flush=True); print(child.pid, flush=True); time.sleep(60)"}, `leader = subprocess.Popen([m.sys.executable,"-c",a["leader"],a["child"]],stdout=subprocess.PIPE,text=True,start_new_session=True)
ready = leader.stdout.readline().strip()
child_pid = int(leader.stdout.readline().strip())
original = m.wait_for_process_group_quiescence
observations = []
def group(pgid,timeout):
    original(pgid,timeout)
    states = []
    for pid in (leader.pid,child_pid):
        try:
            states.append(Path("/proc/%d/stat"%pid).read_text().rsplit(")",1)[1].split()[0])
        except FileNotFoundError:
            states.append(None)
    observations.append({"returncode":leader.returncode,"states":states})
try:
    with patch.object(m,"wait_for_process_group_quiescence",side_effect=group):
        m.stop_process_group(leader,timeout=2)
    result = {"ready":ready,"observations":observations,"returncode":leader.returncode}
finally:
    if leader.returncode is None:
        m.os.killpg(leader.pid,m.signal.SIGKILL)
        leader.wait()
    leader.stdout.close()`)
	equal(t, got["ready"], "ready")
	observations := arr(got["observations"])
	equal(t, len(observations), 1)
	equal(t, obj(observations[0])["returncode"], nil)
	for _, state := range arr(obj(observations[0])["states"]) {
		if state != nil && state != "Z" && state != "X" {
			t.Fatalf("live process before leader reap: %v", state)
		}
	}
	if got["returncode"] == nil {
		t.Fatal("leader never reaped")
	}
}
func TestClusterDiagnosticUsesSeparateCredentials(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"secrets/c1.creds", "secrets/natsdiag.creds", "natsdiag"} {
		script.Write(t, filepath.Join(dir, name), nil, 0o600)
	}
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := observe(t, dir, `lab.secrets = Path(a)/"secrets"
lab.logs = Path(a)/"logs"
lab.natsdiag = Path(a)/"natsdiag"
lab.vms = {}
lab.addresses = {name:"198.19.1.%d"%index for index,name in enumerate(m.CONTROLLERS,11)}
lab.active_operation_id = None
lab.note = Mock()
lab.capture_host_status = Mock()
lab.cluster_diagnostics_captured = False
with patch.object(m,"run",return_value=SimpleNamespace(stdout="",stderr="",returncode=0)) as command:
    lab.capture_cluster_diagnostics()
result = {"command":command.call_args.args[0]}`)
	command := arr(got["command"])
	index := -1
	for i, value := range command {
		if value == "--operator-creds" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("no credential option")
	}
	equal(t, command[index+1], filepath.Join(dir, "secrets/natsdiag.creds"))
	excludes(t, encoded(command), filepath.Join(dir, "secrets/operator.creds"))
}
func TestRenewalUsesSingle25SecondDeadline(t *testing.T) {
	fault := time.Now().UTC()
	original := fault.Add(25 * time.Second)
	renewed := original.Add(5 * time.Second)
	native := map[string]any{"agent_pid": "940", "agent_state": "S:123", "invocation": "unit-1", "workload_pid": "1209", "workload_state": "S:456", "workload_alive": true, "marker": "v1"}
	for _, tc := range []struct {
		name      string
		monotonic []float64
		typ, err  string
	}{{"within_deadline", []float64{100, 123, 124.5, 124.8, 124.9}, "", ""}, {"late_probe", []float64{100, 101, 102, 103, 126}, "TimeoutError", "renewal deadline passed"}, {"failed_operator", []float64{100, 101, 102, 126}, "TimeoutError", "same-process-host-session-renewal"}} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, map[string]any{"mode": tc.name, "monotonic": tc.monotonic, "fault": fault.Format(time.RFC3339Nano), "original": original.Format(time.RFC3339Nano), "renewed": renewed.Format(time.RFC3339Nano), "native": native, "hash": hashPrefix("opaque-session")}, `fault = datetime.fromisoformat(a["fault"])
original = datetime.fromisoformat(a["original"])
renewed = datetime.fromisoformat(a["renewed"])
first = {"session_id":"opaque-session","expires_at":original}
lab.host_session = Mock(return_value={"session_id":"opaque-session","expires_at":renewed,"report":{"epoch":2}})
lab.native_observation = Mock(return_value=a["native"])
lab.verified_lease_events = Mock(return_value=[{"at":fault+m.timedelta(seconds=1),"expires_at":renewed,"session_id_hash":a["hash"],"epoch":2,"phase":"renew"}])
lab.note = Mock()
probe_values = []
def wait(label,probe,**options):
    value = probe()
    probe_values.append(value)
    if a["mode"] == "late_probe":
        raise TimeoutError("renewal deadline passed")
    return value
if a["mode"] != "failed_operator":
    lab.wait = Mock(side_effect=wait)
else:
    lab.host_session.side_effect = RuntimeError("operator hosts: context deadline exceeded")
with patch.object(m.time,"monotonic",side_effect=a["monotonic"]),patch.object(m.time,"sleep"):
    result = attempt(lambda:lab.wait_same_process_renewal(first,a["native"],"c2",fault))
result.update(host_calls=calls(lab.host_session),native_calls=calls(lab.native_observation),lease_calls=calls(lab.verified_lease_events),notes=calls(lab.note),probe_values=probe_values)
if a["mode"] != "failed_operator":
    result["wait_kwargs"] = lab.wait.call_args.kwargs`)
			if tc.err == "" {
				equal(t, got["error"], "")
				equal(t, obj(got["wait_kwargs"])["deadline"], 125)
				equal(t, obj(arr(got["host_calls"])[0])["kwargs"], map[string]any{"timeout": 2, "stage": "same-process-host-session-renewal"})
				equal(t, obj(arr(got["native_calls"])[0])["kwargs"], map[string]any{"timeout": 0.5})
				timeout := obj(obj(arr(got["lease_calls"])[0])["kwargs"])["timeout"].(float64)
				if timeout < 0.199999 || timeout > 0.200001 {
					t.Fatalf("lease timeout %v", timeout)
				}
				equal(t, obj(arr(got["notes"])[0])["args"], []string{"host_session_renewed_on_surviving_quorum"})
				return
			}
			rejection(t, got, tc.typ, tc.err)
			notes := arr(got["notes"])
			equal(t, len(notes), 1)
			equal(t, obj(notes[0])["args"], []string{"host_renewal_timeout_diagnostics"})
			equal(t, len(arr(obj(obj(notes[0])["kwargs"])["renewals"])), 1)
			if tc.name == "late_probe" {
				equal(t, got["probe_values"], []bool{false})
				equal(t, obj(obj(notes[0])["kwargs"])["status"], "ok")
				equal(t, obj(obj(arr(got["lease_calls"])[len(arr(got["lease_calls"]))-1])["kwargs"])["timeout"], 5)
			} else {
				equal(t, got["native_calls"], []any{})
				equal(t, obj(obj(arr(got["host_calls"])[0])["kwargs"])["timeout"], 5)
			}
		})
	}
}

const ntpSetup = `lab.bridge = a["bridge"]
lab.subnet = ipaddress.ip_network(a["subnet"])
lab.ntp_rule_comment = None
lab.ntp_rule_handle = None
lab.note = Mock()
`

func ntpRule(comment, destination string) map[string]any {
	match := func(left, right any) map[string]any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) map[string]any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	return map[string]any{"family": "ip", "table": "filter", "chain": "INPUT", "handle": 101, "comment": comment, "expr": []any{match(map[string]any{"meta": map[string]any{"key": "iifname"}}, "tsfabc123b"), match(payload("ip", "saddr"), map[string]any{"prefix": map[string]any{"addr": "198.19.7.0", "len": 24}}), match(payload("ip", "daddr"), destination), match(payload("udp", "dport"), 123), map[string]any{"counter": map[string]any{"packets": 3, "bytes": 228}}, map[string]any{"accept": nil}}}
}
func ntpChain(hook string, jump bool) map[string]any {
	entries := []any{map[string]any{"chain": map[string]any{"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": hook}}}
	if jump {
		entries = append(entries, map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "INPUT", "handle": 17, "expr": []any{map[string]any{"jump": map[string]any{"target": "nixos-fw"}}}}})
	}
	return map[string]any{"nftables": entries}
}
func ntpArgs() map[string]any {
	return map[string]any{"bridge": "tsfabc123b", "subnet": "198.19.7.0/24", "chain": ntpChain("input", true), "rule": ntpRule("", "198.19.7.1")}
}
func TestNTPFirewallInstallsScopedOwnedRuleAndDeletesByHandle(t *testing.T) {
	a := ntpArgs()
	a["token"] = strings.Repeat("a", 24)
	got := observe(t, a, ntpSetup+`active = [None]
def sudo(*args,**options):
    if args[:5] == ("nft","-j","-a","list","chain"):
        entries = list(a["chain"]["nftables"])
        if active[0] is not None:
            entries.insert(1,{"rule":active[0]})
        return SimpleNamespace(stdout=json.dumps({"nftables":entries}),returncode=0)
    if args[:3] == ("nft","insert","rule"):
        active[0] = dict(a["rule"],comment=args[-1])
    elif args[:3] == ("nft","delete","rule"):
        active[0] = None
    return SimpleNamespace(stdout="",returncode=0)
lab.sudo = Mock(side_effect=sudo)
with patch.object(m.secrets,"token_hex",return_value=a["token"]):
    lab.install_ntp_firewall_rule()
handle = lab.ntp_rule_handle
lab.remove_ntp_firewall_rule()
lab.remove_ntp_firewall_rule()
result = {"handle":handle,"comment":lab.ntp_rule_comment,"commands":calls(lab.sudo)}`)
	equal(t, got["handle"], 101)
	equal(t, got["comment"], nil)
	commands := arr(got["commands"])
	equal(t, obj(commands[1])["args"], []string{"nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", "tsfabc123b", "ip", "saddr", "198.19.7.0/24", "ip", "daddr", "198.19.7.1", "udp", "dport", "123", "counter", "accept", "comment", "ts-orch-fc-ntp-" + strings.Repeat("a", 24)})
	deletions := 0
	for _, command := range commands {
		args := arr(obj(command)["args"])
		if encoded(args[:min(3, len(args))]) == encoded([]string{"nft", "delete", "rule"}) {
			deletions++
			equal(t, args[len(args)-2:], []string{"handle", "101"})
		}
	}
	equal(t, deletions, 1)
}
func TestNTPFirewallRejectsInactiveOrUnexpectedBackend(t *testing.T) {
	for _, tc := range []struct {
		hook string
		jump bool
	}{{"forward", true}, {"input", false}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			a := ntpArgs()
			a["chain"] = ntpChain(tc.hook, tc.jump)
			got := observe(t, a, ntpSetup+`lab.sudo = Mock(return_value=SimpleNamespace(stdout=json.dumps(a["chain"])))
result = attempt(lab.install_ntp_firewall_rule)
result.update(comment=lab.ntp_rule_comment,sudo_calls=lab.sudo.call_count)`)
			rejection(t, got, "RuntimeError", "")
			equal(t, got["comment"], nil)
			equal(t, got["sudo_calls"], 1)
		})
	}
}
func TestNTPPartialInsertRetainsOwnershipAndRefusesChangedScope(t *testing.T) {
	a := ntpArgs()
	a["root"] = t.TempDir()
	a["token"] = strings.Repeat("b", 24)
	a["changed"] = ntpRule("", "198.19.7.99")
	got := observe(t, a, cleanupSetup+ntpSetup+`active = [None]
def sudo(*args,**options):
    if args[:5] == ("nft","-j","-a","list","chain"):
        entries = list(a["chain"]["nftables"])
        if active[0] is not None:
            entries.insert(1,{"rule":active[0]})
        return SimpleNamespace(stdout=json.dumps({"nftables":entries}))
    if args[:3] == ("nft","insert","rule"):
        active[0] = dict(a["rule"],comment=args[-1])
        raise RuntimeError("ambiguous insert result")
    if args[:3] == ("nft","delete","rule"):
        active[0] = None
    return SimpleNamespace(returncode=0)
lab.sudo = Mock(side_effect=sudo)
with patch.object(m.secrets,"token_hex",return_value=a["token"]):
    result = attempt(lab.install_ntp_firewall_rule)
result["insert_comment"] = lab.ntp_rule_comment
active[0] = dict(a["changed"],comment=lab.ntp_rule_comment)
with patch.object(m.shutil,"rmtree"):
    result["changed_errors"] = lab.cleanup(preserve_images=True)
result["changed_comment"] = lab.ntp_rule_comment
result["commands_before"] = calls(lab.sudo)
active[0] = dict(a["rule"],comment=lab.ntp_rule_comment)
with patch.object(m.shutil,"rmtree"):
    result["restored_errors"] = lab.cleanup(preserve_images=True)
result.update(comment=lab.ntp_rule_comment,commands=calls(lab.sudo))`)
	rejection(t, got, "RuntimeError", "ambiguous insert")
	if got["insert_comment"] == nil || got["changed_comment"] == nil {
		t.Fatal("lost ambiguous rule ownership")
	}
	errors := arr(got["changed_errors"])
	equal(t, len(errors), 1)
	contains(t, errors[0].(string), "scope changed")
	for _, command := range arr(got["commands_before"]) {
		args := arr(obj(command)["args"])
		if encoded(args[:min(len(args), 3)]) == encoded([]string{"nft", "delete", "rule"}) {
			t.Fatal("deleted changed rule")
		}
	}
	equal(t, got["restored_errors"], []any{})
	equal(t, got["comment"], nil)
	deletions := 0
	for _, command := range arr(got["commands"]) {
		args := arr(obj(command)["args"])
		if encoded(args[:min(len(args), 3)]) == encoded([]string{"nft", "delete", "rule"}) {
			deletions++
		}
	}
	equal(t, deletions, 1)
}
func TestNTPReorderedAcceptIsNotOwnedScopedRule(t *testing.T) {
	a := ntpArgs()
	rule := ntpRule("ts-orch-fc-ntp-owned", "198.19.7.1")
	expr := rule["expr"].([]any)
	rule["expr"] = append([]any{expr[len(expr)-1]}, expr[:len(expr)-1]...)
	a["rule"] = rule
	got := observe(t, a, ntpSetup+`result = {"exact":lab._exact_ntp_rule(a["rule"])}`)
	equal(t, got["exact"], false)
}
func TestClockDiagnosticsAreBoundedAndCaptureFirewallCounters(t *testing.T) {
	a := ntpArgs()
	dir := t.TempDir()
	a["root"] = dir
	script.Write(t, filepath.Join(dir, "stage/chrony.conf"), []byte("bindaddress 198.19.7.1\nport 123\n"), 0o600)
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	a["guest_stdout"] = filepath.Join(dir, "guest-output")
	script.Write(t, a["guest_stdout"].(string), []byte(strings.Repeat("timeout waiting for 198.19.7.1:123\n", 3000)), 0o600)
	a["host_stdout"] = filepath.Join(dir, "host-output")
	script.Write(t, a["host_stdout"].(string), []byte(strings.Repeat("counter packets 3 bytes 228\n", 3000)), 0o600)
	got := observe(t, a, ntpSetup+`lab.logs = Path(a["root"])/"logs"
lab.stage = Path(a["root"])/"stage"
lab.chrony_control_dir = Path("/run/ts-orch-fc-chrony.test1234")
lab.ntp_rule_comment = "ts-orch-fc-ntp-owned"
lab.ntp_rule_handle = 101
lab.clock_diagnostics_captured = set()
lab.ssh = Mock(return_value=SimpleNamespace(returncode=1,stdout=Path(a["guest_stdout"]).read_text(),stderr=""))
with patch.object(m,"run",return_value=SimpleNamespace(returncode=0,stdout=Path(a["host_stdout"]).read_text(),stderr="")) as command:
    lab.capture_clock_diagnostics("c1")
    lab.capture_clock_diagnostics("c1")
result = {"record":json.loads((lab.logs/"c1-clock-diagnostics.json").read_text()),"commands":[c.args[0] for c in command.call_args_list],"ssh_calls":lab.ssh.call_count,"limit":m.NTP_DIAGNOSTIC_BYTES,"chronyc":str(m.CHRONYC)}`)
	record := obj(got["record"])
	guest := obj(record["guest_time"])
	host := obj(record["host_input_rules"])
	equal(t, guest["truncated"], true)
	if len(guest["stdout"].(string)) > int(got["limit"].(float64)) {
		t.Fatal("guest output unbounded")
	}
	equal(t, host["truncated"], true)
	contains(t, host["stdout"].(string), "counter packets 3")
	equal(t, record["ntp_rule_handle"], 101)
	equal(t, record["chrony_config"], "bindaddress 198.19.7.1\nport 123\n")
	equal(t, got["ssh_calls"], 1)
	tracking, input, nixos := false, false, false
	for _, command := range arr(got["commands"]) {
		args := arr(command)
		text := encoded(args)
		if strings.Contains(text, got["chronyc"].(string)) && strings.Contains(text, "tracking") {
			tracking = true
		}
		if args[len(args)-1] == "INPUT" {
			input = true
		}
		if args[len(args)-1] == "nixos-fw" {
			nixos = true
		}
	}
	equal(t, tracking, true)
	equal(t, input, true)
	equal(t, nixos, true)
}

func TestChronySocketUsesPrivateRootOwnedRunDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, directory string
		uid, mode       int
		typ, err        string
	}{{"owned", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, 0o40700, "", ""}, {"wrong_owner", "/run/ts-orch-fc-chrony.aB1cD2eF", 1000, 0o40700, "RuntimeError", "root-owned"}, {"wrong_mode", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, 0o40755, "RuntimeError", "mode 0700"}, {"symlink", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, 0o120700, "RuntimeError", "root-owned"}, {"outside_run", "/tmp/ts-orch-fc-chrony.aB1cD2eF", 0, 0o40700, "RuntimeError", "invalid private Chrony"}} {
		t.Run(tc.name, func(t *testing.T) {
			got := observe(t, map[string]any{"dir": tc.directory, "uid": tc.uid, "mode": tc.mode}, `lab.chrony_control_dir = None
lab.sudo = Mock(return_value=SimpleNamespace(stdout=a["dir"]+"\n"))
with patch.object(m.Path,"lstat",return_value=SimpleNamespace(st_mode=a["mode"],st_uid=a["uid"])):
    result = attempt(lambda:str(lab.chrony_socket_path()))
result.update(directory=str(lab.chrony_control_dir),commands=calls(lab.sudo))`)
			if tc.err != "" {
				rejection(t, got, tc.typ, tc.err)
				return
			}
			equal(t, got["value"], tc.directory+"/chronyd.sock")
			equal(t, got["directory"], tc.directory)
			equal(t, got["commands"], []any{map[string]any{"args": []string{"mktemp", "-d", "-p", "/run", "ts-orch-fc-chrony.XXXXXXXX"}, "kwargs": map[string]any{}}})
		})
	}
}
func TestForegroundChronyUsesRootSocketAndOwnedCleanup(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"stage", "logs", "images", "secrets"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := observe(t, map[string]any{"root": dir, "control": "/run/ts-orch-fc-chrony.aB1cD2eF", "subnet": "198.19.7.0/24", "sources": "^* remote 0 0 0\n", "listen": "UNCONN 0 0 198.19.7.1:123 0.0.0.0:*\n"}, cleanupSetup+`lab.root = Path(a["root"])
lab.logs = lab.root/"logs"
lab.subnet = ipaddress.ip_network(a["subnet"])
control = Path(a["control"])
socket = control/"chronyd.sock"
lab.chrony_socket_path = Mock(return_value=socket)
lab.chrony_control_dir = control
lab.wait = Mock(side_effect=lambda label,predicate,**options:predicate())
lab.sudo = Mock(return_value=SimpleNamespace(returncode=0,stderr=""))
process = Mock(pid=1234,returncode=0)
process.poll.return_value = None
def command_result(command,**options):
    if command[:3] == ["sudo","-n",str(m.CHRONYC)]:
        return SimpleNamespace(returncode=0,stdout=a["sources"])
    if command[:4] == ["sudo","-n","ss","-H"]:
        return SimpleNamespace(returncode=0,stdout=a["listen"])
    return SimpleNamespace(returncode=0,stdout="")
with patch.object(m,"run",side_effect=command_result) as command,patch.object(m.subprocess,"Popen",return_value=process) as spawned,patch.object(m,"digest",return_value="pinned"):
    lab.start_chrony()
config = (lab.stage/"chrony.conf").read_text()
result = {"config":config,"spawned":spawned.call_args.args[0],"commands":[c.args[0] for c in command.call_args_list],"cleanup":lab.cleanup(),"sudo":calls(lab.sudo),"directory":lab.chrony_control_dir,"chronyc":str(m.CHRONYC),"chronyd":str(m.CHRONYD)}`)
	socket := "/run/ts-orch-fc-chrony.aB1cD2eF/chronyd.sock"
	contains(t, got["config"].(string), "bindcmdaddress "+socket+"\ncmdport 0\n")
	contains(t, got["config"].(string), "bindaddress 198.19.7.1\nallow 198.19.7.0/24\nport 123\n")
	excludes(t, got["config"].(string), "local stratum")
	equal(t, got["spawned"], []string{"sudo", "-n", got["chronyd"].(string), "-x", "-d", "-4", "-f", filepath.Join(dir, "stage/chrony.conf")})
	equal(t, got["cleanup"], []any{})
	equal(t, got["directory"], nil)
	foundSocket, foundDir := false, false
	for _, call := range arr(got["sudo"]) {
		args := obj(call)["args"]
		if encoded(args) == encoded([]string{"rm", "-f", "--", socket}) {
			equal(t, obj(call)["kwargs"], map[string]any{"allow_failure": true})
			foundSocket = true
		}
		if encoded(args) == encoded([]string{"rmdir", "--", "/run/ts-orch-fc-chrony.aB1cD2eF"}) {
			equal(t, obj(call)["kwargs"], map[string]any{"allow_failure": true})
			foundDir = true
		}
	}
	equal(t, foundSocket, true)
	equal(t, foundDir, true)
	for _, command := range arr(got["commands"]) {
		args := arr(command)
		if len(args) >= 3 && encoded(args[:3]) == encoded([]string{"sudo", "-n", got["chronyc"].(string)}) {
			equal(t, args[3:], []string{"-n", "-h", socket, "sources"})
		} else if !(len(args) >= 4 && encoded(args[:4]) == encoded([]string{"sudo", "-n", "ss", "-H"})) {
			equal(t, args, []string{got["chronyd"].(string), "-p", "-f", filepath.Join(dir, "stage/chrony.conf")})
		}
	}
}
