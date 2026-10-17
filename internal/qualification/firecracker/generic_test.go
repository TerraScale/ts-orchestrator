package firecracker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nativeLab(t *testing.T) *Lab {
	t.Helper()
	root := t.TempDir()
	l := &Lab{Ctx: t.Context(), Root: root, Logs: filepath.Join(root, "logs"), Stage: filepath.Join(root, "stage"), Secrets: filepath.Join(root, "secrets"), Images: filepath.Join(root, "images"), Binary: "unused", OperatorConfig: "config", Bridge: "tsfabc123b", Addresses: map[string]string{"host": "198.19.7.14", "c1": "198.19.7.11", "c2": "198.19.7.12", "c3": "198.19.7.13"}, VMs: map[string]*VM{}}
	l.Subnet = netip.MustParsePrefix("198.19.7.0/24")
	l.defaults()
	for _, d := range []string{l.Logs, l.Stage, l.Secrets, l.Images} {
		if e := os.Mkdir(d, 0o700); e != nil {
			t.Fatal(e)
		}
	}
	return l
}
func marshal(v any) string {
	b, e := json.Marshal(v, json.Deterministic(true))
	if e != nil {
		panic(e)
	}
	return string(b)
}
func requireError(t *testing.T, e error, part string) {
	t.Helper()
	if e == nil || !strings.Contains(e.Error(), part) {
		t.Fatalf("got %v, want error containing %q", e, part)
	}
}
func requireEqual(t *testing.T, a, b any) {
	t.Helper()
	if !reflect.DeepEqual(a, b) && !jsonEqual(a, b) {
		t.Fatalf("got %#v, want %#v", a, b)
	}
}
func TestDeployRetryContract(t *testing.T) {
	submitted := func(id string) Object {
		return Object{"operationId": id, "fingerprint": "fingerprint-" + id, "status": "submitted"}
	}
	for _, tc := range []struct {
		name      string
		responses []Object
		attempts  int
		err       string
	}{{"fence", []Object{submitted("fc-one-node-loss-2"), {"status": "rejected", "error": PreAcceptanceFenced, "authorityEpoch": 1}, submitted("fc-one-node-loss-epoch-retry-2"), {"status": "accepted", "authorityEpoch": 2}}, 2, ""}, {"0000000000V4MRM46HP1SNGDYW", []Object{submitted("fc-one-node-loss-2"), {"status": "rejected", "error": "artifact is not admitted"}}, 1, "artifact is not admitted"}, {"second_fence", []Object{submitted("fc-one-node-loss-2"), {"status": "rejected", "error": PreAcceptanceFenced}, submitted("fc-one-node-loss-epoch-retry-2"), {"status": "rejected", "error": PreAcceptanceFenced}}, 2, PreAcceptanceFenced}} {
		t.Run(tc.name, func(t *testing.T) {
			l := nativeLab(t)
			calls := 0
			l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				attempt := "one-node-loss"
				if calls >= 2 {
					attempt += "-epoch-retry"
				}
				id := "fc-" + attempt + "-2"
				if calls%2 == 0 {
					requireEqual(t, argv[len(argv)-2:], []string{"--intent", filepath.Join(l.Stage, "intent-"+attempt+"-2.json")})
				} else {
					requireEqual(t, argv[len(argv)-4:], []string{"--operation-id", id, "--fingerprint", "fingerprint-" + id})
				}
				v := tc.responses[calls]
				calls++
				return CommandResult{Stdout: marshal(v)}, nil
			}
			e := l.Deploy(Object{"source": Object{}, "digest": "a", "manifestDigest": "m"}, 2, "one-node-loss", "deploy")
			if tc.err != "" {
				requireError(t, e, tc.err)
			} else if e != nil {
				t.Fatal(e)
			}
			if calls != len(tc.responses) {
				t.Fatal(calls)
			}
			entries, _ := os.ReadDir(l.Stage)
			if len(entries) != tc.attempts {
				t.Fatal(entries)
			}
			for _, entry := range entries {
				b, e := os.ReadFile(filepath.Join(l.Stage, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				if strings.Contains(string(b), "authorityEpoch") {
					t.Fatal("stale epoch pinned")
				}
				intent, e := readObject(filepath.Join(l.Stage, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				name := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "intent-"), ".json")
				requireEqual(t, intent["operationId"], "fc-"+name)
			}
			terminal := []string{}
			for _, event := range l.Events {
				if event["event"] == "terminal_receipt" {
					id := str(event["operation_id"])
					terminal = append(terminal, id)
					requireEqual(t, event["fingerprint"], "fingerprint-"+id)
					if tc.name == "fence" {
						requireEqual(t, event["authority_epoch"], 1)
					}
				}
			}
			want := []string{"fc-one-node-loss-2"}
			if tc.name == "second_fence" {
				want = append(want, "fc-one-node-loss-epoch-retry-2")
			}
			requireEqual(t, terminal, want)
		})
	}
}
func TestHostStatusCuratesSecretsAndSessionCurrency(t *testing.T) {
	at := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for _, delta := range []time.Duration{20 * time.Second, -time.Second} {
		statuses := []any{Object{"registration": Object{"node": "host-a", "public_key": "secret-public-key", "capacity": Object{}}, "session_expires_at": at.Add(delta).Format(time.RFC3339), "reports": []any{Object{"session_id": "secret-session-id", "digest": strings.Repeat("a", 64), "error": "free text"}}}}
		got, e := CuratedHostStatuses(statuses, at)
		if e != nil {
			t.Fatal(e)
		}
		if got[0]["session_current"] != (delta > 0) {
			t.Fatal(got)
		}
		if strings.Contains(marshal(got), "secret") || strings.Contains(marshal(got), "free text") {
			t.Fatal(got)
		}
		reports := got[0]["reports"].([]Object)
		requireEqual(t, reports[0]["digest_prefix"], strings.Repeat("a", 12))
	}
}
func TestOperatorFailureDiagnosticOmitsOutput(t *testing.T) {
	l := nativeLab(t)
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
		return CommandResult{Code: 1, Stdout: "secret-output", Stderr: "secret-error"}, nil
	}
	l.CaptureHostStatus("early-pending")
	m, e := readObject(filepath.Join(l.Logs, "host-status-early-pending.json"))
	if e != nil {
		t.Fatal(e)
	}
	requireEqual(t, m["status"], "operator_failed")
	requireEqual(t, m["exit_code"], 1)
	if strings.Contains(marshal(m), "secret") {
		t.Fatal(m)
	}
}
func TestOperatorHostsHashSessionID(t *testing.T) {
	l := nativeLab(t)
	statuses := []any{Object{"registration": Object{"node": "host-a"}, "session_expires_at": time.Now().Add(time.Minute).Format(time.RFC3339), "reports": []any{Object{"session_id": "secret-session-id"}}}}
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
		return CommandResult{Stdout: marshal(statuses)}, nil
	}
	got, e := l.Operator("hosts", 5*time.Second, false, "")
	if e != nil {
		t.Fatal(e)
	}
	requireEqual(t, got, statuses)
	if strings.Contains(marshal(l.Events), "secret-session-id") || !strings.Contains(marshal(l.Events), "session_id_hash") {
		t.Fatal(l.Events)
	}
}
func TestOperatorFailureRecordsStageAndBoundedTimeout(t *testing.T) {
	for _, mode := range []string{"exit", "timeout"} {
		l := nativeLab(t)
		timeout := 4500 * time.Millisecond
		if mode == "timeout" {
			timeout = 5 * time.Second
		}
		l.Command = func(_ context.Context, _ []string, o CommandOptions) (CommandResult, error) {
			if o.Timeout != timeout || !o.AllowFailure {
				t.Fatal(o)
			}
			r := CommandResult{Code: 1, Stdout: `{"session_id":"secret-session-id"}`, Stderr: "context deadline exceeded"}
			if mode == "timeout" {
				return r, context.DeadlineExceeded
			}
			return r, nil
		}
		var e error
		if mode == "exit" {
			_, e = l.HostSession("v1", timeout, "same-process-host-session-renewal")
		} else {
			_, e = l.Operator("hosts", timeout, false, "same-process-host-session-renewal")
		}
		if e == nil {
			t.Fatal("no error")
		}
		event := l.Events[len(l.Events)-1]
		requireEqual(t, event["event"], "operator")
		requireEqual(t, event["timeout_seconds"], timeout.Seconds())
		requireEqual(t, event["stderr"], "context deadline exceeded")
		if event["elapsed_seconds"].(float64) < 0 {
			t.Fatal(event)
		}
		requireEqual(t, event["stage"], "same-process-host-session-renewal")
		if mode == "timeout" {
			requireEqual(t, event["failure"], "subprocess_timeout")
		} else {
			requireEqual(t, event["failure"], "exit_nonzero")
			requireEqual(t, event["exit_code"], 1)
			requireError(t, e, "context deadline exceeded")
		}
		if strings.Contains(marshal(event), "secret-session-id") {
			t.Fatal(event)
		}
	}
}
func TestConnectedControllerParsesFourColumns(t *testing.T) {
	l := nativeLab(t)
	l.Command = func(_ context.Context, argv []string, o CommandOptions) (CommandResult, error) {
		if o.Timeout != 10*time.Second || !strings.Contains(argv[len(argv)-1], "ss -Hnt state established") {
			t.Fatal(argv, o)
		}
		return CommandResult{Stdout: "0 0 198.19.7.14:48232 198.19.7.11:4222\n0 0 198.19.7.14:22 198.19.7.1:49300\n"}, nil
	}
	got, e := l.ConnectedController()
	if e != nil {
		t.Fatal(e)
	}
	requireEqual(t, got, "c1")
}
func TestGuestUnitsEnforceSupervisorBoundary(t *testing.T) {
	host := GuestUnit("host", "host")
	for _, s := range []string{"NoNewPrivileges=yes\n", "Delegate=yes\n", "DelegateSubgroup=supervisor\n", "AmbientCapabilities=\n", "TimeoutStartSec=180\n", "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP\n", "ExecStartPre=/usr/bin/install -d -o 2000 -g 2000 -m 0700 /run/ts-orch-workload\n", "while ! test -f " + ClockReady} {
		if !strings.Contains(host, s) {
			t.Fatal(s)
		}
	}
	controller := GuestUnit("c1", "run")
	for _, s := range []string{"User=", "Group=", "CapabilityBoundingSet=", "DelegateSubgroup="} {
		if strings.Contains(controller, s) || strings.Contains(host, "\nUser=") || strings.Contains(host, "\nGroup=") {
			t.Fatal(s)
		}
	}
	prestarts := func(unit string) []string {
		result := []string{}
		for line := range strings.SplitSeq(unit, "\n") {
			if v, ok := strings.CutPrefix(line, "ExecStartPre="); ok {
				result = append(result, v)
			}
		}
		return result
	}
	gate := "/bin/sh -c 'while ! test -f " + ClockReady + "; do sleep 0.1; done'"
	requireEqual(t, prestarts(host), []string{"/usr/bin/install -d -o 2000 -g 2000 -m 0700 /run/ts-orch-workload", gate})
	requireEqual(t, prestarts(controller), []string{gate})
	capabilities := map[string]int{"CAP_CHOWN": 0, "CAP_KILL": 5, "CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_SETPCAP": 8}
	mask := 0
	for line := range strings.SplitSeq(host, "\n") {
		if value, ok := strings.CutPrefix(line, "CapabilityBoundingSet="); ok {
			for _, name := range strings.Fields(value) {
				bit, ok := capabilities[name]
				if !ok {
					t.Fatal("unexpected capability", name)
				}
				mask |= 1 << bit
			}
		}
	}
	requireEqual(t, mask, 0x1e1)
}
func TestReadOnlyHostStatusRequiresSessionBoundReport(t *testing.T) {
	for _, id := range []string{"opaque-id", ""} {
		l := nativeLab(t)
		l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
			return CommandResult{Stdout: marshal([]any{Object{"registration": Object{}, "verified": false, "session_expires_at": time.Now().Add(time.Minute).Format(time.RFC3339), "reports": []any{Object{"role": "terrabase", "state": "running", "generation": 2, "session_id": id}}}})}, nil
		}
		v, e := l.HostSession("v2", 5*time.Second, "")
		if id == "" {
			requireError(t, e, "bound to a session")
		} else {
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, v["session_id"], id)
			requireEqual(t, v["reader_verified"], false)
		}
	}
}
func TestBlackholeOwnsScopedTableThroughPartialFailure(t *testing.T) {
	for _, partial := range []bool{false, true} {
		l := nativeLab(t)
		calls := [][]string{}
		l.Command = func(_ context.Context, a []string, _ CommandOptions) (CommandResult, error) {
			calls = append(calls, slices.Clone(a))
			if partial && len(calls) == 2 {
				return CommandResult{}, errors.New("rule failed")
			}
			return CommandResult{}, nil
		}
		table, e := l.BlackholeHostController("c1")
		if len(l.CreatedNFTTables) != 1 {
			t.Fatal(l.CreatedNFTTables)
		}
		if partial {
			requireError(t, e, "rule failed")
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		requireEqual(t, calls[0], []string{"sudo", "-n", "nft", "add", "table", "bridge", table})
		if errs := l.Cleanup(false); len(errs) != 0 {
			t.Fatal(errs)
		}
		if len(l.CreatedNFTTables) != 0 {
			t.Fatal(l.CreatedNFTTables)
		}
		rules := 0
		for _, c := range calls {
			if len(c) > 4 && slices.Equal(c[2:5], []string{"nft", "add", "rule"}) {
				rules++
				if !slices.Contains(c, "198.19.7.14") || !slices.Contains(c, "198.19.7.11") {
					t.Fatal(c)
				}
			}
		}
		if rules != 2 {
			t.Fatal(rules)
		}
		requireEqual(t, calls[len(calls)-1], []string{"sudo", "-n", "nft", "delete", "table", "bridge", table})
	}
}
func journalEntry(at time.Time, message string) string {
	return marshal(Object{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "MESSAGE": message})
}
func TestVerifiedLeaseParserRejectsNeighborEvents(t *testing.T) {
	at := time.Date(2026, 9, 24, 12, 0, 1, 0, time.UTC)
	expiry := at.Add(30 * time.Second)
	hash := head(hashBytes([]byte("opaque-id")), 32)
	renewal := fmt.Sprintf("2026/09/24 12:00:01 INFO host session accepted phase=renew session_id_hash=%s epoch=2 expires_at=%s", hash, expiry.Format(time.RFC3339))
	messages := []string{renewal, strings.Replace(renewal, "INFO", "WARN", 1), strings.Replace(renewal, "host session accepted", "host session exchange recovered", 1), strings.Replace(renewal, "2026/09/24", "2026/02/31", 1), strings.Replace(renewal, hash, "not-a-digest", 1), strings.Replace(renewal, "epoch=2", "epoch=2 epoch=3", 1), strings.Replace(renewal, "session_id_hash="+hash+" ", "", 1), fmt.Sprintf(`time=2026-09-24T12:00:01Z level=INFO msg="host session accepted" phase=renew session_id_hash=%s epoch=2 expires_at=%s`, hash, expiry.Format(time.RFC3339))}
	rows := []string{}
	for _, m := range messages {
		rows = append(rows, journalEntry(at, m))
	}
	rows = append(rows, journalEntry(at.Add(-2*time.Second), renewal))
	events := ParseLeaseEvents(strings.Join(rows, "\n"), at.Add(-time.Second))
	if len(events) != 1 || events[0].SessionHash != hash || events[0].Phase != "renew" || !events[0].ExpiresAt.Equal(expiry) {
		t.Fatal(events)
	}
}
func TestFenceBindsLatestSignedLeaseBeforeExpiry(t *testing.T) {
	expiry := time.Date(2026, 9, 24, 12, 0, 30, 0, time.UTC)
	hash := head(hashBytes([]byte("opaque-id")), 32)
	fenced := fmt.Sprintf("2026/09/24 12:00:25 INFO host session fenced session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted", hash, expiry.Format(time.RFC3339))
	for _, tc := range []struct {
		name, message string
		valid         bool
	}{{"matching", fenced, true}, {"hash", strings.Replace(fenced, hash, strings.Repeat("0", 32), 1), false}, {"epoch", strings.Replace(fenced, "epoch=3", "epoch=4", 1), false}, {"expiry", strings.Replace(fenced, expiry.Format(time.RFC3339), expiry.Add(time.Second).Format(time.RFC3339), 1), false}, {"legacy", `time=2026-09-24T12:00:25Z level=INFO msg="host session fenced"`, false}} {
		t.Run(tc.name, func(t *testing.T) {
			l := nativeLab(t)
			output := journalEntry(expiry.Add(-15*time.Second), "WARN host session exchange deferred") + "\n" + journalEntry(expiry.Add(-4500*time.Millisecond), tc.message)
			if tc.valid {
				for _, neighboring := range []string{strings.Replace(fenced, hash, strings.Repeat("0", 32), 1), strings.Replace(fenced, "epoch=3", "epoch=4", 1), fmt.Sprintf(`time=2026-09-24T12:00:25Z level=INFO msg="host session fenced" session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted`, hash, expiry.Format(time.RFC3339))} {
					output += "\n" + journalEntry(expiry.Add(-4500*time.Millisecond), neighboring)
				}
			}
			l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
				return CommandResult{Stdout: output}, nil
			}
			e := l.HostRenewalFailureEvidence(expiry.Add(-20*time.Second), hash, 3, expiry)
			if tc.valid {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, l.Events[0]["fence_cause_class"], "reserve_exhausted")
				if !l.Events[0]["actual_fence_started_at"].(time.Time).Equal(expiry.Add(-4500 * time.Millisecond)) {
					t.Fatal(l.Events[0])
				}
			} else {
				requireError(t, e, "matching fence")
			}
		})
	}
}

const nativeService = "/system.slice/ts-orch.service"
const nativePath = nativeService + "/terrascale-host-f2f2e59c89f0cea0/terrabase"

func TestNativeCgroupPathRejectsTraversalAndOtherRoles(t *testing.T) {
	cases := [][2]string{{strings.Replace(nativePath, "/system.slice/", "/system.slice/../", 1), nativeService}, {strings.Replace(nativePath, "/ts-orch.service/", "/ts-orch.service/./", 1), nativeService}, {strings.Replace(nativePath, "terrascale-host-", "terrascale.host-", 1), nativeService}, {strings.Replace(nativePath, "f2f2e59c89f0cea0", "g2f2e59c89f0cea0", 1), nativeService}, {strings.Replace(nativePath, "/terrabase", "/other", 1), nativeService}, {strings.Replace(nativePath, "/terrascale-host-", "/supervisor/terrascale-host-", 1), nativeService}, {nativePath + "/child", nativeService}, {nativePath, "/system.slice/other.service"}, {nativePath, "/system.slice/../ts-orch.service"}}
	for _, tc := range cases {
		requireError(t, ValidateNativeCgroupPath(tc[0], tc[1]), "invalid native workload cgroup path")
	}
}
func TestNativeCgroupPathBoundToUnitAndPopulated(t *testing.T) {
	for _, tc := range []struct {
		output string
		empty  bool
		err    string
	}{{"populated 1\nfrozen 0\n", false, ""}, {"populated 0\nfrozen 0\n", true, ""}, {"populated 0\npopulated 1\n", false, "no populated state"}} {
		l := nativeLab(t)
		l.Command = func(_ context.Context, args []string, _ CommandOptions) (CommandResult, error) {
			// Inspect the guest shell program after undoing its SSH argument quote.
			script := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(args[len(args)-1], "'"), "'"), "'\"'\"'", "'")
			for _, s := range []string{"systemctl show ts-orch.service -p ControlGroup --value", `test ! -L "$entry"`, "grep -qw memory '/sys/fs/cgroup" + nativeService + "/cgroup.controllers'", `test ! -s "$parent/cgroup.procs"`, `grep -qw memory "$parent/cgroup.subtree_control"`, "/sys/fs/cgroup" + strings.TrimSuffix(nativePath, "/terrabase"), nativePath + "/cgroup.events", "elif test -e '/sys/fs/cgroup" + nativePath + "'; then exit 5"} {
				if !strings.Contains(script, s) {
					t.Fatal(s)
				}
			}
			return CommandResult{Stdout: tc.output}, nil
		}
		empty, e := l.CgroupEmpty(nativePath, nativeService)
		if tc.err != "" {
			requireError(t, e, tc.err)
		} else if e != nil || empty != tc.empty {
			t.Fatal(empty, e)
		}
	}
}
func TestNativeObservationBindsPIDAndAgentUnit(t *testing.T) {
	output := "agent_pid=1353\nagent_state=S:3500\nagent_cgroup=" + nativeService + "/supervisor\nservice_cgroup=" + nativeService + "\ninvocation=valid\nworkload_pid=1391\nworkload_state_before=S:3537\nworkload_state=S:3537\nworkload_cgroup=" + nativePath + "\nmarker=v1\n"
	for _, tc := range []struct {
		output, err string
		alive       bool
	}{{output, "", true}, {strings.Replace(output, "workload_state=S:3537", "workload_state=missing", 1), "", false}, {strings.Replace(output, "workload_state_before=S:3537", "workload_state_before=missing", 1), "PID changed", false}, {strings.Replace(output, "workload_state=S:3537", "workload_state=S:9999", 1), "PID changed", false}, {strings.Replace(output, nativePath, nativeService+"/supervisor/terrabase", 1), "invalid native workload", false}, {strings.Replace(output, "agent_cgroup="+nativeService+"/supervisor", "agent_cgroup="+nativeService, 1), "supervisor subgroup", false}, {strings.Replace(output, "agent_cgroup="+nativeService+"/supervisor", "agent_cgroup="+nativeService+"/other", 1), "supervisor subgroup", false}, {strings.Replace(output, "agent_cgroup="+nativeService+"/supervisor", "agent_cgroup=/system.slice/other.service/supervisor", 1), "supervisor subgroup", false}} {
		got, e := ParseNativeObservation(tc.output)
		if tc.err != "" {
			requireError(t, e, tc.err)
		} else {
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, got["workload_alive"], tc.alive)
			requireEqual(t, got["agent_cgroup"], nativeService+"/supervisor")
			if !tc.alive {
				requireEqual(t, got["workload_cgroup"], "")
			}
		}
	}
}
func TestClockMeasurementUsesMonotonicUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name                string
		real                [2]int64
		mono                [4]int64
		offset, uncertainty int64
		err                 string
	}{{"measurement", [2]int64{100_000_000_000, 100_300_000_000}, [4]int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 151_500_000, ""}, {"back", [2]int64{100_000_000_000, 98_000_000_000}, [4]int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 0, "lab host clock changed"}, {"forward", [2]int64{100_000_000_000, 102_000_000_000}, [4]int64{0, 1_000_000, 300_000_000, 301_000_000}, 0, 0, "lab host clock changed"}, {"invalid_mono", [2]int64{100_000_000_000, 100_000_000_000}, [4]int64{0, 1_000_000, 500_000, 2_000_000}, 0, 0, "monotonic clock changed"}} {
		t.Run(tc.name, func(t *testing.T) {
			offset, u, e := ClockMeasurement(tc.real[0], tc.real[1], tc.mono[0], tc.mono[1], tc.mono[2], tc.mono[3], 100_150_000_000)
			if tc.err != "" {
				requireError(t, e, tc.err)
			} else if e != nil || offset != tc.offset || u != tc.uncertainty {
				t.Fatal(offset, u, e)
			}
			l := nativeLab(t)
			monoCalls := 0
			l.MonotonicNS = func() int64 { v := tc.mono[monoCalls]; monoCalls++; return v }
			l.Now = func() time.Time {
				if monoCalls >= 3 {
					return time.Unix(0, tc.real[1])
				}
				return time.Unix(0, tc.real[0])
			}
			l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
				return CommandResult{Stdout: "100150000000"}, nil
			}
			offset, u, e = l.MeasureGuestClock("c1")
			if tc.err != "" {
				requireError(t, e, tc.err)
				requireEqual(t, l.GuestClockUpperNS, map[string]int64{})
			} else {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, []int64{offset, u}, []int64{tc.offset, tc.uncertainty})
				requireEqual(t, l.GuestClockUpperNS["c1"], tc.offset+tc.uncertainty)
			}
		})
	}
}
func TestAssetPinsAndHashMismatch(t *testing.T) {
	requireEqual(t, KernelSHA, "586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523")
	requireEqual(t, RootfsSHA, "a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6")
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "kernel"), []byte("unverified"), 0o600); e != nil {
		t.Fatal(e)
	}
	requireError(t, GenericPreflight(GenericOptions{Kernel: filepath.Join(dir, "kernel")}), "SHA-256 mismatch")

	source := t.TempDir()
	writeSource := func(name, content string) {
		t.Helper()
		path := filepath.Join(source, name)
		if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte(content), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	inputs := []string{"go.mod", "go.sum", "main.go", "main_test.go", "docs.go", "third_party/runtime/runtime.go", "third_party/runtime/docs/example.go"}
	for _, name := range inputs {
		writeSource(name, "original")
	}
	before, e := SourceDigest(source)
	if e != nil {
		t.Fatal(e)
	}
	for _, content := range []string{"archived source", "updated archived source"} {
		for _, name := range []string{"docs/evidence/source.go", "docs/evidence/source_test.go", "docs/go.mod"} {
			writeSource(name, content)
		}
		after, e := SourceDigest(source)
		if e != nil {
			t.Fatal(e)
		}
		requireEqual(t, after, before)
	}
	for _, name := range inputs {
		writeSource(name, "changed")
		after, e := SourceDigest(source)
		if e != nil {
			t.Fatal(e)
		}
		if after == before {
			t.Fatalf("source digest ignored build input %s", name)
		}
		writeSource(name, "original")
	}
}
func TestAPISocketPathIsPrivateShortAndBounded(t *testing.T) {
	dir, e := PrivateSocketDirectory()
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(dir)
	s, e := os.Stat(dir)
	if e != nil || s.Mode().Perm() != 0o700 {
		t.Fatal(s, e)
	}
	path, e := SocketPath(dir, "host")
	if e != nil || len(path) > 107 {
		t.Fatal(path, e)
	}
	_, e = SocketPath("/tmp/"+strings.Repeat("x", 107), "host")
	requireError(t, e, "socket path is too long")
}
func TestSocketCleanupOnlyUnlinksOwnedStoppedSockets(t *testing.T) {
	for _, running := range []bool{false, true} {
		dir := t.TempDir()
		socket := filepath.Join(dir, "host.sock")
		other := filepath.Join(dir, "leave-me")
		for _, p := range []string{socket, other} {
			if e := os.WriteFile(p, nil, 0o600); e != nil {
				t.Fatal(e)
			}
		}
		vm := &VM{Name: "host", Socket: socket}
		if running {
			vm.Process = &Process{}
		}
		errs := CleanupOwnedSockets(map[string]*VM{"host": vm}, dir)
		if len(errs) != 1 {
			t.Fatal(errs)
		}
		if running {
			requireEqual(t, errs[0], "keep Firecracker API sockets until host is confirmed stopped")
		} else if !strings.Contains(errs[0], "empty Firecracker API socket directory") {
			t.Fatal(errs)
		}
		_, e := os.Stat(socket)
		if (e == nil) != running {
			t.Fatal(e)
		}
		if _, e = os.Stat(other); e != nil {
			t.Fatal(e)
		}
	}
}
func TestFailedCleanupRetainsGuestImages(t *testing.T) {
	l := nativeLab(t)
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) { return CommandResult{}, nil }
	errs := l.Cleanup(true)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if _, e := os.Stat(l.Images); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(l.Stage); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
func TestChildExitProbeObservesWithoutReaping(t *testing.T) {
	p, e := Start([]string{"/bin/sh", "-c", "exit 7"}, "", os.Stderr)
	if e != nil {
		t.Fatal(e)
	}
	done, e := p.WaitUnreaped(2 * time.Second)
	if e != nil || !done || p.Reaped {
		t.Fatal(done, e, p.Reaped)
	}
	if e = p.Stop(time.Second, true); e != nil {
		t.Fatal(e)
	}
	if p.ExitCode != 7 {
		t.Fatal(p.ExitCode)
	}
}
func TestProcessGroupRejectsReapedLeaderAndRetainsLiveGroup(t *testing.T) {
	p, e := Start([]string{"/bin/sh", "-c", "exit 0"}, "", os.Stderr)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	p.Reaped = true
	requireError(t, p.Stop(time.Second, false), "reaped before group cleanup")
	stuck := fixtureProcess()
	signals := []int{}
	stuck.hooks.signal = func(_ int, signal syscall.Signal) error {
		signals = append(signals, int(signal))
		return nil
	}
	stuck.hooks.quiescent = func(int, time.Duration) error {
		return errors.New("owned process group 1234 still has live members: [5678]")
	}
	stuck.hooks.reap = func() error { t.Fatal("reaped a live process group"); return nil }
	requireError(t, stuck.Stop(time.Second, false), "still has live members")
	requireEqual(t, signals, []int{15, 9})
	if stuck.Reaped || stuck.Cmd.ProcessState != nil {
		t.Fatal("lost live group ownership")
	}
}
func TestProcessGroupKillsTermIgnoringChildBeforeReapingLeader(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	p, e := Start([]string{"/bin/sh", "-c", `trap 'exit 0' TERM; sh -c 'trap "" TERM; echo $$ > "$1"; while :; do sleep 1; done' sh "$1" & while :; do sleep 1; done`, "sh", pidFile}, "", os.Stderr)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if !p.Reaped {
			_ = p.Stop(time.Second, true)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, e := os.Stat(pidFile); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	childBytes, e := os.ReadFile(pidFile)
	if e != nil {
		t.Fatal(e)
	}
	child, e := strconv.Atoi(strings.TrimSpace(string(childBytes)))
	if e != nil {
		t.Fatal(e)
	}
	observations := 0
	p.hooks = &processHooks{quiescent: func(id int, timeout time.Duration) error {
		if e := WaitProcessGroupQuiescent(id, timeout); e != nil {
			return e
		}
		observations++
		if p.Reaped || p.Cmd.ProcessState != nil {
			t.Fatal("leader reaped before group quiescence")
		}
		for _, pid := range []int{p.PID(), child} {
			b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if processStatGone(e) {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			_, after, _ := strings.CutLast(string(b), ")")
			state := strings.Fields(after)[0]
			if state != "Z" && state != "X" && state != "x" {
				t.Fatal("live process before leader reap", pid, state)
			}
		}
		return nil
	}}
	if e = p.Stop(time.Second, false); e != nil {
		t.Fatal(e)
	}
	members, e := LiveProcessGroupMembers(p.PID())
	if e != nil || len(members) > 0 || !p.Reaped {
		t.Fatal(members, e)
	}
	requireEqual(t, observations, 1)
}

func TestProcessStatGone(t *testing.T) {
	for _, test := range []struct {
		err  error
		gone bool
	}{{syscall.ENOENT, true}, {syscall.ESRCH, true}, {syscall.EACCES, false}, {syscall.EIO, false}, {nil, false}} {
		err := test.err
		if err != nil {
			err = &os.PathError{Op: "read", Path: "/proc/123/stat", Err: err}
		}
		if got := processStatGone(err); got != test.gone {
			t.Errorf("stat error %v: gone=%v, want %v", err, got, test.gone)
		}
	}
}
