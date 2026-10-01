package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixtureProcess() *Process {
	return &Process{Cmd: &exec.Cmd{Process: &os.Process{Pid: 1234}}, hooks: &processHooks{
		group:     func(pid int) (int, error) { return pid, nil },
		signal:    func(int, syscall.Signal) error { return nil },
		exited:    func() (bool, error) { return false, nil },
		wait:      func(time.Duration) (bool, error) { return true, nil },
		quiescent: func(int, time.Duration) error { return nil },
		reap:      func() error { return nil },
	}}
}

func TestRetryIntentOmitsEpoch(t *testing.T) {
	l := nativeLab(t)
	path, e := l.Intent(Object{"source": Object{}, "digest": "artifact", "manifestDigest": "manifest"}, 2, "one-node-loss-epoch-retry")
	if e != nil {
		t.Fatal(e)
	}
	intent, e := readObject(path)
	if e != nil {
		t.Fatal(e)
	}
	requireEqual(t, intent["operationId"], "fc-one-node-loss-epoch-retry-2")
	if _, exists := intent["authorityEpoch"]; exists {
		t.Fatal("retry pins stale epoch")
	}
}

func TestClockReleaseRequiresNTPKernelHealthAndFreshService(t *testing.T) {
	for _, mode := range []string{"healthy", "unhealthy", "already_running"} {
		t.Run(mode, func(t *testing.T) {
			l := nativeLab(t)
			commands := []string{}
			measurements := 0
			l.measureClock = func(string) (int64, int64, error) {
				measurements++
				return -100_000_000, 100_000_000, nil
			}
			l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				command := argv[len(argv)-1]
				commands = append(commands, command)
				if len(commands) == 1 && mode == "already_running" {
					return CommandResult{Code: 1}, nil
				}
				if strings.Contains(command, "ts-orch-clockprobe") {
					if mode == "unhealthy" {
						return CommandResult{Code: 1, Stdout: `{"healthy":false}`}, nil
					}
					return CommandResult{Stdout: `{"healthy":true,"kernel_maxerror_us":1000}`}, nil
				}
				return CommandResult{}, nil
			}
			l.wait = func(_ string, probe func() (any, error), _ time.Time, _ time.Duration) (any, error) {
				v, e := probe()
				if e == nil && !truth(v) {
					e = errors.New("NTP clock stayed unhealthy")
				}
				return v, e
			}
			e := l.ReleaseSynchronizedGuestClock("c1")
			switch mode {
			case "healthy":
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, len(commands), 3)
				requireEqual(t, measurements, 2)
				if !strings.Contains(commands[1], "systemd-timesyncd.service") || !strings.Contains(commands[1], "ts-orch-clockprobe") {
					t.Fatal(commands)
				}
				requireEqual(t, commands[2], quote("/usr/bin/install -m 0600 /dev/null "+ClockReady))
			case "unhealthy":
				requireError(t, e, "NTP clock")
				requireEqual(t, measurements, 0)
				if !strings.Contains(commands[1], "ts-orch-clockprobe") {
					t.Fatal(commands)
				}
			case "already_running":
				requireError(t, e, "before NTP clock readiness")
				requireEqual(t, len(commands), 1)
				requireEqual(t, measurements, 0)
			}
			for _, command := range commands {
				if strings.Contains(command, "date -u --set=") {
					t.Fatal("clock release set guest time", command)
				}
			}
		})
	}
}

func TestClockDiagnosticFailurePreservesOriginalTimeout(t *testing.T) {
	l := nativeLab(t)
	original := errors.New("NTP clock remained unsynchronized")
	l.wait = func(string, func() (any, error), time.Time, time.Duration) (any, error) { return nil, original }
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) { return CommandResult{}, nil }
	if e := os.RemoveAll(l.Logs); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(l.Logs, []byte("diagnostic storage unavailable"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := l.WaitSynchronizedGuestClock("c1"); e != original {
		t.Fatalf("diagnostic replaced primary error: %v", e)
	}
	requireEqual(t, l.ClockDiagnostics["c1"], true)
	requireEqual(t, l.Events[len(l.Events)-1]["event"], "clock_diagnostics")
	requireEqual(t, l.Events[len(l.Events)-1]["status"], "write_failed")
}

func TestSSHWaitOrdersClockBeforeRuntime(t *testing.T) {
	l := nativeLab(t)
	order := []string{}
	l.wait = func(label string, _ func() (any, error), _ time.Time, _ time.Duration) (any, error) {
		order = append(order, label)
		return true, nil
	}
	l.measureClock = func(string) (int64, int64, error) { return 0, 0, nil }
	l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
		if strings.Contains(argv[len(argv)-1], "install -m 0600") {
			order = append(order, "clock-release")
		}
		return CommandResult{}, nil
	}
	if e := l.WaitSSH("c1"); e != nil {
		t.Fatal(e)
	}
	requireEqual(t, order, []string{"ssh-c1", "ntp-clock-c1", "clock-release", "service-c1"})
}

func TestClockCheckKeepsStrictOneSecondBound(t *testing.T) {
	l := nativeLab(t)
	l.measureClock = func(string) (int64, int64, error) { return 900_000_000, 100_000_001, nil }
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
		t.Fatal("strict clock bound issued SSH")
		return CommandResult{}, nil
	}
	requireError(t, l.CheckGuestClocks(), "over one second")
}

func TestBrokerClockFaultBudgetIncludesSSH(t *testing.T) {
	l := nativeLab(t)
	current := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return current }
	l.startProcess = func(_ []string, _ string, output io.Writer) (*Process, error) {
		fmt.Fprintln(output, `{"state":"ready"}`)
		return fixtureProcess(), nil
	}
	waits, ssh := 0, 0
	l.wait = func(_ string, probe func() (any, error), _ time.Time, _ time.Duration) (any, error) {
		waits++
		return probe()
	}
	l.Command = func(_ context.Context, argv []string, options CommandOptions) (CommandResult, error) {
		ssh++
		command := argv[len(argv)-1]
		if strings.Contains(command, "date -u --set=") {
			requireEqual(t, options.Timeout, 12*time.Second)
			current = current.Add(12 * time.Second)
			return CommandResult{}, nil
		}
		if strings.Contains(command, "ts-orch-clockprobe") {
			requireEqual(t, options.Timeout, 8*time.Second)
			current = current.Add(10 * time.Second)
			return CommandResult{Code: 1, Stdout: `{"healthy":false}`}, nil
		}
		t.Fatal(command)
		return CommandResult{}, nil
	}
	requireError(t, l.VerifyBrokerClockGate(), "20-second fault budget")
	requireEqual(t, ssh, 2)
	requireEqual(t, waits, 1)
	if e := l.SessionProbeProcess.Stop(time.Second, true); e != nil {
		t.Fatal(e)
	}
}

func TestProcessGroupSignalsPrecedeLeaderReap(t *testing.T) {
	p := fixtureProcess()
	operations := []any{}
	p.hooks.signal = func(id int, signal syscall.Signal) error {
		operations = append(operations, []any{"signal", id, int(signal)})
		return nil
	}
	p.hooks.wait = func(timeout time.Duration) (bool, error) {
		operations = append(operations, []any{"wait", p.PID(), timeout.Seconds()})
		return true, nil
	}
	p.hooks.quiescent = func(id int, timeout time.Duration) error {
		operations = append(operations, []any{"quiescent", id, timeout.Seconds()})
		if p.Reaped {
			t.Fatal("leader already reaped")
		}
		return nil
	}
	p.hooks.reap = func() error { operations = append(operations, []any{"reap"}); return nil }
	if e := p.Stop(time.Second, false); e != nil {
		t.Fatal(e)
	}
	requireEqual(t, operations, []any{[]any{"signal", 1234, 15}, []any{"wait", 1234, 1}, []any{"signal", 1234, 9}, []any{"quiescent", 1234, 1}, []any{"reap"}})
	requireEqual(t, p.Reaped, true)
}

func TestClusterDiagnosticUsesSeparateCredentials(t *testing.T) {
	l := nativeLab(t)
	l.NATSDiag = filepath.Join(l.Root, "natsdiag")
	for _, path := range []string{l.NATSDiag, filepath.Join(l.Secrets, "c1.creds"), filepath.Join(l.Secrets, "natsdiag.creds")} {
		if e := os.WriteFile(path, nil, 0o600); e != nil {
			t.Fatal(e)
		}
	}
	commands := [][]string{}
	l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
		commands = append(commands, slices.Clone(argv))
		return CommandResult{Stdout: "[]"}, nil
	}
	l.CaptureClusterDiagnostics()
	command := commands[len(commands)-1]
	index := slices.Index(command, "--operator-creds")
	if index < 0 {
		t.Fatal("no credential option", command)
	}
	requireEqual(t, command[index+1], filepath.Join(l.Secrets, "natsdiag.creds"))
	if slices.Contains(command, filepath.Join(l.Secrets, "operator.creds")) {
		t.Fatal("diagnostics use write-capable operator credentials")
	}
}

func TestRenewalUsesSingle25SecondDeadline(t *testing.T) {
	for _, mode := range []string{"within_deadline", "late_probe", "failed_operator"} {
		t.Run(mode, func(t *testing.T) {
			l := nativeLab(t)
			base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
			current := base.Add(100 * time.Second)
			l.Now = func() time.Time { return current }
			original, renewed := base.Add(150*time.Second), base.Add(155*time.Second)
			id := "opaque-session"
			hash := head(hashBytes([]byte(id)), 32)
			output := "agent_pid=940\nagent_state=S:123\nagent_cgroup=" + nativeService + "/supervisor\nservice_cgroup=" + nativeService + "\ninvocation=unit-1\nworkload_pid=1209\nworkload_state_before=S:456\nworkload_state=S:456\nworkload_cgroup=" + nativePath + "\nmarker=v1\n"
			native, e := ParseNativeObservation(output)
			if e != nil {
				t.Fatal(e)
			}
			hostTimeouts, nativeTimeouts, leaseTimeouts := []time.Duration{}, []time.Duration{}, []time.Duration{}
			l.Command = func(_ context.Context, argv []string, options CommandOptions) (CommandResult, error) {
				if slices.Contains(argv, "hosts") {
					hostTimeouts = append(hostTimeouts, options.Timeout)
					if mode == "failed_operator" {
						return CommandResult{Code: 1, Stderr: "context deadline exceeded"}, nil
					}
					current = base.Add(124500 * time.Millisecond)
					return CommandResult{Stdout: marshal([]any{Object{"session_expires_at": renewed.Format(time.RFC3339Nano), "reports": []any{Object{"role": "terrabase", "generation": 1, "state": "running", "session_id": id, "epoch": 2}}}})}, nil
				}
				if strings.Contains(argv[len(argv)-1], "journalctl") {
					leaseTimeouts = append(leaseTimeouts, options.Timeout)
					if len(leaseTimeouts) == 1 {
						current = base.Add(124900 * time.Millisecond)
						if mode == "late_probe" {
							current = base.Add(126 * time.Second)
						}
					}
					message := fmt.Sprintf("2026/09/24 12:01:41 INFO host session accepted phase=renew session_id_hash=%s epoch=2 expires_at=%s", hash, renewed.Format(time.RFC3339Nano))
					return CommandResult{Stdout: journalEntry(base.Add(101*time.Second), message)}, nil
				}
				nativeTimeouts = append(nativeTimeouts, options.Timeout)
				current = base.Add(124800 * time.Millisecond)
				return CommandResult{Stdout: output}, nil
			}
			l.wait = func(label string, probe func() (any, error), deadline time.Time, period time.Duration) (any, error) {
				requireEqual(t, deadline, base.Add(125*time.Second))
				requireEqual(t, period, 500*time.Millisecond)
				if mode == "within_deadline" {
					current = base.Add(123 * time.Second)
				} else {
					current = base.Add(101 * time.Second)
				}
				v, e := probe()
				if mode != "within_deadline" {
					if mode == "late_probe" {
						requireEqual(t, v, false)
					}
					return nil, fmt.Errorf("%s: renewal deadline passed: %w", label, e)
				}
				return v, e
			}
			e = l.WaitSameProcessRenewal(Object{"session_id": id, "expires_at": original}, native, "c2", base.Add(100*time.Second))
			if mode == "within_deadline" {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, hostTimeouts, []time.Duration{2 * time.Second})
				requireEqual(t, nativeTimeouts, []time.Duration{500 * time.Millisecond})
				requireEqual(t, leaseTimeouts, []time.Duration{200 * time.Millisecond})
				requireEqual(t, l.Events[len(l.Events)-1]["event"], "host_session_renewed_on_surviving_quorum")
			} else {
				requireError(t, e, "renewal deadline passed")
				last := l.Events[len(l.Events)-1]
				requireEqual(t, last["event"], "host_renewal_timeout_diagnostics")
				requireEqual(t, last["status"], "ok")
				requireEqual(t, len(last["renewals"].([]Object)), 1)
				requireEqual(t, leaseTimeouts[len(leaseTimeouts)-1], 5*time.Second)
				if mode == "failed_operator" {
					requireEqual(t, nativeTimeouts, []time.Duration{})
					requireEqual(t, hostTimeouts[0], 5*time.Second)
				}
			}
		})
	}
}

func ntpRule(comment, destination string) Object {
	match := func(left, right any) Object { return Object{"match": Object{"op": "==", "left": left, "right": right}} }
	payload := func(protocol, field string) Object {
		return Object{"payload": Object{"protocol": protocol, "field": field}}
	}
	return Object{"family": "ip", "table": "filter", "chain": "INPUT", "handle": 101, "comment": comment, "expr": []any{
		match(Object{"meta": Object{"key": "iifname"}}, "tsfabc123b"),
		match(payload("ip", "saddr"), Object{"prefix": Object{"addr": "198.19.7.0", "len": 24}}),
		match(payload("ip", "daddr"), destination), match(payload("udp", "dport"), 123),
		Object{"counter": Object{"packets": 3, "bytes": 228}}, Object{"accept": nil},
	}}
}
func ntpChain(hook string, jump bool) []any {
	entries := []any{Object{"chain": Object{"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": hook}}}
	if jump {
		entries = append(entries, Object{"rule": Object{"family": "ip", "table": "filter", "chain": "INPUT", "handle": 17, "expr": []any{Object{"jump": Object{"target": "nixos-fw"}}}}})
	}
	return entries
}

func TestNTPFirewallInstallsScopedOwnedRuleAndDeletesByHandle(t *testing.T) {
	l := nativeLab(t)
	var active Object
	commands := [][]string{}
	l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
		a := argv[2:]
		commands = append(commands, slices.Clone(a))
		switch {
		case slices.Equal(a[:5], []string{"nft", "-j", "-a", "list", "chain"}):
			entries := ntpChain("input", true)
			if active != nil {
				entries = slices.Insert(entries, 1, any(Object{"rule": active}))
			}
			return CommandResult{Stdout: marshal(Object{"nftables": entries})}, nil
		case slices.Equal(a[:3], []string{"nft", "insert", "rule"}):
			active = ntpRule(a[len(a)-1], "198.19.7.1")
		case slices.Equal(a[:3], []string{"nft", "delete", "rule"}):
			active = nil
		}
		return CommandResult{}, nil
	}
	if e := l.InstallNTPFirewallRule(); e != nil {
		t.Fatal(e)
	}
	requireEqual(t, l.NTPRuleHandle, 101)
	comment := l.NTPRuleComment
	requireEqual(t, commands[1], []string{"nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", "tsfabc123b", "ip", "saddr", "198.19.7.0/24", "ip", "daddr", "198.19.7.1", "udp", "dport", "123", "counter", "accept", "comment", comment})
	for range 2 {
		if e := l.RemoveNTPFirewallRule(); e != nil {
			t.Fatal(e)
		}
	}
	requireEqual(t, l.NTPRuleComment, "")
	deletions := 0
	for _, command := range commands {
		if slices.Equal(command[:3], []string{"nft", "delete", "rule"}) {
			deletions++
			requireEqual(t, command, []string{"nft", "delete", "rule", "ip", "filter", "INPUT", "handle", "101"})
		}
	}
	requireEqual(t, deletions, 1)
}

func TestNTPFirewallRejectsInactiveOrUnexpectedBackend(t *testing.T) {
	for _, tc := range []struct {
		hook string
		jump bool
	}{{"forward", true}, {"input", false}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			l := nativeLab(t)
			calls := 0
			l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
				calls++
				return CommandResult{Stdout: marshal(Object{"nftables": ntpChain(tc.hook, tc.jump)})}, nil
			}
			if e := l.InstallNTPFirewallRule(); e == nil {
				t.Fatal("admitted unexpected firewall backend")
			}
			requireEqual(t, l.NTPRuleComment, "")
			requireEqual(t, calls, 1)
		})
	}
}

func TestNTPPartialInsertRetainsOwnershipAndRefusesChangedScope(t *testing.T) {
	l := nativeLab(t)
	var active Object
	deletions := 0
	l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
		a := argv[2:]
		switch {
		case slices.Equal(a[:5], []string{"nft", "-j", "-a", "list", "chain"}):
			entries := ntpChain("input", true)
			if active != nil {
				entries = append(entries, Object{"rule": active})
			}
			return CommandResult{Stdout: marshal(Object{"nftables": entries})}, nil
		case slices.Equal(a[:3], []string{"nft", "insert", "rule"}):
			active = ntpRule(a[len(a)-1], "198.19.7.1")
			return CommandResult{}, errors.New("ambiguous insert result")
		case slices.Equal(a[:3], []string{"nft", "delete", "rule"}):
			deletions++
			active = nil
		}
		return CommandResult{}, nil
	}
	requireError(t, l.InstallNTPFirewallRule(), "ambiguous insert")
	comment := l.NTPRuleComment
	if comment == "" {
		t.Fatal("lost ambiguous rule ownership")
	}
	active = ntpRule(comment, "198.19.7.99")
	errs := l.Cleanup(true)
	requireEqual(t, len(errs), 1)
	if !strings.Contains(errs[0], "scope changed") {
		t.Fatal(errs)
	}
	requireEqual(t, l.NTPRuleComment, comment)
	requireEqual(t, deletions, 0)
	active = ntpRule(comment, "198.19.7.1")
	if errs = l.Cleanup(true); len(errs) > 0 {
		t.Fatal(errs)
	}
	requireEqual(t, l.NTPRuleComment, "")
	requireEqual(t, deletions, 1)
}

func TestNTPReorderedAcceptIsNotOwnedScopedRule(t *testing.T) {
	l := nativeLab(t)
	rule := ntpRule("ts-orch-fc-ntp-owned", "198.19.7.1")
	expr := array(rule["expr"])
	rule["expr"] = append([]any{expr[len(expr)-1]}, expr[:len(expr)-1]...)
	requireEqual(t, l.ExactNTPRule(rule), false)
}

func TestClockDiagnosticsAreBoundedAndCaptureFirewallCounters(t *testing.T) {
	l := nativeLab(t)
	config := "bindaddress 198.19.7.1\nport 123\n"
	if e := os.WriteFile(filepath.Join(l.Stage, "chrony.conf"), []byte(config), 0o600); e != nil {
		t.Fatal(e)
	}
	l.ChronyControlDir = "/run/ts-orch-fc-chrony.test1234"
	l.NTPRuleComment, l.NTPRuleHandle = "ts-orch-fc-ntp-owned", 101
	commands := [][]string{}
	ssh := 0
	l.Command = func(_ context.Context, argv []string, o CommandOptions) (CommandResult, error) {
		commands = append(commands, argv)
		if argv[0] == "ssh" {
			ssh++
			requireEqual(t, o.Timeout, 12*time.Second)
			return CommandResult{Code: 1, Stdout: strings.Repeat("timeout waiting for 198.19.7.1:123\n", 3000)}, nil
		}
		requireEqual(t, o.Timeout, 10*time.Second)
		return CommandResult{Stdout: strings.Repeat("counter packets 3 bytes 228\n", 3000)}, nil
	}
	l.CaptureClockDiagnostics("c1")
	l.CaptureClockDiagnostics("c1")
	record, e := readObject(filepath.Join(l.Logs, "c1-clock-diagnostics.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, label := range []string{"guest_time", "host_input_rules"} {
		value := object(record[label])
		requireEqual(t, value["truncated"], true)
		if len(str(value["stdout"])) > 32<<10 {
			t.Fatal("unbounded diagnostics", label)
		}
	}
	if !strings.Contains(str(object(record["host_input_rules"])["stdout"]), "counter packets 3") {
		t.Fatal(record)
	}
	requireEqual(t, record["ntp_rule_handle"], 101)
	requireEqual(t, record["chrony_config"], config)
	requireEqual(t, ssh, 1)
	tracking, input, nixos := false, false, false
	for _, command := range commands {
		tracking = tracking || slices.Contains(command, Chronyc) && slices.Contains(command, "tracking")
		input = input || command[len(command)-1] == "INPUT"
		nixos = nixos || command[len(command)-1] == "nixos-fw"
	}
	requireEqual(t, []bool{tracking, input, nixos}, []bool{true, true, true})
}

type chronyDirectoryInfo struct {
	name string
	mode os.FileMode
	uid  uint32
}

func (s chronyDirectoryInfo) Name() string       { return filepath.Base(s.name) }
func (s chronyDirectoryInfo) Size() int64        { return 0 }
func (s chronyDirectoryInfo) Mode() os.FileMode  { return s.mode }
func (s chronyDirectoryInfo) ModTime() time.Time { return time.Time{} }
func (s chronyDirectoryInfo) IsDir() bool        { return s.mode.IsDir() }
func (s chronyDirectoryInfo) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }

func TestChronySocketUsesPrivateRootOwnedRunDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, directory string
		uid             uint32
		mode            os.FileMode
		err             string
	}{
		{"owned", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, os.ModeDir | 0o700, ""},
		{"wrong_owner", "/run/ts-orch-fc-chrony.aB1cD2eF", 1000, os.ModeDir | 0o700, "root-owned"},
		{"wrong_mode", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, os.ModeDir | 0o755, "mode 0700"},
		{"symlink", "/run/ts-orch-fc-chrony.aB1cD2eF", 0, os.ModeSymlink | 0o700, "root-owned"},
		{"outside_run", "/tmp/ts-orch-fc-chrony.aB1cD2eF", 0, os.ModeDir | 0o700, "invalid private Chrony"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := nativeLab(t)
			calls := [][]string{}
			l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				calls = append(calls, argv)
				return CommandResult{Stdout: tc.directory + "\n"}, nil
			}
			l.lstat = func(path string) (os.FileInfo, error) {
				requireEqual(t, path, tc.directory)
				return chronyDirectoryInfo{path, tc.mode, tc.uid}, nil
			}
			path, e := l.ChronySocketPath()
			if tc.err != "" {
				requireError(t, e, tc.err)
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, path, tc.directory+"/chronyd.sock")
			requireEqual(t, l.ChronyControlDir, tc.directory)
			requireEqual(t, calls, [][]string{{"sudo", "-n", "mktemp", "-d", "-p", "/run", "ts-orch-fc-chrony.XXXXXXXX"}})
		})
	}
}

func TestForegroundChronyUsesRootSocketAndOwnedCleanup(t *testing.T) {
	l := nativeLab(t)
	control := "/run/ts-orch-fc-chrony.aB1cD2eF"
	socket := control + "/chronyd.sock"
	commands := [][]string{}
	spawned := []string{}
	l.lstat = func(path string) (os.FileInfo, error) { return chronyDirectoryInfo{path, os.ModeDir | 0o700, 0}, nil }
	l.startProcess = func(argv []string, _ string, _ io.Writer) (*Process, error) {
		spawned = slices.Clone(argv)
		return fixtureProcess(), nil
	}
	l.Command = func(_ context.Context, argv []string, o CommandOptions) (CommandResult, error) {
		commands = append(commands, slices.Clone(argv))
		switch {
		case slices.Contains(argv, "mktemp"):
			return CommandResult{Stdout: control + "\n"}, nil
		case slices.Contains(argv, Chronyc):
			requireEqual(t, argv, []string{"sudo", "-n", Chronyc, "-n", "-h", socket, "sources"})
			return CommandResult{Stdout: "^* remote 0 0 0\n"}, nil
		case slices.Contains(argv, "ss"):
			return CommandResult{Stdout: "UNCONN 0 0 198.19.7.1:123 0.0.0.0:*\n"}, nil
		case slices.Contains(argv, "rm"), slices.Contains(argv, "rmdir"):
			if !o.AllowFailure {
				t.Fatal(o)
			}
		}
		return CommandResult{}, nil
	}
	if e := l.StartChrony(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(l.Stage, "chrony.conf"))
	if e != nil {
		t.Fatal(e)
	}
	config := string(b)
	for _, part := range []string{"bindcmdaddress " + socket + "\ncmdport 0\n", "bindaddress 198.19.7.1\nallow 198.19.7.0/24\nport 123\n"} {
		if !strings.Contains(config, part) {
			t.Fatal(config)
		}
	}
	if strings.Contains(config, "local stratum") {
		t.Fatal("untrusted local Chrony clock")
	}
	requireEqual(t, spawned, []string{"sudo", "-n", Chronyd, "-x", "-d", "-4", "-f", filepath.Join(l.Stage, "chrony.conf")})
	if errs := l.Cleanup(false); len(errs) != 0 {
		t.Fatal(errs)
	}
	requireEqual(t, l.ChronyControlDir, "")
	requireEqual(t, commands[len(commands)-2:], [][]string{{"sudo", "-n", "rm", "-f", "--", socket}, {"sudo", "-n", "rmdir", "--", control}})
	requireEqual(t, commands[1], []string{Chronyd, "-p", "-f", filepath.Join(l.Stage, "chrony.conf")})
}
