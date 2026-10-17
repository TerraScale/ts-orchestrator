package firecracker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProductionNTPResponse(t *testing.T) {
	request := make([]byte, 48)
	request[0] = 0x23
	copy(request[40:], "client01")
	answer, e := NTPResponse(request, 1700000000.25, 1700000000.5)
	if e != nil || len(answer) != 48 || answer[0]&7 != 4 || answer[1] != 2 || string(answer[24:32]) != "client01" {
		t.Fatal(answer, e)
	}
	_, e = NTPResponse([]byte("short"), 1700000000, 1700000000)
	requireError(t, e, "not an NTP client request")
}
func productionAuditFixture() Object {
	requests := []any{}
	for _, p := range IMDSPaths {
		requests = append(requests, Object{"method": "GET", "host": "169.254.169.254", "requestUri": p, "status": 200, "listed": true})
	}
	requests = append(requests, Object{"method": "POST", "host": "auth.sa-saopaulo-1.oraclecloud.com", "status": 200, "listed": true})
	for _, p := range []string{"/compute/0", "/compute/1", "/compute/2"} {
		requests = append(requests, Object{"method": "GET", "host": "iaas.sa-saopaulo-1.oraclecloud.com", "requestUri": p, "status": 200, "listed": true})
	}
	requests = append(requests, Object{"method": "GET", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com", "status": 200, "listed": true})
	slots := Object{}
	for _, slot := range ProductionSlots {
		slots[slot] = Object{"requests": requests, "overflow": 0}
	}
	return Object{"unknownSources": 0, "slots": slots}
}
func TestProductionAuditAcceptsNetBirdVNICRead(t *testing.T) {
	audit := productionAuditFixture()
	slots := object(audit["slots"])
	for _, slot := range ProductionSlots {
		entry := object(slots[slot])
		requests := slices.Clone(array(entry["requests"]))
		for _, p := range OptionalIMDSPaths {
			requests = append(requests, Object{"method": "GET", "host": "169.254.169.254", "requestUri": p, "status": 200, "listed": true})
		}
		entry["requests"] = requests
	}
	counts, e := CheckProductionAudit(audit)
	if e != nil {
		t.Fatal(e)
	}
	requireEqual(t, counts, map[string]int{"controller-a": 12, "controller-b": 12, "controller-c": 12})
}
func TestProductionAudit(t *testing.T) {
	for _, tc := range []string{"valid", "write", "bad_status", "duplicate_metadata_compute", "unknown_imds", "unknown_source", "empty_slot", "overflow"} {
		t.Run(tc, func(t *testing.T) {
			audit := productionAuditFixture()
			slots := object(audit["slots"])
			requests := array(object(slots["controller-c"])["requests"])
			switch tc {
			case "write":
				object(slots["controller-c"])["requests"] = append(requests, Object{"method": "PUT", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com", "status": 405, "listed": false})
			case "bad_status":
				object(requests[0])["status"] = 404
			case "duplicate_metadata_compute":
				for _, r := range requests {
					r := object(r)
					if r["host"] == "169.254.169.254" {
						r["requestUri"] = "/opc/v2/instance/id"
					}
					if r["host"] == "iaas.sa-saopaulo-1.oraclecloud.com" {
						r["requestUri"] = "/compute/1"
					}
				}
			case "unknown_imds":
				object(slots["controller-c"])["requests"] = append(requests, Object{"method": "GET", "host": "169.254.169.254", "requestUri": "/opc/v2/instance/", "status": 200, "listed": true})
			case "unknown_source":
				audit["unknownSources"] = 1
			case "empty_slot":
				object(slots["controller-c"])["requests"] = []any{}
			case "overflow":
				object(slots["controller-c"])["overflow"] = 1
			}
			counts, e := CheckProductionAudit(audit)
			if tc == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, counts, map[string]int{"controller-a": 11, "controller-b": 11, "controller-c": 11})
			} else if e == nil {
				t.Fatal("accepted", tc)
			}
		})
	}
}
func TestProductionPinnedFileDetectsChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if e := os.WriteFile(path, []byte("pinned"), 0o644); e != nil {
		t.Fatal(e)
	}
	p, e := RequirePinnedFile(path, hashBytes([]byte("pinned")))
	if e != nil || p != path {
		t.Fatal(p, e)
	}
	if e = os.WriteFile(path, []byte("changed"), 0o644); e != nil {
		t.Fatal(e)
	}
	_, e = RequirePinnedFile(path, hashBytes([]byte("pinned")))
	requireError(t, e, "hash mismatch")
}
func TestProductionFirewallBoundaries(t *testing.T) {
	q, e := NewProductionQualification(t.Context(), ProductionOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(q.Root)
	calls := [][]string{}
	programs := []string{}
	q.Command = func(_ context.Context, argv []string, o CommandOptions) (CommandResult, error) {
		calls = append(calls, argv)
		if len(argv) > 2 && argv[1] == "list" {
			return CommandResult{Code: 1}, nil
		}
		if o.Input == "" {
			t.Fatal("empty firewall program")
		}
		programs = append(programs, o.Input)
		return CommandResult{}, nil
	}
	if e = q.Firewall(); e != nil {
		t.Fatal(e)
	}
	if len(calls) != 4 || len(programs) != 2 || len(q.CreatedTables) != 2 {
		t.Fatal(calls, programs, q.CreatedTables)
	}
	for _, part := range []string{"tcp dport { 4222, 6222 } accept", "ether type arp accept", "169.254.169.254 tcp dport 80 counter accept", "10.44.0.1 udp dport 123 counter accept", "counter drop"} {
		if !strings.Contains(programs[1], part) {
			t.Fatal(part)
		}
	}
	if strings.Contains(programs[0], "policy drop") {
		t.Fatal("host traffic policy affected")
	}
}
func TestProductionFailedRunRetainsCounters(t *testing.T) {
	q, e := NewProductionQualification(t.Context(), ProductionOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(q.Root)
	rules := "table bridge tspr_test {\nudp dport 123 counter packets 6 bytes 288 accept\ncounter packets 1 bytes 48 drop\n}\n"
	q.CreatedTables = [][2]string{{"bridge", "tspr_test"}}
	socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	close(done)
	requests, replies := map[string]int{}, map[string]int{}
	for _, slot := range ProductionSlots {
		requests[slot], replies[slot] = 2, 0
	}
	q.NTP = &NTPServer{Socket: socket, Requests: requests, Replies: replies, SendErrors: map[string]int{}, Done: done}
	commands := [][]string{}
	q.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
		commands = append(commands, slices.Clone(argv))
		if argv[1] == "list" {
			return CommandResult{Stdout: rules}, nil
		}
		return CommandResult{}, nil
	}
	errs := q.Cleanup()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	requireEqual(t, q.Report["ntpRequests"], requests)
	requireEqual(t, q.Report["ntpReplies"], replies)
	requireEqual(t, commands, [][]string{{"nft", "list", "table", "bridge", "tspr_test"}, {"nft", "delete", "table", "bridge", "tspr_test"}})
	requireEqual(t, q.Report["firewallDrops"], 1)
	requireEqual(t, q.Report["firewallCounterFiles"], Object{"bridge": "firewall-bridge.txt"})
	b, e := os.ReadFile(filepath.Join(q.Root, "firewall-bridge.txt"))
	if e != nil || string(b) != rules {
		t.Fatal(string(b), e)
	}
}
func TestProductionRebootDisconnectRequiresNewIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, firstBoot, boot, inv string
		valid                      bool
	}{{"new_boot_and_invocation", "boot-old", "boot-new", "inv-new", true}, {"old_boot", "boot-old", "boot-old", "inv-new", false}, {"old_invocation", "boot-old", "boot-new", "inv-old", false}, {"identity_changes_during_initial_health", "boot-unexpected", "boot-new", "inv-new", false}} {
		t.Run(tc.name, func(t *testing.T) {
			q := nativeProduction(t)
			rebooted := map[string]bool{}
			identities := Object{}
			for _, slot := range ProductionSlots {
				identities[slot] = Object{"uid": 1000, "gid": 1000}
				q.VMs[slot] = &ProductionVM{Q: q, Slot: slot}
			}
			q.Report["serviceIdentity"] = identities
			q.bootVM = func(vm *ProductionVM) error { vm.Process = fixtureProcess(); return nil }
			q.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
			q.sleep = func(time.Duration) error { return errors.New("test SSH did not return a new boot") }
			q.Command = func(_ context.Context, argv []string, options CommandOptions) (CommandResult, error) {
				slot := ""
				for name, address := range ProductionAddresses {
					if slices.Contains(argv, "root@"+address) {
						slot = name
					}
				}
				if slot == "" {
					t.Fatal(argv)
				}
				script := argv[len(argv)-1]
				if script == quote("systemctl reboot") {
					requireEqual(t, options.Timeout, 10*time.Second)
					rebooted[slot] = true
					return CommandResult{}, context.DeadlineExceeded
				}
				if script == quote("cat /proc/sys/kernel/random/boot_id") {
					boot := "boot-old"
					if rebooted[slot] {
						// WaitSSH returns a different identity even when the subsequent
						// health readback falsely reports the old boot.
						boot = "boot-new"
					}
					return CommandResult{Stdout: boot + "\n"}, nil
				}
				requireEqual(t, script, quote(productionHealthScript))
				boot, invocation := tc.firstBoot, "inv-old"
				if rebooted[slot] {
					boot, invocation = tc.boot, tc.inv
				}
				return CommandResult{Stdout: fmt.Sprintf("Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\n%s\n%s\n", invocation, boot)}, nil
			}
			e := q.RunVMs()
			if !tc.valid {
				part := "did not complete a new production controller invocation"
				if tc.name == "identity_changes_during_initial_health" {
					part = "boot identity changed during health check"
				}
				requireError(t, e, part)
				requireEqual(t, object(q.Report["guests"]), Object{})
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			guests := object(q.Report["guests"])
			requireEqual(t, len(guests), len(ProductionSlots))
			for _, slot := range ProductionSlots {
				first, restart := object(object(guests[slot])["first"]), object(object(guests[slot])["restart"])
				requireEqual(t, first["bootId"], "boot-old")
				requireEqual(t, first["controllerInvocation"], "inv-old")
				requireEqual(t, restart["bootId"], "boot-new")
				requireEqual(t, restart["controllerInvocation"], "inv-new")
			}
		})
	}
}
func TestProductionHealthFailureNamesStageAndDiagnostics(t *testing.T) {
	if !strings.Contains(productionHealthScript, "|| fail ntp-synchronized") || !strings.Contains(productionHealthDiagnosticScript, "SYSLOG_IDENTIFIER=systemd") {
		t.Fatal("missing stage or curated journal")
	}
	if strings.Contains(productionHealthDiagnosticScript, "journalctl -u terrascale-orchestrator") {
		t.Fatal("uncurated application journal")
	}
	q := nativeProduction(t)
	current := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	q.now = func() time.Time { return current }
	q.sleep = func(time.Duration) error { current = current.Add(301 * time.Second); return nil }
	commands := []string{}
	q.Command = func(_ context.Context, argv []string, options CommandOptions) (CommandResult, error) {
		commands = append(commands, argv[len(argv)-1])
		if len(commands) == 1 {
			requireEqual(t, options.Timeout, 15*time.Second)
			return CommandResult{Code: 1, Stderr: "failed-stage=ntp-synchronized\n"}, nil
		}
		requireEqual(t, options.Timeout, 20*time.Second)
		return CommandResult{Stdout: "[clock]\nno\n"}, nil
	}
	vm := &ProductionVM{Q: q, Slot: "controller-a"}
	_, failure := vm.Health(988, 988)
	requireError(t, failure, "failed-stage=ntp-synchronized")
	requireError(t, failure, "guest diagnostics:\n[clock]\nno")
	requireEqual(t, len(commands), 2)
	requireEqual(t, commands, []string{quote(productionHealthScript), quote(productionHealthDiagnosticScript)})
	_, e := ProductionHealthEvidence("Uid: 988 988 988 988\nGid: 988 988 988 988\ninvocation\nboot\n", 988, 988)
	if e != nil {
		t.Fatal(e)
	}
	_, e = ProductionHealthEvidence("Uid: 0 0 0 0\nGid: 988 988 988 988\ninvocation\nboot\n", 988, 988)
	requireError(t, e, "failed-stage=service-identity")
}

func nativeProduction(t *testing.T) *ProductionQualification {
	t.Helper()
	q, e := NewProductionQualification(t.Context(), ProductionOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(q.Root) })
	return q
}

func TestProductionNetworkNamespace(t *testing.T) {
	for _, tc := range []struct {
		name      string
		run, same bool
	}{{"enters_after_host_checks", true, true}, {"prepare_only", false, true}, {"already_isolated", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			steps := []string{}
			commands := [][]string{}
			var reexec []string
			sentinel := errors.New("reexec")
			dependencies := namespaceDependencies{
				same: func() (bool, error) { return tc.same, nil },
				uid:  func() int { return 0 },
				command: func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
					commands = append(commands, slices.Clone(argv))
					steps = append(steps, argv[0])
					if argv[0] == "timedatectl" {
						return CommandResult{Stdout: "yes\n"}, nil
					}
					return CommandResult{Stdout: "[]"}, nil
				},
				lookPath: func(name string) (string, error) {
					requireEqual(t, name, "unshare")
					steps = append(steps, "lookpath")
					return "/bin/unshare", nil
				},
				executable: func() (string, error) { return "/bin/ts-orch", nil },
				reexec: func(path string, argv, _ []string) error {
					requireEqual(t, path, "/bin/unshare")
					steps = append(steps, "reexec")
					reexec = slices.Clone(argv)
					return sentinel
				},
			}
			argv := []string{"qualification", "firecracker", "production", "--run"}
			e := ensureProductionNetworkNamespace(t.Context(), tc.run, argv, dependencies)
			if tc.run && tc.same {
				if e != sentinel {
					t.Fatal(e)
				}
				requireEqual(t, steps, []string{"ip", "ip", "timedatectl", "lookpath", "reexec"})
				requireEqual(t, commands[2], []string{"timedatectl", "show", "-p", "NTPSynchronized", "--value"})
				requireEqual(t, reexec, append([]string{"/bin/unshare", "--net", "--", "/bin/ts-orch"}, argv...))
			} else {
				if e != nil || reexec != nil || len(commands) != 0 {
					t.Fatal(e, reexec, commands)
				}
			}
		})
	}
}

func TestProductionNetworkRaisesLoopbackFirst(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(fmt.Sprint(same), func(t *testing.T) {
			q := nativeProduction(t)
			q.sameNamespace = func() (bool, error) { return same, nil }
			commands := [][]string{}
			q.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				commands = append(commands, slices.Clone(argv))
				if argv[0] == "nft" && argv[1] == "list" {
					return CommandResult{Code: 1}, nil
				}
				return CommandResult{}, nil
			}
			e := q.Network()
			if same {
				requireError(t, e, "private namespace")
				requireEqual(t, commands, [][]string{})
			} else {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, commands[0], []string{"ip", "link", "set", "lo", "up"})
			}
		})
	}
}

func TestProductionCleanupKillsStuckSimulator(t *testing.T) {
	q := nativeProduction(t)
	p := fixtureProcess()
	killed := false
	signals := []int{}
	p.hooks.wait = func(time.Duration) (bool, error) { return false, nil }
	p.hooks.signal = func(_ int, signal syscall.Signal) error {
		signals = append(signals, int(signal))
		if signal == syscall.SIGKILL {
			killed = true
		}
		return nil
	}
	q.Simulator = p
	errs := q.Cleanup()
	requireEqual(t, errs, []string{"simulator required SIGKILL during cleanup"})
	requireEqual(t, signals, []int{15, 9})
	requireEqual(t, killed, true)
	requireEqual(t, p.Reaped, true)
	if q.Simulator != nil {
		t.Fatal("stopped simulator retained")
	}
}

func TestQualificationCleanupSurvivesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	l := nativeLab(t)
	l.Ctx = ctx
	l.CreatedNFTTables = []string{"owned-table"}
	l.Command = func(ctx context.Context, _ []string, _ CommandOptions) (CommandResult, error) {
		if e := ctx.Err(); e != nil {
			return CommandResult{}, e
		}
		return CommandResult{}, nil
	}
	if errs := l.Cleanup(true); len(errs) > 0 {
		t.Fatal(errs)
	}
	if l.Ctx != ctx {
		t.Fatal("cleanup replaced caller context")
	}
	q := nativeProduction(t)
	q.Ctx = ctx
	q.CreatedLinks = []string{"owned-bridge"}
	q.Command = l.Command
	if errs := q.Cleanup(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if q.Ctx != ctx {
		t.Fatal("cleanup replaced caller context")
	}
}
func TestProductionVMStopExitSignalRace(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "vm.sock")
	if e := os.WriteFile(socket, nil, 0o600); e != nil {
		t.Fatal(e)
	}
	serial, e := os.Create(filepath.Join(root, "serial.log"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := Start([]string{"/bin/sh", "-c", "exit 0"}, "", serial)
	if e != nil {
		serial.Close()
		t.Fatal(e)
	}
	p.Output = serial
	if _, e = p.WaitUnreaped(time.Second); e != nil {
		t.Fatal(e)
	}
	v := &ProductionVM{Socket: socket, Process: p}
	if e = v.Stop(); e != nil {
		t.Fatal(e)
	}
	if v.Process != nil {
		t.Fatal("process retained")
	}
	if p.Output != nil {
		t.Fatal("serial output retained")
	}
	if _, e = serial.Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("serial output not closed", e)
	}
	if _, e = os.Stat(socket); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
func TestProductionNetworkCollision(t *testing.T) {
	for _, tc := range []struct {
		routes, addresses string
		err               string
	}{{`[{"dst":"10.44.0.0/24"}]`, `[]`, "host route collides"}, {`[{"dst":"default"}]`, `[{"addr_info":[{"family":"inet","local":"169.254.169.254"}]}]`, "host address collides"}, {`[{"dst":"192.168.0.0/16"}]`, `[]`, ""}} {
		calls := 0
		e := CheckNetworkCollision(t.Context(), func(context.Context, []string, CommandOptions) (CommandResult, error) {
			calls++
			if calls == 1 {
				return CommandResult{Stdout: tc.routes}, nil
			}
			return CommandResult{Stdout: tc.addresses}, nil
		}, netip.MustParsePrefix("10.44.0.0/24"), true)
		if tc.err != "" {
			requireError(t, e, tc.err)
		} else if e != nil {
			t.Fatal(e)
		}
	}
}
