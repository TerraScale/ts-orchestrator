package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func (l *Lab) Scenario() error {
	for _, step := range []func() error{l.Network, l.InstallNTPFirewallRule, l.StartChrony} {
		if e := step(); e != nil {
			return e
		}
	}
	for _, name := range Guests {
		if e := l.PrepareGuest(name); e != nil {
			return e
		}
	}
	for _, name := range Guests {
		if e := l.VMs[name].Boot(); e != nil {
			return e
		}
	}
	for _, name := range Guests {
		if e := l.WaitSSH(name); e != nil {
			return e
		}
	}
	for _, step := range []func() error{l.CheckGuestClocks, l.WaitCluster, l.VerifyBrokerClockGate, l.WaitCluster} {
		if e := step(); e != nil {
			return e
		}
	}
	registration, e := l.Wait("signed-host-registration", func() (any, error) {
		return l.Operator("host-register", 35*time.Second, false, "", "--registration", filepath.Join(l.Secrets, "registration.json"))
	}, l.Now().Add(100*time.Second), 2*time.Second)
	if e != nil {
		return e
	}
	if integer(object(registration)["generation"]) != 1 {
		return fmt.Errorf("host registration failed: %v", registration)
	}
	if e = l.WaitHost(""); e != nil {
		return e
	}
	original, e := l.Artifact("v1")
	if e != nil {
		return e
	}
	if e = l.Deploy(original, 1, "initial", "deploy"); e != nil {
		return e
	}
	if e = l.WaitHost("v1"); e != nil {
		return e
	}
	l.Note("milestone", Object{"name": "initial-native-workload"})
	for _, step := range []func() error{l.VMs["host"].Stop, l.VMs["host"].Boot, func() error { return l.WaitSSH("host") }, func() error { return l.WaitHost("v1") }} {
		if e = step(); e != nil {
			return e
		}
	}
	l.Note("milestone", Object{"name": "host-restart-recovery"})
	replacement, e := l.Artifact("v2")
	if e != nil {
		return e
	}
	firstSession, e := l.HostSession("v1", 35*time.Second, "")
	if e != nil {
		return e
	}
	firstNative, e := l.NativeObservation(15 * time.Second)
	if e != nil {
		return e
	}
	if e = l.requireWorkload(firstNative, "v1", "before controller loss"); e != nil {
		return e
	}
	connected, e := l.ConnectedController()
	if e != nil {
		return e
	}
	table, e := l.BlackholeHostController(connected)
	if e != nil {
		return e
	}
	nowConnected, e := l.ConnectedController()
	if e != nil {
		return e
	}
	if nowConnected != connected {
		return errors.New("host changed NATS peer before connected-controller crash")
	}
	if e = l.VMs[connected].Crash(); e != nil {
		return e
	}
	fault := l.Now()
	if e = l.WaitCluster(); e != nil {
		return e
	}
	if e = l.WaitSameProcessRenewal(firstSession, firstNative, connected, fault); e != nil {
		return e
	}
	if e = l.Deploy(replacement, 2, "one-node-loss", "deploy"); e != nil {
		return e
	}
	if e = l.WaitHost("v2"); e != nil {
		return e
	}
	l.Note("milestone", Object{"name": "one-controller-nats-node-loss"})
	for _, step := range []func() error{func() error { return l.RemoveBlackhole(table) }, l.VMs[connected].Boot, func() error { return l.WaitSSH(connected) }, l.WaitCluster, l.CheckGuestClocks} {
		if e = step(); e != nil {
			return e
		}
	}
	rollback, e := l.Intent(original, 3, "rollback")
	if e != nil {
		return e
	}
	lastNative, e := l.NativeObservation(15 * time.Second)
	if e != nil {
		return e
	}
	if e = l.requireWorkload(lastNative, "v2", "before quorum loss"); e != nil {
		return e
	}
	var matching []LeaseEvent
	var second, secondTable, sessionHash string
	var blackholeAt time.Time
	for attempt := range 3 {
		connected, e = l.ConnectedController()
		if e != nil {
			return e
		}
		for _, name := range Controllers {
			if name != connected {
				second = name
				break
			}
		}
		secondTable, e = l.BlackholeHostController(connected)
		if e != nil {
			return e
		}
		blackholeAt = l.Now()
		lastSession, e := l.HostSession("v2", 35*time.Second, "")
		if e != nil {
			return e
		}
		recent, e := l.VerifiedLeaseEvents(l.Now().Add(-8*time.Second), 15*time.Second)
		if e != nil {
			return e
		}
		sessionHash = head(hashBytes([]byte(str(lastSession["session_id"]))), 32)
		expiry := lastSession["expires_at"].(time.Time)
		matching = slices.DeleteFunc(recent, func(event LeaseEvent) bool {
			return event.Phase != "renew" || event.SessionHash != sessionHash || event.Epoch != integer(object(lastSession["report"])["epoch"]) || !event.ExpiresAt.Equal(expiry)
		})
		if len(matching) > 0 && matching[len(matching)-1].ExpiresAt.Sub(l.Now()) < 15*time.Second {
			matching = nil
		}
		if len(matching) > 0 {
			peer, peerErr := l.ConnectedController()
			if peerErr != nil || peer != connected {
				matching = nil
			}
		}
		if len(matching) > 0 {
			break
		}
		if e = l.RemoveBlackhole(secondTable); e != nil {
			return e
		}
		l.Note("lease_capture_retry", Object{"attempt": attempt + 1, "reason": "durable_expiry_not_equal_to_verified_renewal"})
		l.Sleep(time.Second)
	}
	if len(matching) == 0 {
		return errors.New("latest durable host expiry lacks a matching verified signed renewal")
	}
	lease := matching[len(matching)-1]
	before, e := l.NativeObservation(15 * time.Second)
	if e != nil {
		return e
	}
	if before["marker"] != "v2" || !sameNative(before, lastNative) {
		return errors.New("host agent or native v2 workload changed during lease capture")
	}
	if e = l.VMs[connected].Crash(); e != nil {
		return e
	}
	if e = l.VMs[second].Crash(); e != nil {
		return e
	}
	fault = l.Now()
	l.Sleep(time.Second)
	events, e := l.VerifiedLeaseEvents(lease.At, 15*time.Second)
	if e != nil {
		return e
	}
	for _, event := range events {
		if event.SessionHash == sessionHash && event.Epoch == lease.Epoch && event.ExpiresAt.After(lease.ExpiresAt) {
			lease = event
		}
	}
	allowance := max(int64(0), l.GuestClockUpperNS["host"]) + 250_000_000
	stopDeadline := lease.ExpiresAt.Add(-time.Duration((allowance+999)/1000) * time.Microsecond)
	l.Note("quorum_loss", Object{"crashed": []string{connected, second}, "blackhole_table": secondTable, "session_id_hash": sessionHash, "signed_renewal_at": lease.At, "signed_expiry": lease.ExpiresAt, "conservative_stop_deadline": stopDeadline, "host_clock_upper_ns": l.GuestClockUpperNS["host"], "expected_fence_at": lease.ExpiresAt.Add(-5 * time.Second), "blackhole_at": blackholeAt, "fault_at": fault, "native": lastNative})
	var stopped Object
	for l.Now().Before(stopDeadline) {
		o, e := l.NativeObservation(15 * time.Second)
		if e != nil {
			return e
		}
		if o["workload_alive"] == false {
			empty, e := l.CgroupEmpty(str(lastNative["workload_cgroup"]), str(lastNative["service_cgroup"]))
			if e != nil {
				return e
			}
			if empty {
				stopped = o
				break
			}
		}
		l.Sleep(250 * time.Millisecond)
	}
	if stopped == nil {
		return errors.New("native v2 workload survived the conservative signed-session stop deadline")
	}
	stoppedAt := l.Now()
	if !stoppedAt.Before(stopDeadline) {
		return errors.New("native v2 workload stopped after the conservative signed-session deadline")
	}
	l.Note("native_stopped_on_quorum_loss", Object{"stopped_at": stoppedAt, "seconds_before_expiry": lease.ExpiresAt.Sub(stoppedAt).Seconds(), "execution_reserve_seconds": 5, "original_cgroup_empty": true, "native": stopped})
	if e = l.HostRenewalFailureEvidence(blackholeAt, sessionHash, lease.Epoch, lease.ExpiresAt); e != nil {
		return e
	}
	denied, e := l.Operator("rollback", 25*time.Second, true, "", "--intent", rollback)
	if e != nil {
		return e
	}
	if denied != nil {
		return errors.New("rollback submitted without JetStream quorum")
	}
	l.Sleep(2 * time.Second)
	o, e := l.NativeObservation(15 * time.Second)
	if e != nil {
		return e
	}
	empty, e := l.CgroupEmpty(str(lastNative["workload_cgroup"]), str(lastNative["service_cgroup"]))
	if e != nil {
		return e
	}
	if o["workload_alive"] == true || !empty {
		return errors.New("native v2 workload resumed before quorum restoration")
	}
	l.Note("milestone", Object{"name": "quorum-loss-rejected-new-intent"})
	for _, step := range []func() error{l.VMs[connected].Boot, func() error { return l.WaitSSH(connected) }, l.WaitCluster, func() error { return l.Deploy(original, 3, "rollback", "rollback") }, func() error { return l.WaitHost("v1") }, l.VMs[second].Boot, func() error { return l.WaitSSH(second) }} {
		if e = step(); e != nil {
			return e
		}
	}
	l.Note("milestone", Object{"name": "rollback-after-quorum-recovery"})
	return nil
}
func (l *Lab) requireWorkload(o Object, version, stage string) error {
	if o["workload_alive"] != true || o["marker"] != version || str(o["workload_cgroup"]) == "" {
		return fmt.Errorf("native %s workload is not running %s", version, stage)
	}
	empty, e := l.CgroupEmpty(str(o["workload_cgroup"]), str(o["service_cgroup"]))
	if e != nil {
		return e
	}
	if empty {
		return fmt.Errorf("native %s workload is not running %s", version, stage)
	}
	return nil
}
func (l *Lab) CaptureHostStatus(label string) {
	l.defaults()
	if l.HostDiagnostics[label] {
		return
	}
	l.HostDiagnostics[label] = true
	captured := l.Now()
	snapshot := Object{"captured_at": captured, "label": label}
	r, e := l.cmd([]string{l.Binary, "operator", "hosts", "--config", l.OperatorConfig}, CommandOptions{Timeout: 10 * time.Second, AllowFailure: true})
	if errors.Is(e, contextDeadline) {
		snapshot["status"] = "timeout"
	} else if e != nil {
		snapshot["status"] = "error"
		snapshot["error_type"] = fmt.Sprintf("%T", e)
	} else if r.Code != 0 {
		snapshot["status"] = "operator_failed"
		snapshot["exit_code"] = r.Code
	} else {
		v, e := decode(r.Stdout)
		hosts, ce := CuratedHostStatuses(v, captured)
		if e != nil || ce != nil {
			snapshot["status"] = "error"
		} else {
			snapshot["status"] = "ok"
			snapshot["hosts"] = hosts
		}
	}
	path := filepath.Join(l.Logs, "host-status-"+label+".json")
	if e = writeJSON(path, snapshot); e != nil {
		l.Note("host_status_diagnostics", Object{"label": label, "status": "write_failed", "error_type": fmt.Sprintf("%T", e)})
		return
	}
	l.Note("host_status_diagnostics", Object{"label": label, "path": path, "status": snapshot["status"]})
}
func (l *Lab) CaptureClusterDiagnostics() {
	if l.ClusterCaptured {
		return
	}
	l.ClusterCaptured = true
	l.CaptureHostStatus("early-pending")
	for _, name := range Controllers {
		v := l.VMs[name]
		if v == nil || v.Process == nil {
			continue
		}
		done, e := v.Process.Exited()
		if e != nil || done {
			continue
		}
		r, e := l.SSH(name, "systemctl status ts-orch.service --no-pager --full; journalctl -u ts-orch.service -b --no-pager -n 300 -o short-iso-precise; ps -eo pid,ppid,stat,etime,cmd | grep '[t]errascale-orchestrator'", 12*time.Second, true)
		path := filepath.Join(l.Logs, name+"-live-diagnostics.txt")
		text := r.Stdout + r.Stderr
		if e != nil {
			text = fmt.Sprintf("controller diagnostics unavailable: %v\n", e)
		}
		_ = os.WriteFile(path, []byte(text), 0o600)
		l.Note("cluster_diagnostics", Object{"name": name, "path": path, "exit_code": r.Code})
	}
	if _, e := os.Stat(l.NATSDiag); e != nil {
		return
	}
	if _, e := os.Stat(filepath.Join(l.Secrets, "c1.creds")); e != nil {
		return
	}
	urls := []string{}
	for _, name := range Controllers {
		urls = append(urls, "tls://"+l.Addresses[name]+":4222")
	}
	argv := []string{l.NATSDiag, "--creds", filepath.Join(l.Secrets, "c1.creds"), "--operator-creds", filepath.Join(l.Secrets, "natsdiag.creds"), "--cell", "lab", "--urls", strings.Join(urls, ","), "--ca", filepath.Join(l.Secrets, "nats-ca.pem"), "--cert", filepath.Join(l.Secrets, "nats-c1.pem"), "--key", filepath.Join(l.Secrets, "nats-c1.key"), "--operator-cert", filepath.Join(l.Secrets, "nats-operator.pem"), "--operator-key", filepath.Join(l.Secrets, "nats-operator.key")}
	if l.ActiveOperationID != "" {
		argv = append(argv, "--operation-id", l.ActiveOperationID)
	}
	r, e := l.cmd(argv, CommandOptions{Timeout: 35 * time.Second, AllowFailure: true})
	path := filepath.Join(l.Logs, "nats-live-diagnostics.jsonl")
	text := r.Stdout + r.Stderr
	if e != nil {
		text = fmt.Sprintf("NATS diagnostics unavailable: %v\n", e)
	}
	_ = os.WriteFile(path, []byte(text), 0o600)
	l.Note("cluster_diagnostics", Object{"name": "nats", "path": path, "exit_code": r.Code})
}
func (l *Lab) CaptureFailureDiagnostics() {
	if l.FailureCaptured {
		return
	}
	l.CaptureHostStatus("failure")
	v := l.VMs["host"]
	if v == nil || v.Process == nil {
		return
	}
	done, e := v.Process.Exited()
	if e != nil || done {
		return
	}
	l.FailureCaptured = true
	r, e := l.SSH("host", failureDiagnosticScript, 35*time.Second, true)
	path := filepath.Join(l.Logs, "host-failure-diagnostics.txt")
	text := r.Stdout + r.Stderr
	if e != nil {
		text = fmt.Sprintf("host diagnostics unavailable: %v\n", e)
	}
	_ = os.WriteFile(path, []byte(text), 0o600)
	l.Note("failure_diagnostics", Object{"name": "host", "path": path, "exit_code": r.Code})
}
func (l *Lab) CaptureClockDiagnostics(name string) {
	l.defaults()
	if l.ClockDiagnostics[name] {
		return
	}
	l.ClockDiagnostics[name] = true
	snapshot := Object{"captured_at": l.Now(), "guest": name}
	record := func(label string, argv []string, guest string) {
		var r CommandResult
		var e error
		if guest != "" {
			r, e = l.SSH(name, guest, 12*time.Second, true)
		} else {
			r, e = l.cmd(argv, CommandOptions{Timeout: 10 * time.Second, AllowFailure: true})
		}
		if e != nil {
			snapshot[label] = Object{"error_type": fmt.Sprintf("%T", e), "error": head(e.Error(), 512)}
		} else {
			snapshot[label] = Object{"exit_code": r.Code, "stdout": head(r.Stdout, 32<<10), "stderr": head(r.Stderr, 2048), "truncated": len(r.Stdout) > 32<<10 || len(r.Stderr) > 2048}
		}
	}
	record("guest_time", nil, clockDiagnosticScript)
	if l.ClockHostDiagnostics == nil {
		snapshot["host_clock_captured_at"] = l.Now()
		if l.ChronyControlDir != "" {
			for _, suffix := range []string{"sources", "tracking", "clients"} {
				record("chrony_"+suffix, []string{"sudo", "-n", Chronyc, "-n", "-h", filepath.Join(l.ChronyControlDir, "chronyd.sock"), suffix}, "")
			}
		}
		b, e := os.ReadFile(filepath.Join(l.Stage, "chrony.conf"))
		if e != nil {
			snapshot["chrony_config"] = Object{"error_type": fmt.Sprintf("%T", e)}
		} else {
			snapshot["chrony_config"] = head(string(b), 4096)
		}
		record("chrony_listener", []string{"sudo", "-n", "ss", "-H", "-lun"}, "")
		record("host_input_rules", []string{"sudo", "-n", "nft", "-j", "-a", "list", "chain", "ip", "filter", "INPUT"}, "")
		record("host_nixos_firewall", []string{"sudo", "-n", "nft", "-j", "-a", "list", "chain", "ip", "filter", "nixos-fw"}, "")
		snapshot["ntp_rule_comment"] = l.NTPRuleComment
		snapshot["ntp_rule_handle"] = l.NTPRuleHandle
		l.ClockHostDiagnostics = Object{}
		for k, v := range snapshot {
			if k != "captured_at" && k != "guest" && k != "guest_time" {
				l.ClockHostDiagnostics[k] = v
			}
		}
	} else {
		for k, v := range l.ClockHostDiagnostics {
			snapshot[k] = v
		}
	}
	path := filepath.Join(l.Logs, name+"-clock-diagnostics.json")
	if e := writeJSON(path, snapshot); e != nil {
		l.Note("clock_diagnostics", Object{"guest": name, "status": "write_failed", "error_type": fmt.Sprintf("%T", e)})
	} else {
		l.Note("clock_diagnostics", Object{"guest": name, "path": path})
	}
}
func (l *Lab) Cleanup(preserve bool) []string {
	l.defaults()
	originalContext := l.Ctx
	l.Ctx = context.WithoutCancel(originalContext)
	defer func() { l.Ctx = originalContext }()
	errs := []string{}
	if pendingErrors := quiescePendingCommands(&l.PendingCommands); len(pendingErrors) > 0 {
		l.Note("guest_images_retained", Object{"path": l.Images, "reason": "pending_command_cleanup_failed"})
		return pendingErrors
	}
	imagesSafe := true
	stop := func(p **Process, label string) {
		if *p == nil {
			return
		}
		if e := (*p).Stop(5*time.Second, false); e != nil {
			errs = append(errs, fmt.Sprintf("stop %s: %v", label, e))
			return
		}
		*p = nil
	}
	stop(&l.SessionProbeProcess, "session probe")
	if e := l.RemoveNTPFirewallRule(); e != nil {
		errs = append(errs, "remove owned private NTP firewall rule: "+e.Error())
	}
	if len(l.PendingCommands) > 0 {
		return errs
	}
	for i := len(l.CreatedNFTTables) - 1; i >= 0; i-- {
		table := l.CreatedNFTTables[i]
		r, e := l.sudoAllow("nft", "delete", "table", "bridge", table)
		if len(l.PendingCommands) > 0 {
			return append(errs, fmt.Sprintf("delete owned nft table %s is not confirmed stopped: %v", table, e))
		}
		if e != nil || r.Code != 0 {
			errs = append(errs, fmt.Sprintf("delete owned nft table %s: %v %s", table, e, r.Stderr))
		} else {
			l.CreatedNFTTables = slices.Delete(l.CreatedNFTTables, i, i+1)
		}
	}
	for i := len(Guests) - 1; i >= 0; i-- {
		if v := l.VMs[Guests[i]]; v != nil {
			if e := v.Stop(); e != nil {
				imagesSafe = false
				errs = append(errs, fmt.Sprintf("stop %s: %v", v.Name, e))
			}
		}
	}
	if l.SocketDir != "" {
		errs = append(errs, CleanupOwnedSockets(l.VMs, l.SocketDir)...)
	}
	for i := len(l.Mounted) - 1; i >= 0; i-- {
		mount := l.Mounted[i]
		r, e := l.sudoAllow("umount", mount)
		if len(l.PendingCommands) > 0 {
			return append(errs, fmt.Sprintf("unmount %s is not confirmed stopped: %v", mount, e))
		}
		if e != nil || r.Code != 0 {
			errs = append(errs, fmt.Sprintf("unmount %s: %v %s", mount, e, r.Stderr))
		} else {
			l.Mounted = slices.Delete(l.Mounted, i, i+1)
		}
	}
	stop(&l.ChronyProcess, "chrony")
	if l.ChronyControlDir != "" && l.ChronyProcess == nil {
		r, e := l.sudoAllow("rm", "-f", "--", filepath.Join(l.ChronyControlDir, "chronyd.sock"))
		if len(l.PendingCommands) > 0 {
			return append(errs, fmt.Sprintf("Chrony socket removal is not confirmed stopped: %v", e))
		}
		if e == nil && r.Code == 0 {
			r, e = l.sudoAllow("rmdir", "--", l.ChronyControlDir)
			if len(l.PendingCommands) > 0 {
				return append(errs, fmt.Sprintf("Chrony directory removal is not confirmed stopped: %v", e))
			}
		}
		if e != nil || r.Code != 0 {
			errs = append(errs, fmt.Sprintf("remove owned Chrony control directory %s: %v %s", l.ChronyControlDir, e, r.Stderr))
		} else {
			l.ChronyControlDir = ""
		}
	}
	for i := len(l.CreatedLinks) - 1; i >= 0; i-- {
		link := l.CreatedLinks[i]
		r, e := l.sudoAllow("ip", "link", "del", link)
		if len(l.PendingCommands) > 0 {
			return append(errs, fmt.Sprintf("delete link %s is not confirmed stopped: %v", link, e))
		}
		if e != nil || r.Code != 0 {
			errs = append(errs, fmt.Sprintf("delete link %s: %v %s", link, e, r.Stderr))
		} else {
			l.CreatedLinks = slices.Delete(l.CreatedLinks, i, i+1)
		}
	}
	if preserve || len(errs) > 0 {
		reason := "qualification_failed"
		if !preserve {
			reason = "cleanup_failed"
		}
		l.Note("guest_images_retained", Object{"path": l.Images, "reason": reason})
	} else if imagesSafe && len(l.Mounted) == 0 {
		_ = os.RemoveAll(l.Images)
	} else {
		errs = append(errs, "guest images retained for manual cleanup: "+l.Images)
	}
	_ = os.RemoveAll(l.Secrets)
	_ = os.RemoveAll(l.Stage)
	return errs
}
