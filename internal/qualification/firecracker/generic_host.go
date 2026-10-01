package firecracker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func ValidateNativeCgroupPath(path, service string) error {
	valid := func(s string) []string {
		if !strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
			return nil
		}
		parts := strings.Split(s[1:], "/")
		if slices.ContainsFunc(parts, func(p string) bool { return p == "" || p == "." || p == ".." }) {
			return nil
		}
		return parts
	}
	sp, wp := valid(service), valid(path)
	if len(sp) < 2 || sp[len(sp)-1] != "ts-orch.service" || len(wp) != len(sp)+2 {
		return errors.New("invalid native workload cgroup path")
	}
	for i, p := range sp {
		if wp[i] != p || (i < len(sp)-1 && !regexp.MustCompile(`^[A-Za-z0-9_-]+\.slice$`).MatchString(p)) {
			return errors.New("invalid native workload cgroup path")
		}
	}
	if !regexp.MustCompile(`^terrascale-host-[0-9a-f]{16}$`).MatchString(wp[len(sp)]) || wp[len(wp)-1] != "terrabase" {
		return errors.New("invalid native workload cgroup path")
	}
	return nil
}
func ParseNativeObservation(output string) (Object, error) {
	o := Object{}
	for line := range strings.SplitSeq(output, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			o[k] = v
		}
	}
	for _, k := range []string{"agent_pid", "agent_state", "agent_cgroup", "service_cgroup", "invocation", "workload_pid", "workload_state_before", "workload_state", "workload_cgroup", "marker"} {
		if _, ok := o[k]; !ok {
			return nil, errors.New("incomplete native process observation")
		}
	}
	if str(o["service_cgroup"]) == "" || o["agent_cgroup"] != str(o["service_cgroup"])+"/supervisor" {
		return nil, errors.New("host agent is not in its systemd supervisor subgroup")
	}
	_, before, _ := strings.CutLast(str(o["workload_state_before"]), ":")
	if before == "" {
		before = str(o["workload_state_before"])
	}
	_, after, _ := strings.CutLast(str(o["workload_state"]), ":")
	if after == "" {
		after = str(o["workload_state"])
	}
	if (before == "missing" && after != "missing") || (after != "missing" && before != after) {
		return nil, errors.New("native workload PID changed during cgroup observation")
	}
	if after == "missing" {
		o["workload_cgroup"] = ""
	}
	state, _, _ := strings.Cut(str(o["workload_state"]), ":")
	alive := !slices.Contains([]string{"missing", "Z", "X"}, state)
	o["workload_alive"] = alive
	if alive {
		if e := ValidateNativeCgroupPath(str(o["workload_cgroup"]), str(o["service_cgroup"])); e != nil {
			return nil, e
		}
	}
	return o, nil
}

const nativeObservationScript = `set -eu
agent=$(systemctl show ts-orch.service -p MainPID --value)
invocation=$(systemctl show ts-orch.service -p InvocationID --value)
service_cgroup=$(systemctl show ts-orch.service -p ControlGroup --value)
agent_cgroup=''
case "$agent" in ''|0|*[!0-9]*) ;; *)
    if [ -r "/proc/$agent/cgroup" ]; then agent_cgroup=$(awk -F: '$1 == "0" {print $3}' "/proc/$agent/cgroup"); fi ;;
esac
workload=$(cat /run/ts-orch-workload/pid 2>/dev/null || true)
marker=$(cat /run/ts-orch-workload/marker 2>/dev/null || true)
proc_state() {
    case "$1" in ''|0|*[!0-9]*) printf 'missing'; return ;; esac
    if [ -r "/proc/$1/stat" ]; then awk '{print $3 ":" $22}' "/proc/$1/stat"; else printf 'missing'; fi
}
workload_state_before=$(proc_state "$workload")
workload_cgroup=''
case "$workload" in ''|0|*[!0-9]*) ;; *)
    if [ -r "/proc/$workload/cgroup" ]; then workload_cgroup=$(awk -F: '$1 == "0" {print $3}' "/proc/$workload/cgroup"); fi ;;
esac
printf 'agent_pid=%s\nagent_state=%s\nagent_cgroup=%s\nservice_cgroup=%s\ninvocation=%s\nworkload_pid=%s\nworkload_state_before=%s\nworkload_state=%s\nworkload_cgroup=%s\nmarker=%s\n' "$agent" "$(proc_state "$agent")" "$agent_cgroup" "$service_cgroup" "$invocation" "$workload" "$workload_state_before" "$(proc_state "$workload")" "$workload_cgroup" "$marker"
`

func (l *Lab) NativeObservation(timeout time.Duration) (Object, error) {
	r, e := l.SSH("host", nativeObservationScript, timeout, false)
	if e != nil {
		return nil, e
	}
	return ParseNativeObservation(r.Stdout)
}
func CgroupEmptyScript(path, service string) (string, error) {
	if e := ValidateNativeCgroupPath(path, service); e != nil {
		return "", e
	}
	role := "/sys/fs/cgroup" + path
	servicePath := "/sys/fs/cgroup" + service
	runner := "/sys/fs/cgroup" + filepath.Dir(path)
	prefixes := []string{"/sys", "/sys/fs", "/sys/fs/cgroup"}
	for part := range strings.SplitSeq(path[1:], "/") {
		prefixes = append(prefixes, prefixes[len(prefixes)-1]+"/"+part)
	}
	for i := range prefixes {
		prefixes[i] = quote(prefixes[i])
	}
	events := role + "/cgroup.events"
	return "set -eu\ntest \"$(systemctl show ts-orch.service -p ControlGroup --value)\" = " + quote(service) + "\nfor entry in " + strings.Join(prefixes, " ") + "; do test ! -L \"$entry\" || exit 4; done\ntest -d " + quote(servicePath) + "\ngrep -qw memory " + quote(servicePath+"/cgroup.controllers") + "\nfor parent in " + quote(servicePath) + " " + quote(runner) + "; do\n test -f \"$parent/cgroup.procs\"\n test ! -s \"$parent/cgroup.procs\"\n grep -qw memory \"$parent/cgroup.subtree_control\"\ndone\nif test -f " + quote(events) + "; then\n test ! -L " + quote(events) + "\n cat " + quote(events) + "\nelif test -e " + quote(role) + "; then exit 5\nelse printf 'populated 0\\n'; fi", nil
}
func (l *Lab) CgroupEmpty(path, service string) (bool, error) {
	s, e := CgroupEmptyScript(path, service)
	if e != nil {
		return false, e
	}
	r, e := l.SSH("host", s, 15*time.Second, false)
	if e != nil {
		return false, e
	}
	states := []string{}
	for line := range strings.SplitSeq(r.Stdout, "\n") {
		if strings.HasPrefix(line, "populated ") {
			states = append(states, line)
		}
	}
	if slices.Equal(states, []string{"populated 0"}) {
		return true, nil
	}
	if slices.Equal(states, []string{"populated 1"}) {
		return false, nil
	}
	return false, errors.New("native workload cgroup has no populated state")
}
func (l *Lab) ConnectedController() (string, error) {
	r, e := l.SSH("host", "ss -Hnt state established", 10*time.Second, false)
	if e != nil {
		return "", e
	}
	connected := map[string]bool{}
	for line := range strings.SplitSeq(r.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, _, ok := strings.CutLast(f[len(f)-2], ":")
		if !ok || strings.Trim(local, "[]") != l.Addresses["host"] {
			continue
		}
		peer, port, ok := strings.CutLast(f[len(f)-1], ":")
		if ok && port == "4222" {
			for _, name := range Controllers {
				if l.Addresses[name] == strings.Trim(peer, "[]") {
					connected[name] = true
				}
			}
		}
	}
	if len(connected) != 1 {
		return "", fmt.Errorf("expected one established host NATS controller socket, found %v", connected)
	}
	for n := range connected {
		return n, nil
	}
	panic("unreachable")
}
func (l *Lab) BlackholeHostController(controller string) (string, error) {
	table := "tsfc" + token(5)
	host, peer := l.Addresses["host"], l.Addresses[controller]
	if _, e := l.sudo("nft", "add", "table", "bridge", table); e != nil {
		if len(l.PendingCommands) > 0 || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			l.CreatedNFTTables = append(l.CreatedNFTTables, table)
		}
		return "", e
	}
	l.CreatedNFTTables = append(l.CreatedNFTTables, table)
	if _, e := l.sudo("nft", "add", "chain", "bridge", table, "forward", "{", "type", "filter", "hook", "forward", "priority", "-300", ";", "policy", "accept", ";", "}"); e != nil {
		return "", e
	}
	for _, rule := range [][3]string{{host, peer, "dport"}, {peer, host, "sport"}} {
		if _, e := l.sudo("nft", "add", "rule", "bridge", table, "forward", "ether", "type", "ip", "ip", "saddr", rule[0], "ip", "daddr", rule[1], "tcp", rule[2], "4222", "drop"); e != nil {
			return "", e
		}
	}
	l.Note("host_controller_blackhole", Object{"table": table, "host_ip": host, "controller": controller, "controller_ip": peer, "port": 4222})
	return table, nil
}
func (l *Lab) RemoveBlackhole(table string) error {
	if _, e := l.sudo("nft", "delete", "table", "bridge", table); e != nil {
		return e
	}
	l.CreatedNFTTables = slices.DeleteFunc(l.CreatedNFTTables, func(s string) bool { return s == table })
	l.Note("host_controller_blackhole_removed", Object{"table": table})
	return nil
}
func (l *Lab) Network() error {
	if _, e := l.sudo("ip", "link", "add", "name", l.Bridge, "type", "bridge"); e != nil {
		if len(l.PendingCommands) > 0 || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			l.CreatedLinks = append(l.CreatedLinks, l.Bridge)
		}
		return e
	}
	l.CreatedLinks = append(l.CreatedLinks, l.Bridge)
	if _, e := l.sudo("ip", "addr", "add", l.gateway()+"/24", "dev", l.Bridge); e != nil {
		return e
	}
	if _, e := l.sudo("ip", "link", "set", l.Bridge, "up"); e != nil {
		return e
	}
	for _, name := range Guests {
		tap := l.Taps[name]
		if _, e := l.sudo("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", strconv.Itoa(os.Getuid())); e != nil {
			if len(l.PendingCommands) > 0 || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				l.CreatedLinks = append(l.CreatedLinks, tap)
			}
			return e
		}
		l.CreatedLinks = append(l.CreatedLinks, tap)
		for _, args := range [][]string{{"ip", "link", "set", tap, "master", l.Bridge}, {"ip", "link", "set", tap, "up"}} {
			if _, e := l.sudo(args...); e != nil {
				return e
			}
		}
	}
	l.Note("network", Object{"bridge": l.Bridge, "subnet": l.Subnet.String(), "taps": l.Taps})
	return nil
}
func (l *Lab) gateway() string { return l.Subnet.Addr().Next().String() }
func (l *Lab) inputFirewallRules() ([]Object, error) {
	r, e := l.sudo("nft", "-j", "-a", "list", "chain", "ip", "filter", "INPUT")
	if e != nil {
		return nil, e
	}
	v, e := decode(r.Stdout)
	if e != nil {
		return nil, e
	}
	chains := []Object{}
	rules := []Object{}
	for _, entry := range array(object(v)["nftables"]) {
		entry := object(entry)
		if c, ok := entry["chain"]; ok {
			chains = append(chains, object(c))
		}
		if r, ok := entry["rule"]; ok {
			rules = append(rules, object(r))
		}
	}
	if len(chains) != 1 || chains[0]["family"] != "ip" || chains[0]["table"] != "filter" || chains[0]["name"] != "INPUT" || chains[0]["type"] != "filter" || chains[0]["hook"] != "input" {
		return nil, errors.New("host IPv4 filter INPUT is not the active input hook")
	}
	return rules, nil
}
func (l *Lab) ownedNTPRules() ([]Object, error) {
	if l.NTPRuleComment == "" {
		return []Object{}, nil
	}
	rules, e := l.inputFirewallRules()
	if e != nil {
		return nil, e
	}
	return slices.DeleteFunc(rules, func(r Object) bool {
		return r["family"] != "ip" || r["table"] != "filter" || r["chain"] != "INPUT" || r["comment"] != l.NTPRuleComment
	}), nil
}
func jsonEqual(a, b any) bool {
	x, e := json.Marshal(a, json.Deterministic(true))
	if e != nil {
		return false
	}
	y, e := json.Marshal(b, json.Deterministic(true))
	return e == nil && string(x) == string(y)
}
func (l *Lab) ExactNTPRule(rule Object) bool {
	expected := [][2]any{{Object{"meta": Object{"key": "iifname"}}, l.Bridge}, {Object{"payload": Object{"protocol": "ip", "field": "saddr"}}, Object{"prefix": Object{"addr": l.Subnet.Addr().String(), "len": 24}}}, {Object{"payload": Object{"protocol": "ip", "field": "daddr"}}, l.gateway()}, {Object{"payload": Object{"protocol": "udp", "field": "dport"}}, 123}}
	expr := array(rule["expr"])
	if len(expr) != 6 {
		return false
	}
	for i, w := range expected {
		m := object(object(expr[i])["match"])
		if m["op"] != "==" || !jsonEqual(m["left"], w[0]) || !jsonEqual(m["right"], w[1]) {
			return false
		}
	}
	counter, accept := object(expr[4]), object(expr[5])
	_, hasCounter := counter["counter"]
	_, hasAccept := accept["accept"]
	return len(counter) == 1 && len(accept) == 1 && hasCounter && hasAccept
}
func (l *Lab) InstallNTPFirewallRule() error {
	if l.NTPRuleComment != "" {
		return errors.New("private NTP firewall rule was already attempted")
	}
	if !regexp.MustCompile(`^tsf[0-9a-f]{6}b$`).MatchString(l.Bridge) || l.Subnet.Bits() != 24 || !netip.MustParsePrefix("198.19.0.0/16").Contains(l.Subnet.Addr()) {
		return errors.New("private NTP firewall rule requires the owned bridge and /24")
	}
	rules, e := l.inputFirewallRules()
	if e != nil {
		return e
	}
	jump := false
	for _, r := range rules {
		for _, expr := range array(r["expr"]) {
			if object(object(expr)["jump"])["target"] == "nixos-fw" {
				jump = true
			}
		}
	}
	if !jump {
		return errors.New("host INPUT does not route through the expected NixOS firewall")
	}
	l.NTPRuleComment = "ts-orch-fc-ntp-" + token(12)
	if _, e = l.sudo("nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", l.Bridge, "ip", "saddr", l.Subnet.String(), "ip", "daddr", l.gateway(), "udp", "dport", "123", "counter", "accept", "comment", l.NTPRuleComment); e != nil {
		return e
	}
	owned, e := l.ownedNTPRules()
	if e != nil {
		return e
	}
	if len(owned) != 1 || !l.ExactNTPRule(owned[0]) || integer(owned[0]["handle"]) < 1 {
		return errors.New("cannot identify the private NTP firewall rule after insertion")
	}
	l.NTPRuleHandle = integer(owned[0]["handle"])
	l.Note("ntp_firewall_rule", Object{"bridge": l.Bridge, "source": l.Subnet.String(), "destination": l.gateway(), "protocol": "udp", "port": 123, "comment": l.NTPRuleComment, "handle": l.NTPRuleHandle})
	return nil
}
func (l *Lab) RemoveNTPFirewallRule() error {
	if l.NTPRuleComment == "" {
		return nil
	}
	owned, e := l.ownedNTPRules()
	if e != nil {
		return e
	}
	if len(owned) > 1 {
		return errors.New("private NTP firewall comment matched multiple rules")
	}
	if len(owned) == 0 {
		l.NTPRuleComment = ""
		l.NTPRuleHandle = 0
		return nil
	}
	if !l.ExactNTPRule(owned[0]) {
		return errors.New("private NTP firewall rule scope changed")
	}
	handle := integer(owned[0]["handle"])
	if handle < 1 || (l.NTPRuleHandle != 0 && handle != l.NTPRuleHandle) {
		return errors.New("private NTP firewall handle changed")
	}
	if _, e = l.sudo("nft", "delete", "rule", "ip", "filter", "INPUT", "handle", strconv.FormatInt(handle, 10)); e != nil {
		return e
	}
	owned, e = l.ownedNTPRules()
	if e != nil {
		return e
	}
	if len(owned) > 0 {
		return errors.New("private NTP firewall rule remains after deletion")
	}
	l.Note("ntp_firewall_rule_removed", Object{"comment": l.NTPRuleComment, "handle": handle})
	l.NTPRuleComment = ""
	l.NTPRuleHandle = 0
	return nil
}
func (l *Lab) ChronySocketPath() (string, error) {
	r, e := l.sudo("mktemp", "-d", "-p", "/run", "ts-orch-fc-chrony.XXXXXXXX")
	if e != nil {
		return "", e
	}
	d := strings.TrimSpace(r.Stdout)
	if filepath.Dir(d) != "/run" || !regexp.MustCompile(`^ts-orch-fc-chrony\.[A-Za-z0-9]{8}$`).MatchString(filepath.Base(d)) {
		return "", errors.New("invalid private Chrony control directory")
	}
	l.ChronyControlDir = d
	s, e := l.lstat(d)
	if e != nil {
		return "", e
	}
	owner, ok := s.Sys().(*syscall.Stat_t)
	if !s.IsDir() || s.Mode().Perm() != 0o700 || !ok || owner.Uid != 0 {
		return "", errors.New("private Chrony control directory must be root-owned mode 0700")
	}
	return filepath.Join(d, "chronyd.sock"), nil
}
func (l *Lab) StartChrony() error {
	socket, e := l.ChronySocketPath()
	if e != nil {
		return e
	}
	config := filepath.Join(l.Stage, "chrony.conf")
	text := "pool 2.nixos.pool.ntp.org iburst maxsources 4\nbindaddress " + l.gateway() + "\nallow " + l.Subnet.String() + "\nport 123\nbindcmdaddress " + socket + "\ncmdport 0\npidfile " + filepath.Join(l.Root, "chronyd.pid") + "\ndriftfile " + filepath.Join(l.Root, "chronyd.drift") + "\n"
	if e = os.WriteFile(config, []byte(text), 0o600); e != nil {
		return e
	}
	if _, e = l.cmd([]string{Chronyd, "-p", "-f", config}, CommandOptions{}); e != nil {
		return e
	}
	log, e := os.OpenFile(filepath.Join(l.Logs, "chronyd.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if e != nil {
		return e
	}
	l.ChronyProcess, e = l.startProcess([]string{"sudo", "-n", Chronyd, "-x", "-d", "-4", "-f", config}, l.Options.SourceRoot, log)
	if e != nil {
		log.Close()
		return e
	}
	l.ChronyProcess.Output = log
	_, e = l.Wait("private-chrony-upstream-and-listener", func() (any, error) {
		exited, e := l.ChronyProcess.Exited()
		if e != nil {
			return nil, e
		}
		if exited {
			return nil, errors.New("private chronyd exited")
		}
		r, e := l.cmd([]string{"sudo", "-n", Chronyc, "-n", "-h", socket, "sources"}, CommandOptions{Timeout: 10 * time.Second, AllowFailure: true})
		if e != nil {
			return nil, e
		}
		selected := false
		for line := range strings.SplitSeq(r.Stdout, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "^*") {
				selected = true
			}
		}
		if r.Code != 0 || !selected {
			return false, nil
		}
		r, e = l.cmd([]string{"sudo", "-n", "ss", "-H", "-lun"}, CommandOptions{Timeout: 10 * time.Second})
		return strings.Contains(r.Stdout, l.gateway()+":123"), e
	}, l.Now().Add(150*time.Second), 2*time.Second)
	if e != nil {
		return e
	}
	h, _ := Digest(Chronyd)
	l.Note("chrony_ready", Object{"pid": l.ChronyProcess.PID(), "upstream": "selected_remote", "bind_address": l.gateway(), "chronyd_sha256": h})
	return nil
}
func ClockMeasurement(before, after, startOuter, startInner, endInner, endOuter, guest int64) (int64, int64, error) {
	if !(startOuter <= startInner && startInner <= endInner && endInner <= endOuter) {
		return 0, 0, errors.New("lab host monotonic clock changed during guest clock measurement")
	}
	lower, upper, real := endInner-startInner, endOuter-startOuter, after-before
	allowance := max(int64(1_000_000), upper/1000)
	if real < 0 || real < lower-allowance || real > upper+allowance {
		return 0, 0, errors.New("lab host clock changed during guest clock measurement")
	}
	return guest - (before+after)/2, upper/2 + allowance, nil
}
func (l *Lab) MeasureGuestClock(name string) (int64, int64, error) {
	l.defaults()
	if l.measureClock != nil {
		return l.measureClock(name)
	}
	outer := l.MonotonicNS()
	before := l.Now().UnixNano()
	inner := l.MonotonicNS()
	r, e := l.SSH(name, "date +%s%N", 10*time.Second, false)
	if e != nil {
		return 0, 0, e
	}
	endInner := l.MonotonicNS()
	after := l.Now().UnixNano()
	endOuter := l.MonotonicNS()
	guest, e := strconv.ParseInt(strings.TrimSpace(r.Stdout), 10, 64)
	if e != nil {
		return 0, 0, e
	}
	offset, uncertainty, e := ClockMeasurement(before, after, outer, inner, endInner, endOuter, guest)
	if e != nil {
		return 0, 0, e
	}
	l.GuestClockUpperNS[name] = offset + uncertainty
	l.Note("guest_clock", Object{"name": name, "offset_ns": offset, "uncertainty_ns": uncertainty})
	return offset, uncertainty, nil
}
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
func (l *Lab) WaitSynchronizedGuestClock(name string) error {
	_, e := l.Wait("ntp-clock-"+name, func() (any, error) {
		r, e := l.SSH(name, "systemctl is-active --quiet systemd-timesyncd.service && test \"$(timedatectl show -p NTPSynchronized --value)\" = yes && /usr/local/bin/ts-orch-clockprobe", 10*time.Second, true)
		if e != nil {
			return nil, e
		}
		v, e := decode(strings.TrimSpace(r.Stdout))
		if e != nil || r.Code != 0 || object(v)["healthy"] != true {
			return false, nil
		}
		fields := object(v)
		fields["name"] = name
		l.Note("guest_kernel_clock", fields)
		return true, nil
	}, l.Now().Add(180*time.Second), 2*time.Second)
	if e == nil {
		offset, uncertainty, measureErr := l.MeasureGuestClock(name)
		e = measureErr
		if e == nil && abs(offset)+uncertainty > ClockBoundNS {
			e = fmt.Errorf("%s NTP clock differs from lab host by over one second", name)
		}
	}
	if e != nil {
		l.CaptureClockDiagnostics(name)
	}
	return e
}
func (l *Lab) ReleaseSynchronizedGuestClock(name string) error {
	r, e := l.SSH(name, "test ! -e "+ClockReady+" && test \"$(systemctl show -p MainPID --value ts-orch.service)\" = 0", 10*time.Second, true)
	if e != nil {
		return e
	}
	if r.Code != 0 {
		return fmt.Errorf("%s service began before NTP clock readiness", name)
	}
	if e = l.WaitSynchronizedGuestClock(name); e != nil {
		return e
	}
	offset, uncertainty, e := l.MeasureGuestClock(name)
	if e != nil {
		return e
	}
	if _, e = l.SSH(name, "/usr/bin/install -m 0600 /dev/null "+ClockReady, 10*time.Second, false); e != nil {
		return e
	}
	l.Note("guest_clock_released", Object{"name": name, "offset_ns": offset, "uncertainty_ns": uncertainty})
	return nil
}
func (l *Lab) CheckGuestClocks() error {
	for _, name := range Guests {
		offset, u, e := l.MeasureGuestClock(name)
		if e != nil {
			return e
		}
		if abs(offset)+u > ClockBoundNS {
			return fmt.Errorf("%s clock differs from lab host by over one second", name)
		}
	}
	return nil
}
func (l *Lab) WaitSSH(name string) error {
	_, e := l.Wait("ssh-"+name, func() (any, error) { r, e := l.SSH(name, "true", 15*time.Second, true); return r.Code == 0, e }, l.Now().Add(150*time.Second), 2*time.Second)
	if e != nil {
		return e
	}
	if e = l.ReleaseSynchronizedGuestClock(name); e != nil {
		return e
	}
	_, e = l.Wait("service-"+name, func() (any, error) {
		r, e := l.SSH(name, "systemctl is-active ts-orch.service", 15*time.Second, true)
		return r.Code == 0, e
	}, l.Now().Add(150*time.Second), 2*time.Second)
	return e
}
func (l *Lab) WaitCluster() error {
	_, e := l.Wait("jetstream-quorum", func() (any, error) {
		r, e := l.cmd([]string{l.Binary, "check", "--config", l.OperatorConfig}, CommandOptions{Timeout: 20 * time.Second, AllowFailure: true})
		return r.Code == 0, e
	}, l.Now().Add(100*time.Second), 2*time.Second)
	return e
}
func (l *Lab) WaitHost(version string) error {
	_, e := l.Wait("host-session-"+version, func() (any, error) {
		v, e := l.Operator("hosts", 35*time.Second, false, "")
		if e != nil {
			return nil, e
		}
		rows := array(v)
		if len(rows) != 1 || str(object(rows[0])["session_expires_at"]) == "" {
			return false, nil
		}
		if version == "" {
			return true, nil
		}
		running := false
		for _, r := range array(object(rows[0])["reports"]) {
			r := object(r)
			if r["role"] == "terrabase" && r["state"] == "failed" {
				l.CaptureFailureDiagnostics()
			}
			if r["role"] == "terrabase" && r["state"] == "running" {
				running = true
			}
		}
		if !running {
			return false, nil
		}
		o, e := l.NativeObservation(15 * time.Second)
		if e != nil {
			return nil, e
		}
		if o["marker"] != version || o["workload_alive"] != true || str(o["workload_cgroup"]) == "" {
			return false, nil
		}
		empty, e := l.CgroupEmpty(str(o["workload_cgroup"]), str(o["service_cgroup"]))
		return !empty, e
	}, l.Now().Add(150*time.Second), 2*time.Second)
	return e
}
func parseSlog(message, event string, required []string) map[string]string {
	prefix := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) INFO ` + regexp.QuoteMeta(event) + `(?: (.*))?$`).FindStringSubmatch(message)
	if prefix == nil {
		return nil
	}
	if _, e := time.Parse("2006/01/02 15:04:05", prefix[1]); e != nil {
		return nil
	}
	parts, e := shellFields(prefix[2])
	if e != nil {
		return nil
	}
	fields := map[string]string{}
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil
		}
		if _, ok = fields[k]; ok {
			return nil
		}
		fields[k] = v
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return nil
		}
	}
	return fields
}
func shellFields(s string) ([]string, error) {
	parts := []string{}
	var b strings.Builder
	quoteChar := rune(0)
	escaped := false
	active := false
	for _, c := range s {
		if escaped {
			b.WriteRune(c)
			escaped = false
			active = true
			continue
		}
		if c == '\\' && quoteChar != '\'' {
			escaped = true
			continue
		}
		if quoteChar != 0 {
			if c == quoteChar {
				quoteChar = 0
			} else {
				b.WriteRune(c)
			}
			active = true
			continue
		}
		if c == '\'' || c == '"' {
			quoteChar = c
			active = true
			continue
		}
		if c == ' ' || c == '\t' {
			if active {
				parts = append(parts, b.String())
				b.Reset()
				active = false
			}
			continue
		}
		active = true
		b.WriteRune(c)
	}
	if quoteChar != 0 || escaped {
		return nil, errors.New("malformed shell attributes")
	}
	if active {
		parts = append(parts, b.String())
	}
	return parts, nil
}

type LeaseEvent struct {
	At, ExpiresAt      time.Time
	SessionHash, Phase string
	Epoch              int64
}

func ParseLeaseEvents(output string, since time.Time) []LeaseEvent {
	events := []LeaseEvent{}
	for line := range strings.SplitSeq(output, "\n") {
		v, e := decode(line)
		if e != nil {
			continue
		}
		entry := object(v)
		f := parseSlog(str(entry["MESSAGE"]), "host session accepted", []string{"phase", "session_id_hash", "epoch", "expires_at"})
		if f == nil {
			continue
		}
		micro, e := strconv.ParseInt(str(entry["__REALTIME_TIMESTAMP"]), 10, 64)
		if e != nil {
			continue
		}
		at := time.UnixMicro(micro)
		expiry, e := time.Parse(time.RFC3339Nano, f["expires_at"])
		if e != nil {
			continue
		}
		epoch, e := strconv.ParseInt(f["epoch"], 10, 64)
		if e != nil || epoch <= 0 || at.Before(since) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(f["session_id_hash"]) {
			continue
		}
		events = append(events, LeaseEvent{at, expiry, f["session_id_hash"], f["phase"], epoch})
	}
	return events
}
func (l *Lab) VerifiedLeaseEvents(since time.Time, timeout time.Duration) ([]LeaseEvent, error) {
	r, e := l.SSH("host", "journalctl -u ts-orch.service --since "+quote("@"+strconv.FormatInt(since.Unix(), 10))+" -n 500 -o json --no-pager", timeout, false)
	if e != nil {
		return nil, e
	}
	return ParseLeaseEvents(r.Stdout, since), nil
}
func (l *Lab) HostRenewalFailureEvidence(since time.Time, hash string, epoch int64, expiry time.Time) error {
	r, e := l.SSH("host", "journalctl -u ts-orch.service --since "+quote("@"+strconv.FormatInt(since.Unix(), 10))+" -n 500 -o json --no-pager", 15*time.Second, true)
	if e != nil {
		return e
	}
	if r.Code != 0 {
		return errors.New("host renewal journal query failed")
	}
	var failed, complete, fenced time.Time
	cause := ""
	for line := range strings.SplitSeq(r.Stdout, "\n") {
		v, e := decode(line)
		if e != nil {
			continue
		}
		entry := object(v)
		micro, e := strconv.ParseInt(str(entry["__REALTIME_TIMESTAMP"]), 10, 64)
		if e != nil {
			continue
		}
		instant := time.UnixMicro(micro)
		message := str(entry["MESSAGE"])
		if strings.Contains(message, "host session exchange deferred") && failed.IsZero() {
			failed = instant
		}
		if strings.Contains(message, "host session execution reserve exhausted") && complete.IsZero() {
			complete = instant
		}
		fields := parseSlog(message, "host session fenced", []string{"session_id_hash", "epoch", "expires_at"})
		if fields == nil {
			continue
		}
		ep, _ := strconv.ParseInt(fields["epoch"], 10, 64)
		ex, _ := time.Parse(time.RFC3339Nano, fields["expires_at"])
		if fields["session_id_hash"] == hash && ep == epoch && ex.Equal(expiry) {
			fenced = instant
			cause = fields["cause_class"]
		}
	}
	l.Note("host_renewal_failure_timing", Object{"first_failed_exchange_at": failed, "actual_fence_started_at": fenced, "fence_cause_class": cause, "agent_failure_reported_at": complete, "journal_clock": "guest_realtime", "since": since})
	if failed.IsZero() {
		return errors.New("host logged no failed session renewal after quorum loss")
	}
	if fenced.IsZero() {
		return errors.New("host did not record a matching fence for the native workload")
	}
	if fenced.After(expiry.Add(-3750 * time.Millisecond)) {
		return errors.New("host began fencing too late for its one-second reserve ticker")
	}
	return nil
}
func sameNative(a, b Object) bool {
	start := func(s string) string { _, x, _ := strings.CutLast(s, ":"); return x }
	return a["agent_pid"] == b["agent_pid"] && start(str(a["agent_state"])) == start(str(b["agent_state"])) && a["invocation"] == b["invocation"] && a["workload_pid"] == b["workload_pid"] && start(str(a["workload_state"])) == start(str(b["workload_state"])) && a["workload_alive"] == true
}
func (l *Lab) WaitSameProcessRenewal(firstSession, firstNative Object, connected string, fault time.Time) error {
	deadline := l.Now().Add(25 * time.Second)
	remaining := func(cap time.Duration) time.Duration { return min(cap, max(0, deadline.Sub(l.Now()))) }
	_, e := l.Wait("same-process-host-session-renewal", func() (any, error) {
		timeout := remaining(5 * time.Second)
		if timeout <= 0 {
			return false, nil
		}
		session, e := l.HostSession("v1", timeout, "same-process-host-session-renewal")
		if e != nil {
			return nil, e
		}
		timeout = remaining(15 * time.Second)
		if timeout <= 0 {
			return false, nil
		}
		o, e := l.NativeObservation(timeout)
		if e != nil {
			return nil, e
		}
		if session["session_id"] != firstSession["session_id"] || !sameNative(o, firstNative) || o["marker"] != "v1" {
			return nil, errors.New("host agent, signed session or native workload restarted during 2/3 renewal")
		}
		expiry := session["expires_at"].(time.Time)
		if !expiry.After(firstSession["expires_at"].(time.Time)) {
			return false, nil
		}
		timeout = remaining(15 * time.Second)
		if timeout <= 0 {
			return false, nil
		}
		hash := head(hashBytes([]byte(str(session["session_id"]))), 32)
		events, e := l.VerifiedLeaseEvents(fault, timeout)
		if e != nil {
			return nil, e
		}
		matching := slices.DeleteFunc(events, func(event LeaseEvent) bool {
			return event.Phase != "renew" || event.SessionHash != hash || event.Epoch != integer(object(session["report"])["epoch"]) || !event.ExpiresAt.Equal(expiry)
		})
		if len(matching) == 0 || !l.Now().Before(deadline) {
			return false, nil
		}
		l.Note("host_session_renewed_on_surviving_quorum", Object{"connected_controller": connected, "session_id_hash": hash, "signed_renewal_at": matching[len(matching)-1].At, "previous_expiry": firstSession["expires_at"], "renewed_expiry": expiry, "native": o})
		return true, nil
	}, deadline, 500*time.Millisecond)
	if e != nil {
		events, de := l.VerifiedLeaseEvents(fault, 5*time.Second)
		if de != nil {
			l.Note("host_renewal_timeout_diagnostics", Object{"status": "unavailable", "error_type": fmt.Sprintf("%T", de)})
		} else {
			renewals := []Object{}
			for _, event := range events {
				if event.Phase == "renew" {
					renewals = append(renewals, Object{"accepted_at": event.At, "expires_at": event.ExpiresAt, "session_id_hash": event.SessionHash, "epoch": event.Epoch})
				}
			}
			l.Note("host_renewal_timeout_diagnostics", Object{"status": "ok", "renewals": renewals})
		}
	}
	return e
}
func (l *Lab) VerifyBrokerClockGate() error {
	command := []string{l.NATSDiag, "--creds", filepath.Join(l.Secrets, "c1.creds"), "--cell", "lab", "--urls", "tls://" + l.Addresses["c1"] + ":4222", "--ca", filepath.Join(l.Secrets, "nats-ca.pem"), "--cert", filepath.Join(l.Secrets, "nats-c1.pem"), "--key", filepath.Join(l.Secrets, "nats-c1.key")}
	logPath := filepath.Join(l.Logs, "c1-clock-gate-session.jsonl")
	log, e := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if e != nil {
		return e
	}
	l.SessionProbeProcess, e = l.startProcess(append(slices.Clone(command), "--session-probe", "hold"), l.Options.SourceRoot, log)
	if e != nil {
		log.Close()
		return e
	}
	l.SessionProbeProcess.Output = log
	state := func(expected string) (any, error) {
		b, e := os.ReadFile(logPath)
		if e != nil {
			return nil, e
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			v, e := decode(line)
			if e == nil && object(v)["state"] == expected {
				return true, nil
			}
		}
		done, e := l.SessionProbeProcess.Exited()
		if done {
			return nil, fmt.Errorf("pinned c1 session exited before %s", expected)
		}
		return false, e
	}
	if _, e = l.Wait("c1-authenticated-session", func() (any, error) { return state("ready") }, l.Now().Add(20*time.Second), 100*time.Millisecond); e != nil {
		return e
	}
	started := l.Now()
	deadline := started.Add(20 * time.Second)
	remaining := func(cap time.Duration) (time.Duration, error) {
		v := deadline.Sub(l.Now())
		if v <= 0 {
			return 0, errors.New("c1 session closure exceeded the 20-second fault budget")
		}
		return min(cap, v), nil
	}
	timeout, e := remaining(12 * time.Second)
	if e != nil {
		return e
	}
	if _, e = l.SSH("c1", `systemctl stop systemd-timesyncd.service && date -u --set="$(date -u -d '+90 seconds' '+%Y-%m-%d %H:%M:%S')" >/dev/null`, timeout, false); e != nil {
		return e
	}
	timeout, e = remaining(10 * time.Second)
	if e != nil {
		return e
	}
	r, e := l.SSH("c1", "/usr/local/bin/ts-orch-clockprobe", timeout, true)
	if e != nil {
		return e
	}
	v, e := decode(strings.TrimSpace(r.Stdout))
	if e != nil {
		return e
	}
	if r.Code == 0 || object(v)["healthy"] != false {
		return errors.New("c1 clock jump did not make the production kernel predicate unhealthy")
	}
	fields := object(v)
	fields["name"] = "c1"
	l.Note("broker_clock_unhealthy", fields)
	if _, e = remaining(20 * time.Second); e != nil {
		return e
	}
	if _, e = l.Wait("c1-session-closed", func() (any, error) { return state("closed") }, deadline, 100*time.Millisecond); e != nil {
		return e
	}
	elapsed := l.Now().Sub(started)
	if elapsed > 20*time.Second {
		return errors.New("c1 session closure exceeded polling and ticket bound")
	}
	r, e = l.cmd(append(slices.Clone(command), "--session-probe", "once"), CommandOptions{Timeout: 8 * time.Second, AllowFailure: true})
	if e != nil {
		return e
	}
	if r.Code == 0 || strings.Contains(r.Stdout, `"state":"ready"`) {
		return errors.New("c1 broker admitted a new authenticated session while clock was unhealthy")
	}
	l.Note("broker_clock_fenced", Object{"name": "c1", "closure_elapsed_seconds": elapsed.Seconds(), "new_admission_exit_code": r.Code})
	if _, e = l.SSH("c1", "systemctl start systemd-timesyncd.service", 12*time.Second, false); e != nil {
		return e
	}
	if e = l.WaitSynchronizedGuestClock("c1"); e != nil {
		return e
	}
	_, e = l.Wait("c1-readmitted-after-ntp", func() (any, error) {
		r, e := l.cmd(append(slices.Clone(command), "--session-probe", "once"), CommandOptions{Timeout: 8 * time.Second, AllowFailure: true})
		return r.Code == 0, e
	}, l.Now().Add(75*time.Second), 2*time.Second)
	if e == nil {
		l.Note("broker_clock_recovered", Object{"name": "c1"})
	}
	return e
}

var _ = context.DeadlineExceeded
