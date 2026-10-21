package firecracker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"encoding/json/v2"
)

const (
	KernelSHA                 = "586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523"
	RootfsSHA                 = "a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6"
	PreAcceptanceFenced       = "authority epoch was fenced before acceptance"
	ClockReady                = "/run/ts-orch-clock-ready"
	ClockBoundNS        int64 = 1_000_000_000
	Chronyd                   = "/nix/store/zinbanwvmabvr9lk7x5qaac0al3v18ml-chrony-4.8/bin/chronyd"
	Chronyc                   = "/nix/store/zinbanwvmabvr9lk7x5qaac0al3v18ml-chrony-4.8/bin/chronyc"
	ChronydSHA                = "bcfa87ddfc6b61c079ed764b541c82de7e1f279c56ad50b6757c679d6c3b05dd"
	ChronycSHA                = "10fbfd50c1efe52f56e2a1f1643ab8855b41a6954b5f93242bba1404d8fc7875"
)

var Controllers = []string{"c1", "c2", "c3"}
var Guests = []string{"c1", "c2", "c3", "host"}
var ConfigDigest = hashBytes([]byte(`{"args":[],"env":{}}`))

type GenericOptions struct{ Kernel, Rootfs, Firecracker, RunDir, SourceRoot string }
type Lab struct {
	Ctx                                                                                                                                                 context.Context
	Options                                                                                                                                             GenericOptions
	Command                                                                                                                                             CommandFunc
	Stdout                                                                                                                                              io.Writer
	Root, Logs, Secrets, Images, Stage, SocketDir, Bridge, SSHKey, KnownHosts, Binary, NATSDiag, JWTSetup, ClockProbe, OperatorConfig, ChronyControlDir string
	Subnet                                                                                                                                              netip.Prefix
	Addresses, Taps, SigningPublic                                                                                                                      map[string]string
	Source, JWTManifest                                                                                                                                 Object
	CreatedLinks, CreatedNFTTables, Mounted                                                                                                             []string
	NTPRuleComment                                                                                                                                      string
	NTPRuleHandle                                                                                                                                       int64
	VMs                                                                                                                                                 map[string]*VM
	ChronyProcess, SessionProbeProcess                                                                                                                  *Process
	PendingCommands                                                                                                                                     []*Process
	NativeExecutable                                                                                                                                    NativeProvenance
	Events                                                                                                                                              []Object
	GuestClockUpperNS                                                                                                                                   map[string]int64
	GoSourceSHA, HarnessSHA, ActiveOperationID, SSHPublic                                                                                               string
	HostDiagnostics, ClockDiagnostics                                                                                                                   map[string]bool
	ClockHostDiagnostics                                                                                                                                Object
	ClusterCaptured, FailureCaptured                                                                                                                    bool
	Now                                                                                                                                                 func() time.Time
	MonotonicNS                                                                                                                                         func() int64
	Sleep                                                                                                                                               func(time.Duration)
	startProcess                                                                                                                                        func([]string, string, io.Writer) (*Process, error)
	lstat                                                                                                                                               func(string) (os.FileInfo, error)
	wait                                                                                                                                                func(string, func() (any, error), time.Time, time.Duration) (any, error)
	measureClock                                                                                                                                        func(string) (int64, int64, error)
}

func (l *Lab) defaults() {
	if l.Ctx == nil {
		l.Ctx = context.Background()
	}
	if l.Command == nil {
		l.Command = Execute
	}
	if l.Stdout == nil {
		l.Stdout = io.Discard
	}
	if l.Now == nil {
		l.Now = time.Now
	}
	if l.MonotonicNS == nil {
		base := time.Now()
		l.MonotonicNS = func() int64 { return time.Since(base).Nanoseconds() }
	}
	if l.Sleep == nil {
		l.Sleep = time.Sleep
	}
	if l.startProcess == nil {
		l.startProcess = Start
	}
	if l.lstat == nil {
		l.lstat = os.Lstat
	}
	if l.HostDiagnostics == nil {
		l.HostDiagnostics = map[string]bool{}
	}
	if l.ClockDiagnostics == nil {
		l.ClockDiagnostics = map[string]bool{}
	}
	if l.GuestClockUpperNS == nil {
		l.GuestClockUpperNS = map[string]int64{}
	}
}
func NewLab(ctx context.Context, o GenericOptions, out io.Writer) (*Lab, error) {
	l := &Lab{Ctx: ctx, Options: o, Stdout: out, Addresses: map[string]string{}, Taps: map[string]string{}, SigningPublic: map[string]string{}, VMs: map[string]*VM{}, Source: Object{"repository": "https://example.com/terrascale/firecracker-fixtures", "commit": strings.Repeat("f", 40), "treeDigest": ""}}
	l.defaults()
	var e error
	if o.RunDir != "" {
		l.Root, e = filepath.Abs(o.RunDir)
		if e == nil {
			e = os.MkdirAll(filepath.Dir(l.Root), 0o700)
		}
		if e == nil {
			e = os.Mkdir(l.Root, 0o700)
		}
	} else {
		l.Root, e = os.MkdirTemp("/tmp", "ts-orch-fc-")
	}
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(l.Root, 0o700); e != nil {
		return nil, e
	}
	l.Logs = filepath.Join(l.Root, "logs")
	l.Secrets = filepath.Join(l.Root, "secrets")
	l.Images = filepath.Join(l.Root, "images")
	l.Stage = filepath.Join(l.Root, "stage")
	for _, d := range []string{l.Logs, l.Secrets, l.Images, l.Stage} {
		if e = os.Mkdir(d, 0o700); e != nil {
			return nil, e
		}
	}
	l.Bridge = "tsf" + token(3) + "b"
	octet, e := l.ChooseSubnet()
	if e != nil {
		return nil, e
	}
	l.Subnet = netip.MustParsePrefix(fmt.Sprintf("198.19.%d.0/24", octet))
	for i, name := range Guests {
		l.Taps[name] = fmt.Sprintf("tsf%s%d", l.Bridge[3:9], i+1)
		l.Addresses[name] = fmt.Sprintf("198.19.%d.%d", octet, i+11)
	}
	l.Binary = filepath.Join(l.Root, "terrascale-orchestrator")
	l.NATSDiag = filepath.Join(l.Root, "natsdiag")
	l.JWTSetup = filepath.Join(l.Root, "jwtsetup")
	l.ClockProbe = filepath.Join(l.Root, "clockprobe")
	l.SSHKey = filepath.Join(l.Secrets, "lab_ssh")
	l.KnownHosts = filepath.Join(l.Secrets, "known_hosts")
	l.OperatorConfig = filepath.Join(l.Secrets, "operator.json")
	l.SocketDir, e = PrivateSocketDirectory()
	return l, e
}
func (l *Lab) cmd(argv []string, o CommandOptions) (CommandResult, error) {
	l.defaults()
	if o.Dir == "" {
		o.Dir = l.Options.SourceRoot
	}
	r, e := l.Command(l.Ctx, argv, o)
	if pending, ok := errors.AsType[*PendingCommandError](e); ok && !slices.Contains(l.PendingCommands, pending.Process) {
		l.PendingCommands = append(l.PendingCommands, pending.Process)
	}
	return r, e
}
func (l *Lab) sudo(args ...string) (CommandResult, error) {
	return l.cmd(append([]string{"sudo", "-n"}, args...), CommandOptions{})
}
func (l *Lab) sudoAllow(args ...string) (CommandResult, error) {
	return l.cmd(append([]string{"sudo", "-n"}, args...), CommandOptions{AllowFailure: true})
}
func (l *Lab) Note(event string, fields Object) {
	l.defaults()
	entry := Object{"time": l.Now().UTC().Format(time.RFC3339), "event": event}
	for k, v := range fields {
		entry[k] = v
	}
	l.Events = append(l.Events, entry)
	_ = writeJSON(filepath.Join(l.Logs, "events.json"), l.Events)
	b, _ := json.Marshal(entry)
	fmt.Fprintln(l.Stdout, string(b))
}
func (l *Lab) ChooseSubnet() (int, error) {
	r, e := l.cmd([]string{"ip", "-j", "route", "show", "table", "all"}, CommandOptions{})
	if e != nil {
		return 0, e
	}
	v, e := decode(r.Stdout)
	if e != nil {
		return 0, e
	}
	used := []netip.Prefix{}
	for _, row := range array(v) {
		s := str(object(row)["dst"])
		p, e := netip.ParsePrefix(s)
		if e == nil {
			used = append(used, p)
		}
	}
	for range 256 {
		b := token(1)
		n, _ := strconv.ParseInt(b, 16, 16)
		candidate := netip.MustParsePrefix(fmt.Sprintf("198.19.%d.0/24", n))
		if !slices.ContainsFunc(used, func(p netip.Prefix) bool { return p.Overlaps(candidate) }) {
			return int(n), nil
		}
	}
	return 0, errors.New("no isolated 198.19.x.0/24 subnet is free")
}
func SourceDigest(root string) (string, error) {
	paths := []string{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".git" || p == filepath.Join(root, "docs") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if strings.HasSuffix(p, ".go") || p == filepath.Join(root, "go.mod") || p == filepath.Join(root, "go.sum") {
			paths = append(paths, p)
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	slices.Sort(paths)
	var b []byte
	for _, p := range paths {
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return "", e
		}
		h, e := Digest(p)
		if e != nil {
			return "", e
		}
		raw, _ := hexDecode(h)
		b = append(b, []byte(filepath.ToSlash(rel))...)
		b = append(b, 0)
		b = append(b, raw...)
	}
	return hashBytes(b), nil
}
func hexDecode(s string) ([]byte, error) {
	var b []byte
	for i := 0; i < len(s); i += 2 {
		n, e := strconv.ParseUint(s[i:i+2], 16, 8)
		if e != nil {
			return nil, e
		}
		b = append(b, byte(n))
	}
	return b, nil
}
func (l *Lab) HarnessDigest() (string, error) {
	names := []string{"go.mod", "go.sum", "tests/firecracker/natsdiag.go", "tests/firecracker/natsdiag_test.go", "tests/firecracker/jwtsetup/main.go", "tests/firecracker/clockprobe/main.go", "tests/firecracker/README.md"}
	e := filepath.WalkDir(filepath.Join(l.Options.SourceRoot, "internal/qualification/firecracker"), func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") {
			r, e := filepath.Rel(l.Options.SourceRoot, p)
			if e != nil {
				return e
			}
			names = append(names, filepath.ToSlash(r))
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	slices.Sort(names)
	b := []byte{}
	for _, n := range names {
		h, e := Digest(filepath.Join(l.Options.SourceRoot, n))
		if e != nil {
			return "", e
		}
		raw, _ := hexDecode(h)
		b = append(b, []byte(n)...)
		b = append(b, 0)
		b = append(b, raw...)
	}
	return hashBytes(b), nil
}
func (l *Lab) Build() error {
	provenance, e := CaptureNativeProvenance()
	if e != nil {
		return e
	}
	l.NativeExecutable = provenance
	l.Note("native_qualification", Object{"provenance": provenance})
	before, e := SourceDigest(l.Options.SourceRoot)
	if e != nil {
		return e
	}
	l.GoSourceSHA = before
	l.HarnessSHA, e = l.HarnessDigest()
	if e != nil {
		return e
	}
	revision, e := l.cmd([]string{"git", "rev-parse", "HEAD"}, CommandOptions{})
	if e != nil {
		return e
	}
	version, e := l.cmd([]string{"go", "version"}, CommandOptions{})
	if e != nil {
		return e
	}
	l.Note("source", Object{"revision": strings.TrimSpace(revision.Stdout), "manifest_sha256": before, "go": strings.TrimSpace(version.Stdout)})
	for _, build := range [][3]string{{"binary", l.Binary, "./cmd/terrascale-orchestrator"}, {"natsdiag", l.NATSDiag, "tests/firecracker/natsdiag.go"}, {"jwtsetup", l.JWTSetup, "tests/firecracker/jwtsetup/main.go"}, {"clockprobe", l.ClockProbe, "tests/firecracker/clockprobe/main.go"}} {
		env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		r, e := l.cmd([]string{"go", "build", "-trimpath", "-o", build[1], build[2]}, CommandOptions{Timeout: 600 * time.Second, AllowFailure: true, Env: env})
		_ = os.WriteFile(filepath.Join(l.Logs, build[0]+"-build.log"), []byte(r.Stdout+r.Stderr), 0o600)
		if e != nil {
			return e
		}
		if r.Code != 0 {
			return fmt.Errorf("%s Go build failed; see %s", build[0], l.Logs)
		}
		h, e := Digest(build[1])
		if e != nil {
			return e
		}
		l.Note(build[0]+"_binary", Object{"sha256": h})
	}
	after, e := SourceDigest(l.Options.SourceRoot)
	if e != nil {
		return e
	}
	h, e := l.HarnessDigest()
	if e != nil {
		return e
	}
	if before != after || h != l.HarnessSHA {
		return errors.New("source changed during build; rerun against a stable tree")
	}
	return nil
}
func GuestUnit(name, role string) string {
	host := ""
	if name == "host" {
		host = "NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP\nAmbientCapabilities=\nDelegate=yes\nDelegateSubgroup=supervisor\nExecStartPre=/usr/bin/install -d -o 2000 -g 2000 -m 0700 /run/ts-orch-workload\n"
	}
	return "[Unit]\nDescription=TerraScale Firecracker qualification " + name + "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n" + host + "TimeoutStartSec=180\nExecStartPre=/bin/sh -c 'while ! test -f " + ClockReady + "; do sleep 0.1; done'\nExecStart=/usr/local/bin/terrascale-orchestrator " + role + " --config /etc/ts-orch/config.json\nRestart=on-failure\nRestartSec=2\nStandardOutput=journal+console\nStandardError=journal+console\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (l *Lab) SSH(name, command string, timeout time.Duration, allow bool) (CommandResult, error) {
	return l.cmd([]string{"ssh", "-i", l.SSHKey, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=3", "-o", "UserKnownHostsFile=" + l.KnownHosts, "root@" + l.Addresses[name], "sh", "-lc", quote(command)}, CommandOptions{Timeout: timeout, AllowFailure: allow})
}
func (l *Lab) Wait(label string, probe func() (any, error), deadline time.Time, period time.Duration) (any, error) {
	l.defaults()
	if l.wait != nil {
		return l.wait(label, probe, deadline, period)
	}
	var last error
	for l.Now().Before(deadline) {
		if e := l.Ctx.Err(); e != nil {
			return nil, e
		}
		v, e := probe()
		if e != nil {
			var terminal *TerminalReceipt
			if errors.As(e, &terminal) {
				return nil, e
			}
			last = e
		} else if truth(v) {
			l.Note("ready", Object{"label": label})
			return v, nil
		}
		l.Sleep(period)
	}
	return nil, fmt.Errorf("%s did not become ready: %w", label, errors.Join(context.DeadlineExceeded, last))
}

type TerminalReceipt struct{ Receipt Object }

func (e *TerminalReceipt) Error() string {
	return fmt.Sprintf("terminal delivery receipt: %v", e.Receipt)
}
func CuratedHostStatuses(statuses any, captured time.Time) ([]Object, error) {
	rows, ok := statuses.([]any)
	if !ok {
		return nil, errors.New("operator hosts did not return a list")
	}
	result := []Object{}
	for _, raw := range rows {
		s, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("operator hosts returned an invalid status")
		}
		r, ok := s["registration"].(map[string]any)
		if !ok {
			return nil, errors.New("operator hosts returned an invalid status")
		}
		expiry, _ := time.Parse(time.RFC3339Nano, str(s["session_expires_at"]))
		capacity := object(r["capacity"])
		reports := []Object{}
		for _, rawReport := range array(s["reports"]) {
			report, ok := rawReport.(map[string]any)
			if !ok {
				continue
			}
			var h any
			if id, ok := report["session_id"].(string); ok {
				h = head(hashBytes([]byte(id)), 32)
			}
			reports = append(reports, Object{"role": report["role"], "generation": report["generation"], "state": report["state"], "digest_prefix": head(str(report["digest"]), 12), "epoch": report["epoch"], "observed_at": report["observed_at"], "session_id_hash": h})
		}
		result = append(result, Object{"node": r["node"], "environment": r["environment"], "roles": r["roles"], "registration_generation": r["generation"], "capacity": Object{"cpu": capacity["cpu"], "memory_bytes": capacity["memory_bytes"], "disk_bytes": capacity["disk_bytes"]}, "session_expires_at": s["session_expires_at"], "session_current": expiry.After(captured), "verified": s["verified"], "reports": reports})
	}
	return result, nil
}
func (l *Lab) Operator(operation string, timeout time.Duration, allow bool, stage string, args ...string) (any, error) {
	l.defaults()
	if stage == "" {
		stage = operation
	}
	started := l.Now()
	argv := append([]string{l.Binary, "operator", operation, "--config", l.OperatorConfig}, args...)
	r, e := l.cmd(argv, CommandOptions{Timeout: timeout, AllowFailure: true})
	fields := Object{"operation": operation, "stage": stage, "exit_code": r.Code, "elapsed_seconds": l.Now().Sub(started).Seconds(), "timeout_seconds": timeout.Seconds(), "stdout": "", "stderr": tail(strings.TrimSpace(r.Stderr), 1000), "failure": nil}
	if e != nil {
		fields["exit_code"] = nil
		fields["failure"] = "launch_error"
		if errors.Is(e, context.DeadlineExceeded) {
			fields["failure"] = "subprocess_timeout"
		}
		l.Note("operator", fields)
		return nil, e
	}
	logged := tail(strings.TrimSpace(r.Stdout), 3000)
	if operation == "hosts" {
		logged = ""
		if r.Code == 0 {
			v, e := decode(r.Stdout)
			if e == nil {
				curated, e := CuratedHostStatuses(v, l.Now())
				if e == nil {
					b, _ := json.Marshal(curated)
					logged = tail(string(b), 3000)
				} else {
					logged = "<invalid host-status output>"
				}
			} else {
				logged = "<invalid host-status output>"
			}
		}
	}
	fields["stdout"] = logged
	if r.Code != 0 {
		fields["failure"] = "exit_nonzero"
	}
	l.Note("operator", fields)
	if r.Code != 0 {
		if allow {
			return nil, nil
		}
		out := r.Stdout
		if operation == "hosts" {
			out = ""
		}
		return nil, fmt.Errorf("command %q failed (%d): %s %s", argv, r.Code, tail(out, 2000), tail(r.Stderr, 2000))
	}
	return decode(r.Stdout)
}
func (l *Lab) HostSession(version string, timeout time.Duration, stage string) (Object, error) {
	v, e := l.Operator("hosts", timeout, false, stage)
	if e != nil {
		return nil, e
	}
	rows := array(v)
	if len(rows) != 1 {
		return nil, errors.New("expected exactly one host status")
	}
	s := object(rows[0])
	expiry, e := time.Parse(time.RFC3339Nano, str(s["session_expires_at"]))
	if e != nil {
		return nil, errors.New("host status lacks a session expiry")
	}
	if !expiry.After(l.Now()) {
		return nil, errors.New("host session is not current")
	}
	generation := int64(2)
	if version == "v1" {
		generation = 1
	}
	reports := []Object{}
	for _, r := range array(s["reports"]) {
		r := object(r)
		if r["role"] == "terrabase" && r["state"] == "running" && integer(r["generation"]) == generation {
			reports = append(reports, r)
		}
	}
	if len(reports) != 1 || str(reports[0]["session_id"]) == "" {
		return nil, errors.New("host lacks a unique running report bound to a session")
	}
	return Object{"expires_at": expiry, "session_id": reports[0]["session_id"], "report": reports[0], "reader_verified": s["verified"]}, nil
}
func (l *Lab) Intent(record Object, generation int, name string) (string, error) {
	request := Object{"schemaVersion": 1, "operationId": fmt.Sprintf("fc-%s-%d", name, generation), "source": record["source"], "artifactDigest": record["digest"], "manifestDigest": record["manifestDigest"], "cell": "lab", "role": "terrabase", "environment": "test", "generation": generation, "desiredReplicas": 1, "configDigest": ConfigDigest}
	p := filepath.Join(l.Stage, fmt.Sprintf("intent-%s-%d.json", name, generation))
	return p, writeJSON(p, request)
}
func (l *Lab) Deploy(record Object, generation int, name, operation string) error {
	l.defaults()
	deadline := l.Now().Add(200 * time.Second)
	remaining := func(cap time.Duration) time.Duration { return min(cap, max(0, deadline.Sub(l.Now()))) }
	attempts := []string{name}
	if name == "one-node-loss" {
		attempts = append(attempts, name+"-epoch-retry")
	}
	for i, attempt := range attempts {
		p, e := l.Intent(record, generation, attempt)
		if e != nil {
			return e
		}
		submitted, e := l.Wait("submit-"+attempt, func() (any, error) { return l.Operator(operation, remaining(35*time.Second), false, "", "--intent", p) }, deadline, 2*time.Second)
		if e != nil {
			return e
		}
		s := object(submitted)
		if s["status"] != "submitted" {
			return fmt.Errorf("%s %s did not submit", operation, attempt)
		}
		l.ActiveOperationID = str(s["operationId"])
		started := l.Now()
		_, e = l.Wait("accepted-"+attempt, func() (any, error) {
			v, e := l.Operator("status", remaining(35*time.Second), false, "", "--operation-id", str(s["operationId"]), "--fingerprint", str(s["fingerprint"]))
			if e != nil {
				return nil, e
			}
			if name == "one-node-loss" && l.Now().Sub(started) >= 20*time.Second {
				l.CaptureClusterDiagnostics()
			}
			r := object(v)
			if r["status"] == "rejected" || r["status"] == "held" {
				return nil, &TerminalReceipt{r}
			}
			return r["status"] == "accepted", nil
		}, deadline, 2*time.Second)
		if e == nil {
			return nil
		}
		if terminal, ok := errors.AsType[*TerminalReceipt](e); ok {
			r := terminal.Receipt
			l.Note("terminal_receipt", Object{"name": attempt, "operation_id": s["operationId"], "fingerprint": s["fingerprint"], "status": r["status"], "error": r["error"], "authority_epoch": r["authorityEpoch"]})
			if i == 0 && name == "one-node-loss" && r["status"] == "rejected" && r["error"] == PreAcceptanceFenced {
				l.Note("retry_fenced_intent", Object{"rejected_operation_id": s["operationId"], "new_operation_id": fmt.Sprintf("fc-%s-%d", attempts[1], generation)})
				continue
			}
			return fmt.Errorf("%s %s became terminal %v", operation, attempt, r)
		}
		return e
	}
	return errors.New("no deployment attempt accepted")
}
func GenericPreflight(o GenericOptions) error {
	for _, x := range [][2]string{{o.Kernel, KernelSHA}, {o.Rootfs, RootfsSHA}, {Chronyd, ChronydSHA}, {Chronyc, ChronycSHA}} {
		h, e := Digest(x[0])
		if e != nil || h != x[1] {
			return fmt.Errorf("asset missing or SHA-256 mismatch: %s", x[0])
		}
	}
	for _, name := range []string{"go", "git", "ssh", "ssh-keygen", "cp", "ip", "nft", "openssl", "sudo", "mount", "umount", "e2fsck", "resize2fs", "ss"} {
		if _, e := exec.LookPath(name); e != nil {
			return fmt.Errorf("required command missing: %s", name)
		}
	}
	if s, e := os.Stat(o.Firecracker); e != nil || !s.Mode().IsRegular() {
		return fmt.Errorf("Firecracker executable missing: %s", o.Firecracker)
	}
	for _, p := range []string{"/dev/kvm", "/dev/net/tun"} {
		if _, e := os.Stat(p); e != nil {
			return errors.New("Firecracker requires /dev/kvm and /dev/net/tun")
		}
	}
	return nil
}
func RunGeneric(ctx context.Context, args []string, out, errout io.Writer) error {
	if len(args) == 0 {
		return errors.New("firecracker requires check or run")
	}
	action := args[0]
	if action != "check" && action != "run" {
		return errors.New("firecracker action must be check or run")
	}
	f := flag.NewFlagSet("qualification firecracker generic", flag.ContinueOnError)
	f.SetOutput(errout)
	var o GenericOptions
	f.StringVar(&o.Kernel, "kernel", "", "pinned guest kernel")
	f.StringVar(&o.Rootfs, "rootfs", "", "pinned guest ext4 image")
	fc, _ := exec.LookPath("firecracker")
	f.StringVar(&o.Firecracker, "firecracker", fc, "Firecracker executable")
	f.StringVar(&o.RunDir, "run-dir", "", "new private evidence directory")
	f.StringVar(&o.SourceRoot, "source-root", ".", "repository source root")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	var e error
	o.SourceRoot, e = filepath.Abs(o.SourceRoot)
	if e != nil {
		return e
	}
	if e = GenericPreflight(o); e != nil {
		return e
	}
	if action == "check" {
		fmt.Fprintln(out, "Firecracker assets and host prerequisites verified; no resources created")
		return nil
	}
	if _, e = Execute(ctx, []string{"sudo", "-n", "true"}, CommandOptions{}); e != nil {
		return e
	}
	l, e := NewLab(ctx, o, out)
	if e != nil {
		return e
	}
	outcome := "FAILED"
	for _, step := range []func() error{l.Build, l.Identities, l.Configs, l.Scenario} {
		if e = step(); e != nil {
			break
		}
	}
	if l.NativeExecutable.ExecutableSHA256 != "" {
		e = errors.Join(e, l.NativeExecutable.VerifyExecutable())
	}
	if e == nil {
		source, se := SourceDigest(o.SourceRoot)
		h, he := l.HarnessDigest()
		if se != nil || he != nil || source != l.GoSourceSHA || h != l.HarnessSHA {
			e = errors.New("source changed during qualification; run cannot certify a moving tree")
		} else {
			outcome = "PASS"
		}
	}
	if e != nil {
		fmt.Fprintf(errout, "qualification failed: %v\n", e)
		l.CaptureClusterDiagnostics()
		l.CaptureFailureDiagnostics()
	}
	cleanup := l.Cleanup(outcome != "PASS")
	if len(cleanup) > 0 {
		outcome = "CLEANUP_FAILED"
	}
	revision, _ := l.cmd([]string{"git", "rev-parse", "HEAD"}, CommandOptions{})
	finalSource, _ := SourceDigest(o.SourceRoot)
	finalHarness, _ := l.HarnessDigest()
	binary, _ := Digest(l.Binary)
	failure := ""
	if e != nil {
		failure = e.Error()
	}
	summary := Object{"result": outcome, "failure": failure, "cleanup_errors": cleanup, "revision": strings.TrimSpace(revision.Stdout), "go_source_sha256": l.GoSourceSHA, "harness_sha256": l.HarnessSHA, "final_go_source_sha256": finalSource, "final_harness_sha256": finalHarness, "binary_sha256": binary, "native_qualification": l.NativeExecutable, "events": l.Events}
	writeErr := writeJSON(filepath.Join(l.Root, "summary.json"), summary)
	fmt.Fprintf(out, "evidence: %s\n", filepath.Join(l.Root, "summary.json"))
	if outcome != "PASS" && e == nil {
		e = fmt.Errorf("qualification failed: %v", cleanup)
	}
	return errors.Join(e, writeErr)
}
