package firecracker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type BoundedWriter struct {
	mu           sync.Mutex
	File         *os.File
	Total, Limit int64
}

func (w *BoundedWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := max(int64(0), w.Limit-w.Total)
	w.Total += int64(len(b))
	if remaining > 0 {
		if _, e := w.File.Write(b[:min(int64(len(b)), remaining)]); e != nil {
			return 0, e
		}
	}
	return len(b), nil
}
func (w *BoundedWriter) Overflowed() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.Total > w.Limit }
func (w *BoundedWriter) Close() error     { return w.File.Close() }
func BoundedCommand(ctx context.Context, argv []string, o CommandOptions, path string, bound int64) (CommandResult, error) {
	r, _, err := runBoundedCommand(ctx, argv, o, path, bound, nil)
	return r, err
}
func runBoundedCommand(ctx context.Context, argv []string, o CommandOptions, path string, bound int64, hooks *processHooks) (CommandResult, *Process, error) {
	if len(argv) == 0 {
		return CommandResult{}, nil, errors.New("empty command")
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{}, nil, err
	}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if e != nil {
		return CommandResult{}, nil, e
	}
	capture := &BoundedWriter{File: file, Limit: bound}
	c := exec.Command(argv[0], argv[1:]...)
	c.Dir = o.Dir
	c.Env = o.Env
	c.Stdin = strings.NewReader(o.Input)
	c.Stdout = capture
	c.Stderr = capture
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.WaitDelay = 2 * time.Second
	if e = c.Start(); e != nil {
		file.Close()
		return CommandResult{}, nil, e
	}
	p := &Process{Cmd: c, Output: capture, hooks: hooks}
	waitErr := waitCommand(ctx, p, o.Timeout)
	cleanup := p.Stop(10*time.Second, true)
	b, readErr := os.ReadFile(path)
	r := CommandResult{Code: p.ExitCode, Stdout: string(b)}
	if capture.Overflowed() {
		waitErr = errors.Join(waitErr, fmt.Errorf("command log exceeded %d bytes", bound))
	}
	if e = errors.Join(waitErr, cleanup, readErr); e != nil {
		if !p.Reaped {
			return r, p, &PendingCommandError{Process: p, Err: e}
		}
		return r, nil, e
	}
	if r.Code != 0 && !o.AllowFailure {
		return r, nil, fmt.Errorf("command failed (%d): %q; log: %s: %s", r.Code, argv, path, tail(r.Stdout, 1500))
	}
	return r, nil, nil
}
func GuestPath(mount, destination string) (string, error) {
	if !filepath.IsAbs(destination) || slices.Contains(strings.Split(destination, "/"), "..") {
		return "", fmt.Errorf("unsafe guest path %s", destination)
	}
	current := mount
	parts := strings.Split(strings.TrimPrefix(destination, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		s, e := os.Lstat(current)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", e
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("guest path traverses symlink %s", current)
		}
		if i < len(parts)-1 && !s.IsDir() {
			return "", fmt.Errorf("guest path parent is not a directory: %s", current)
		}
	}
	return current, nil
}
func CheckManagedGuestTools(mount string) error {
	for _, tool := range []string{"/usr/lib/systemd/systemd", "/usr/sbin/blkid", "/usr/sbin/update-ca-certificates", "/usr/bin/mount", "/usr/bin/findmnt", "/usr/bin/mountpoint", "/usr/bin/readlink", "/usr/bin/systemctl", "/usr/bin/ip"} {
		p, e := GuestPath(mount, tool)
		if e != nil {
			return e
		}
		s, e := os.Stat(p)
		if e != nil || !s.Mode().IsRegular() {
			return fmt.Errorf("guest rootfs lacks %s", tool)
		}
	}
	return nil
}
func ManagedDirectories(member string) [][2]any {
	dir := ManagedMemberDirs[member]
	return [][2]any{{"/srv/ts-managed", 0o750}, {dir, 0o750}, {dir + "/material", 0o750}, {dir + "/control", 0o730}, {dir + "/volume", 0o750}}
}
func FirecrackerDriveRequest(identifier, path string, root bool) (string, Object, error) {
	if !regexpID.MatchString(identifier) {
		return "", nil, fmt.Errorf("invalid Firecracker drive resource ID: %s", identifier)
	}
	return "/drives/" + identifier, Object{"drive_id": identifier, "path_on_host": path, "is_root_device": root, "is_read_only": false}, nil
}
func FirecrackerNetworkRequest(identifier, tap, mac string) (string, Object, error) {
	if !regexpID.MatchString(identifier) {
		return "", nil, fmt.Errorf("invalid Firecracker network resource ID: %s", identifier)
	}
	return "/network-interfaces/" + identifier, Object{"iface_id": identifier, "host_dev_name": tap, "guest_mac": mac}, nil
}
func ManagedMetric(metrics Object, name string, required bool) (float64, error) {
	v, ok := metrics[name]
	if !ok {
		if required {
			return 0, fmt.Errorf("native metric missing: %s", name)
		}
		return 0, nil
	}
	var n float64
	switch v := v.(type) {
	case float64:
		n = v
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case strictNumber:
		var e error
		n, e = strconv.ParseFloat(string(v), 64)
		if e != nil {
			return 0, e
		}
	default:
		return 0, fmt.Errorf("native metric invalid: %s=%v", name, v)
	}
	if n < 0 || math.IsNaN(n) {
		return 0, fmt.Errorf("native metric invalid: %s=%v", name, v)
	}
	return n, nil
}
func ValidateManagedEvidence(member string, e Object) error {
	fields := []string{"version", "node", "member_id", "process_pid", "process_uid", "process_gid", "process_cgroup", "memory_max_bytes", "filesystem_uuid", "mount_id", "claim_sha256", "storage_recovered", "listener_ready", "metrics"}
	if !exactFields(e, fields) || integer(e["version"]) != 1 || e["node"] != "node-"+member || e["member_id"] != ManagedMemberIDs[member] || e["filesystem_uuid"] != ManagedVolumeUUIDs[member] || integer(e["process_uid"]) != 65534 || integer(e["process_gid"]) != 65534 || integer(e["memory_max_bytes"]) != 4<<30 || integer(e["process_pid"]) < 2 || integer(e["mount_id"]) < 1 || e["storage_recovered"] != true || e["listener_ready"] != true || !shaPattern.MatchString(str(e["claim_sha256"])) || !strings.HasSuffix(str(e["process_cgroup"]), "/terrabase") {
		return fmt.Errorf("%s: native process/volume evidence is incomplete or inconsistent", member)
	}
	if _, ok := e["metrics"].(map[string]any); !ok {
		return fmt.Errorf("%s: native process/volume evidence is incomplete or inconsistent", member)
	}
	return nil
}
func ParseManagedTestResult(member, output, serial string) error {
	lines := []string{}
	runs, passes, phases := []string{}, []string{}, []string{}
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "=== RUN   ") {
			runs = append(runs, line)
		}
		if strings.HasPrefix(line, "--- PASS:") {
			passes = append(passes, line)
		}
		if strings.HasPrefix(line, "--- FAIL:") || strings.HasPrefix(line, "--- SKIP:") {
			return fmt.Errorf("%s: focused Go test did not pass exactly once without skip", member)
		}
		if regexpPhase.MatchString(line) {
			phases = append(phases, line)
		}
	}
	if !slices.Equal(runs, []string{"=== RUN   " + ManagedMemberGoTest}) || len(passes) != 1 || !strings.HasPrefix(passes[0], "--- PASS: "+ManagedMemberGoTest+" ") || len(lines) == 0 || lines[len(lines)-1] != "PASS" || !slices.Equal(phases, []string{"TS_MANAGED_MEMBER_PHASE=PASS node=node-" + member}) {
		return fmt.Errorf("%s: focused Go test did not pass exactly once without skip", member)
	}
	markers := []string{}
	for line := range strings.SplitSeq(serial, "\n") {
		if _, after, ok := strings.Cut(line, "TS_MANAGED_MEMBER_QUALIFICATION_RESULT="); ok {
			markers = append(markers, strings.TrimSpace(after))
		}
	}
	if !slices.Equal(markers, []string{"PASS node=node-" + member}) {
		return fmt.Errorf("%s: terminal guest runner result is absent or ambiguous: %v", member, markers)
	}
	return nil
}

type FirecrackerRequest struct {
	Route string
	Body  Object
}

type ManagedVM struct {
	Resources func() ([]FirecrackerRequest, error)

	Lab            *ManagedLab
	Member, Socket string
	Process        *Process
	Serial, VMM    *BoundedWriter
	Stopped        bool
}

func (v *ManagedVM) ResourceRequests() ([]FirecrackerRequest, error) {
	requests := []FirecrackerRequest{}
	for _, drive := range []struct {
		id, path string
		root     bool
	}{{"rootfs", filepath.Join(v.Lab.Images, v.Member+"-rootfs.ext4"), true}, {"managed_volume", filepath.Join(v.Lab.Images, v.Member+"-volume.ext4"), false}} {
		route, body, e := FirecrackerDriveRequest(drive.id, drive.path, drive.root)
		if e != nil {
			return nil, e
		}
		requests = append(requests, FirecrackerRequest{route, body})
	}
	route, body, e := FirecrackerNetworkRequest("eth0", v.Lab.Taps[v.Member], ManagedGuestMACs[v.Member])
	if e != nil {
		return nil, e
	}
	requests = append(requests, FirecrackerRequest{route, body})
	return requests, nil
}
func (v *ManagedVM) Start() error {
	if len(v.Socket) >= 100 {
		return errors.New("Firecracker API socket path is too long")
	}
	var requests []FirecrackerRequest
	var e error
	if v.Resources != nil {
		requests, e = v.Resources()
	} else {
		requests, e = v.ResourceRequests()
	}
	if e != nil {
		return e
	}
	serial, e := os.OpenFile(filepath.Join(v.Lab.Logs, v.Member+"-serial.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	vmm, e := os.OpenFile(filepath.Join(v.Lab.Logs, v.Member+"-vmm.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if e != nil {
		serial.Close()
		return e
	}
	v.Serial = &BoundedWriter{File: serial, Limit: 32 << 20}
	v.VMM = &BoundedWriter{File: vmm, Limit: 32 << 20}
	c := exec.Command(v.Lab.Manifest.Inputs["firecracker"].Path, "--api-sock", v.Socket, "--log-path", "/dev/stderr")
	c.Stdout = v.Serial
	c.Stderr = v.VMM
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.WaitDelay = 2 * time.Second
	if e = c.Start(); e != nil {
		return errors.Join(e, v.finishCapture())
	}
	v.Process = &Process{Cmd: c}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, e = os.Stat(v.Socket); e == nil {
			break
		}
		done, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if done {
			return fmt.Errorf("Firecracker %s exited before API socket", v.Member)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Firecracker %s API socket timeout", v.Member)
		}
		select {
		case <-v.Lab.Ctx.Done():
			return v.Lab.Ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	requests = append([]FirecrackerRequest{{"/machine-config", Object{"vcpu_count": 2, "mem_size_mib": 6144, "smt": false}}, {"/boot-source", Object{"kernel_image_path": v.Lab.Manifest.Inputs["kernel"].Path, "boot_args": "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw systemd.unit=multi-user.target"}}}, requests...)
	requests = append(requests, FirecrackerRequest{"/actions", Object{"action_type": "InstanceStart"}})
	for _, r := range requests {
		if e = UnixAPI(v.Lab.Ctx, v.Socket, r.Route, r.Body); e != nil {
			return e
		}
	}
	v.Lab.Note("vm_started", Object{"member": v.Member, "pid": v.Process.PID()})
	return nil
}
func (v *ManagedVM) finishCapture() error {
	var e error
	for _, capture := range []*BoundedWriter{v.Serial, v.VMM} {
		if capture != nil {
			if capture.Overflowed() {
				e = errors.Join(e, errors.New("VM output truncated or not drained"))
			}
			e = errors.Join(e, capture.Close())
		}
	}
	v.Serial, v.VMM = nil, nil
	return e
}
func (v *ManagedVM) NaturalExit() error {
	if v.Process == nil {
		return errors.New("VM was not started")
	}
	deadline := time.Now().Add(540 * time.Second)
	for {
		done, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("VM %s did not exit naturally", v.Member)
		}
		select {
		case <-v.Lab.Ctx.Done():
			return v.Lab.Ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e := v.Process.Stop(10*time.Second, true); e != nil {
		v.Stopped = v.Process.Reaped
		if v.Stopped {
			e = errors.Join(e, v.finishCapture())
		}
		return e
	}
	v.Stopped = true
	e := v.finishCapture()
	if v.Process.ExitCode != 0 {
		return errors.Join(e, fmt.Errorf("VM %s exit %d", v.Member, v.Process.ExitCode))
	}
	v.Lab.Note("vm_natural_exit", Object{"member": v.Member, "status": v.Process.ExitCode})
	return e
}
func (v *ManagedVM) Stop() []string {
	errs := []string{}
	if v.Process == nil {
		v.Stopped = true
		if e := v.finishCapture(); e != nil {
			errs = append(errs, e.Error())
		}
		return errs
	}
	if !v.Process.Reaped {
		if e := UnixAPI(context.WithoutCancel(v.Lab.Ctx), v.Socket, "/actions", Object{"action_type": "SendCtrlAltDel"}); e == nil {
			_, _ = v.Process.WaitUnreaped(15 * time.Second)
		}
		if e := v.Process.Stop(5*time.Second, false); e != nil {
			errs = append(errs, e.Error())
		}
		v.Stopped = v.Process.Reaped
	} else {
		v.Stopped = true
	}
	if v.Stopped {
		if e := v.finishCapture(); e != nil {
			errs = append(errs, e.Error())
		}
	}
	return errs
}
func (l *ManagedLab) Request(member, method, path string) (int, Object, error) {
	ctx, cancel := context.WithTimeout(l.Ctx, 5*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, method, "http://"+ManagedGuestIPs[member]+":9540"+path, nil)
	if e != nil {
		return 0, nil, e
	}
	request.Header.Set("X-TS-Test-Token", l.Tokens[member])
	response, e := http.DefaultClient.Do(request)
	if e != nil {
		return 0, nil, e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil {
		return 0, nil, e
	}
	if len(body) > 64<<10 {
		return response.StatusCode, nil, fmt.Errorf("%s %s: evidence response exceeded bound", member, path)
	}
	if response.StatusCode == 204 {
		if len(body) > 0 {
			return 204, nil, errors.New("unexpected no-content body")
		}
		return 204, Object{}, nil
	}
	if response.StatusCode != 200 {
		return response.StatusCode, Object{"error": head(string(body), 1024)}, nil
	}
	var v any
	if e = json.Unmarshal(body, &v); e != nil {
		return 200, nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return 200, nil, errors.New("response is not an object")
	}
	return 200, m, nil
}
func (l *ManagedLab) WaitEvidence(member string, timeout time.Duration) (Object, error) {
	deadline := time.Now().Add(timeout)
	last := "no response"
	for time.Now().Before(deadline) {
		if vm := l.VMs[member]; vm != nil && vm.Process != nil {
			done, e := vm.Process.Exited()
			if e != nil {
				return nil, e
			}
			if done {
				return nil, fmt.Errorf("%s: VM exited before guest evidence was ready", member)
			}
		}
		status, evidence, e := l.Request(member, "GET", "/evidence")
		if e == nil && status == 200 {
			if e = ValidateManagedEvidence(member, evidence); e != nil {
				return nil, e
			}
			return evidence, nil
		}
		if e != nil {
			last = e.Error()
		} else {
			last = fmt.Sprintf("HTTP %d: %v", status, evidence)
		}
		select {
		case <-l.Ctx.Done():
			return nil, l.Ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("%s: native evidence timeout: %s", member, last)
}

var regexpID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var regexpPhase = regexp.MustCompile(`^TS_MANAGED_MEMBER_PHASE=PASS node=node-[ab]$`)
