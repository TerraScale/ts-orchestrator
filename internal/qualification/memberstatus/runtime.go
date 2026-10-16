package memberstatus

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
)

func AtomicReplace(path string, value any) error {
	b, e := json.Marshal(value, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".evidence-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(append(b, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

type EventLog struct {
	Path    string
	Entries []Object
	Err     error
}

func (e *EventLog) Add(event string, fields Object) {
	if fields == nil {
		fields = Object{}
	}
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = event
	e.Entries = append(e.Entries, fields)
	if e.Err == nil {
		e.Err = AtomicReplace(e.Path, e.Entries)
	}
}

// BoundedOutput always drains writes while retaining at most Maximum bytes.
// Returning a full write length ensures verbose children cannot block on pipes.
type BoundedOutput struct {
	Path      string
	Maximum   int64
	Written   int64
	Truncated bool
	err       error
	file      *os.File
	mu        sync.Mutex
}

func NewBoundedOutput(path string, maximum int64) (*BoundedOutput, error) {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return nil, e
	}
	return &BoundedOutput{Path: path, Maximum: maximum, file: f}, nil
}
func (b *BoundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	length := len(p)
	room := max(int64(0), b.Maximum-b.Written)
	if int64(len(p)) > room {
		p = p[:room]
		b.Truncated = true
	}
	if b.file != nil && b.err == nil {
		n, e := b.file.Write(p)
		b.Written += int64(n)
		if e != nil {
			b.err = e
			b.Truncated = true
		}
	}
	return length, nil
}
func (b *BoundedOutput) Finish() (Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file != nil {
		b.err = errors.Join(b.err, b.file.Sync(), b.file.Close())
		b.file = nil
	}
	return Object{"path": b.Path, "bytes_written": b.Written, "limit_bytes": b.Maximum, "truncated": b.Truncated}, b.err
}

type pendingCommand struct {
	Label   string
	Process *firecracker.Process
	Capture *BoundedOutput
}
type CommandRunner struct {
	Root     string
	Events   *EventLog
	Sequence int
	Maximum  int64
	pending  []pendingCommand
}

func (r *CommandRunner) Pending() bool { return len(r.pending) > 0 }
func (r *CommandRunner) StopPending() []string {
	var errs []string
	pending := r.pending
	r.pending = nil
	for _, p := range pending {
		if e := p.Process.Stop(5*time.Second, false); e != nil {
			errs = append(errs, fmt.Sprintf("stop pending command process group %d (%s): %v", p.Process.PID(), p.Label, e))
			r.pending = append(r.pending, p)
			continue
		}
		result, e := p.Capture.Finish()
		if e != nil {
			errs = append(errs, e.Error())
		}
		r.Events.Add("pending_command_stopped", Object{"label": p.Label, "pid": p.Process.PID(), "returncode": p.Process.ExitCode, "output": result})
	}
	return errs
}
func (r *CommandRunner) Run(ctx context.Context, label string, args []string, timeout time.Duration, allowed []int) (int, string, error) {
	if r.Pending() {
		return 0, "", fmt.Errorf("refusing to start a command while an earlier process group is not confirmed stopped")
	}
	r.Sequence++
	log := filepath.Join(r.Root, "commands", fmt.Sprintf("%03d-%s.log", r.Sequence, label))
	maximum := r.Maximum
	if maximum == 0 {
		maximum = MaxCommandLogBytes
	}
	if e := AtomicReplace(log[:len(log)-4]+".json", Object{"label": label, "command": args, "timeout_seconds": timeout.Seconds(), "log": log, "log_limit_bytes": maximum}); e != nil {
		return 0, log, e
	}
	r.Events.Add("command_start", Object{"label": label, "command": args, "timeout_seconds": timeout.Seconds(), "log": log})
	if r.Events.Err != nil {
		return 0, log, r.Events.Err
	}
	capture, e := NewBoundedOutput(log, maximum)
	if e != nil {
		return 0, log, e
	}
	p, e := firecracker.Start(args, "", capture)
	if e != nil {
		capture.Finish()
		return 0, log, e
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	finished := false
	for waitCtx.Err() == nil {
		exited, e := p.Exited()
		if e != nil {
			break
		}
		if exited {
			finished = true
			break
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	stopErr := p.Stop(time.Second, false)
	if stopErr != nil {
		if !p.Reaped {
			r.pending = append(r.pending, pendingCommand{label, p, capture})
		} else {
			_, captureErr := capture.Finish()
			stopErr = errors.Join(stopErr, captureErr)
		}
		return 0, log, fmt.Errorf("command cleanup failed: %w", stopErr)
	}
	result, logErr := capture.Finish()
	r.Events.Add("command_exit", Object{"label": label, "returncode": p.ExitCode, "log": log, "output": result})
	if !finished {
		return p.ExitCode, log, fmt.Errorf("command failed: timed out or interrupted after %s", timeout)
	}
	if logErr != nil {
		return p.ExitCode, log, fmt.Errorf("bounded log collection failed: %w", logErr)
	}
	if capture.Truncated {
		return p.ExitCode, log, fmt.Errorf("bounded command log was truncated")
	}
	if allowed == nil {
		allowed = []int{0}
	}
	if !slices.Contains(allowed, p.ExitCode) {
		return p.ExitCode, log, fmt.Errorf("command failed (%d): %v; log %s", p.ExitCode, args, log)
	}
	return p.ExitCode, log, nil
}

type APIRequest struct {
	Method, Path string
	Payload      Object
}
type VM struct {
	Firecracker, Kernel, Image, SocketDir, Logs, ManagedVolume string
	Events                                                     *EventLog
	Process                                                    *firecracker.Process
	Serial, VMM                                                *BoundedOutput
	ProcessGroupStopped                                        bool
	Output                                                     Object
	API                                                        func(context.Context, string, string, Object) error
	StartProcess                                               func([]string, io.Writer, io.Writer) (*firecracker.Process, error)
}

func (v *VM) SocketPath() string { return filepath.Join(v.SocketDir, "api.sock") }
func unixRequest(ctx context.Context, socket, method, path string, payload Object) error {
	if method == "PUT" {
		return firecracker.UnixAPI(ctx, socket, path, payload)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	r, e := http.NewRequestWithContext(ctx, method, "http://localhost"+path, nil)
	if e != nil {
		return e
	}
	response, e := client.Do(r)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	_, e = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 && response.StatusCode != 204 {
		return fmt.Errorf("Firecracker %s %s: HTTP %d", method, path, response.StatusCode)
	}
	return nil
}
func (v *VM) api(ctx context.Context, method, path string, payload Object) error {
	if v.API != nil {
		return v.API(ctx, method, path, payload)
	}
	return unixRequest(ctx, v.SocketPath(), method, path, payload)
}
func (v *VM) Requests() []APIRequest {
	r := []APIRequest{{"PUT", "/machine-config", Object{"vcpu_count": GuestVCPUs, "mem_size_mib": GuestRAMMiB, "smt": false}}, {"PUT", "/boot-source", Object{"kernel_image_path": v.Kernel, "boot_args": BootArgs}}, {"PUT", "/drives/rootfs", Object{"drive_id": "rootfs", "path_on_host": v.Image, "is_root_device": true, "is_read_only": false}}}
	if v.ManagedVolume != "" {
		r = append(r, APIRequest{"PUT", "/drives/" + ManagedVolumeDriveID, Object{"drive_id": ManagedVolumeDriveID, "path_on_host": v.ManagedVolume, "is_root_device": false, "is_read_only": false}})
	}
	return append(r, APIRequest{"PUT", "/actions", Object{"action_type": "InstanceStart"}})
}
func (v *VM) Start(ctx context.Context) error {
	if len([]byte(v.SocketPath())) >= 100 {
		return fmt.Errorf("Firecracker API socket path must be shorter than 100 bytes")
	}
	var e error
	v.Serial, e = NewBoundedOutput(filepath.Join(v.Logs, "guest-serial.log"), MaxSerialLogBytes)
	if e != nil {
		return e
	}
	v.VMM, e = NewBoundedOutput(filepath.Join(v.Logs, "firecracker-vmm.log"), MaxCommandLogBytes)
	if e != nil {
		v.Serial.Finish()
		return e
	}
	start := v.StartProcess
	if start == nil {
		start = func(args []string, stdout, stderr io.Writer) (*firecracker.Process, error) {
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = stdout
			cmd.Stderr = stderr
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.WaitDelay = 2 * time.Second
			if e := cmd.Start(); e != nil {
				return nil, e
			}
			return &firecracker.Process{Cmd: cmd}, nil
		}
	}
	command := []string{v.Firecracker, "--api-sock", v.SocketPath(), "--log-path", "/dev/stderr"}
	v.Process, e = start(command, v.Serial, v.VMM)
	if e != nil {
		v.Serial.Finish()
		v.VMM.Finish()
		return e
	}
	v.Events.Add("firecracker_start", Object{"pid": v.Process.PID(), "command": command, "api_socket": v.SocketPath()})
	if v.Events.Err != nil {
		return v.Events.Err
	}
	deadline := time.Now().Add(20 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		exited, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if exited {
			return fmt.Errorf("Firecracker exited before API became ready")
		}
		if _, e := os.Stat(v.SocketPath()); e == nil {
			if e = v.api(ctx, "GET", "/version", nil); e == nil {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("Firecracker API socket did not become ready in 20s")
	}
	for _, r := range v.Requests() {
		if e = v.api(ctx, r.Method, r.Path, r.Payload); e != nil {
			return e
		}
	}
	v.Events.Add("guest_boot", Object{"pid": v.Process.PID(), "memory_mib": GuestRAMMiB, "vcpus": GuestVCPUs, "network_interfaces": []any{}})
	return nil
}
func (v *VM) FinishOutput() error {
	v.Output = Object{}
	var errs []error
	for _, entry := range []struct {
		name    string
		capture *BoundedOutput
	}{{"serial", v.Serial}, {"vmm", v.VMM}} {
		if entry.capture == nil {
			continue
		}
		r, e := entry.capture.Finish()
		if e != nil {
			errs = append(errs, e)
		}
		v.Output[entry.name] = r
		if entry.capture.Truncated {
			errs = append(errs, fmt.Errorf("Firecracker output log was truncated: %s", entry.name))
		}
	}
	v.Events.Add("firecracker_output_collected", Object{"output": v.Output})
	return errors.Join(errs...)
}
func (v *VM) WaitForShutdown(ctx context.Context) error {
	deadline := time.Now().Add(GuestDeadlineSeconds * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		done, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if done {
			if e = v.Process.Stop(time.Second, false); e != nil {
				return e
			}
			v.ProcessGroupStopped = true
			if e = v.FinishOutput(); e != nil {
				return e
			}
			if v.Process.ExitCode != 0 {
				return fmt.Errorf("Firecracker exited with status %d", v.Process.ExitCode)
			}
			v.Events.Add("guest_vmm_exit", Object{"returncode": v.Process.ExitCode})
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("guest exceeded %ds deadline", GuestDeadlineSeconds)
}
func (v *VM) Stop(ctx context.Context) []string {
	var errs []string
	if v.Process == nil {
		return nil
	}
	if !v.ProcessGroupStopped {
		done, e := v.Process.Exited()
		if e != nil {
			errs = append(errs, e.Error())
		}
		if !done {
			if e = v.api(ctx, "PUT", "/actions", Object{"action_type": "SendCtrlAltDel"}); e != nil {
				errs = append(errs, fmt.Sprintf("send guest CtrlAltDel: %v", e))
			}
			v.Process.WaitUnreaped(25 * time.Second)
		}
		if e = v.Process.Stop(5*time.Second, false); e != nil {
			errs = append(errs, fmt.Sprintf("stop Firecracker process group: %v", e))
		} else {
			v.ProcessGroupStopped = true
		}
	}
	if !v.ProcessGroupStopped {
		errs = append(errs, "Firecracker process group is not confirmed stopped")
	} else if len(v.Output) == 0 {
		if e := v.FinishOutput(); e != nil {
			errs = append(errs, e.Error())
		}
	}
	if len(errs) == 0 {
		v.Events.Add("firecracker_stopped", Object{"pid": v.Process.PID(), "returncode": v.Process.ExitCode})
	}
	return errs
}
