// Package firecracker owns disposable qualification resources for real Firecracker guests.
package firecracker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Object = map[string]any

func object(v any) Object {
	x, _ := v.(map[string]any)
	if x == nil {
		return Object{}
	}
	return x
}
func array(v any) []any { x, _ := v.([]any); return x }
func str(v any) string  { x, _ := v.(string); return x }
func integer(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case uint64:
		return int64(n)
	}
	return 0
}
func truth(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case Object:
		return len(x) > 0
	case float64:
		return x != 0
	case int:
		return x != 0
	}
	return true
}
func tail(v string, n int) string {
	if len(v) > n {
		return v[len(v)-n:]
	}
	return v
}
func head(v string, n int) string { return v[:min(n, len(v))] }
func hashBytes(v []byte) string   { s := sha256.Sum256(v); return hex.EncodeToString(s[:]) }
func Digest(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func token(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v, json.Deterministic(true))
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
func decode(s string) (any, error) { var v any; e := json.Unmarshal([]byte(s), &v); return v, e }
func readObject(path string) (Object, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	v, e := decode(string(b))
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must contain a JSON object", path)
	}
	return m, nil
}

type CommandResult struct {
	Code           int
	Stdout, Stderr string
}
type CommandOptions struct {
	Timeout      time.Duration
	Dir          string
	AllowFailure bool
	Input        string
	Env          []string
}
type CommandFunc func(context.Context, []string, CommandOptions) (CommandResult, error)

// PendingCommandError transfers ownership of a command whose process group
// could not be confirmed stopped. Resource owners must retain and retry it.
type PendingCommandError struct {
	Process *Process
	Err     error
}

func (e *PendingCommandError) Error() string { return e.Err.Error() }
func (e *PendingCommandError) Unwrap() error { return e.Err }

type commandBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *commandBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *commandBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitCommand(ctx context.Context, p *Process, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := p.Exited()
		if err != nil || done {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func Execute(ctx context.Context, argv []string, o CommandOptions) (CommandResult, error) {
	if len(argv) == 0 {
		return CommandResult{}, errors.New("empty command")
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Dir = o.Dir
	c.Env = o.Env
	c.Stdin = strings.NewReader(o.Input)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.WaitDelay = 2 * time.Second
	var out, errout commandBuffer
	c.Stdout = &out
	c.Stderr = &errout
	if err := c.Start(); err != nil {
		return CommandResult{}, err
	}
	p := &Process{Cmd: c}
	err := errors.Join(waitCommand(ctx, p, o.Timeout), p.Stop(10*time.Second, true))
	r := CommandResult{Stdout: out.String(), Stderr: errout.String()}
	r.Code = p.ExitCode
	if !p.Reaped {
		return r, &PendingCommandError{Process: p, Err: err}
	}
	if err != nil {
		return r, err
	}
	if r.Code != 0 && !o.AllowFailure {
		return r, fmt.Errorf("command %q failed (%d): %s %s", argv, r.Code, tail(r.Stdout, 2000), tail(r.Stderr, 2000))
	}
	return r, nil
}

// Process deliberately does not launch a Wait goroutine: its unreaped leader reserves
// the process group ID until every member has received the final signal.
type Process struct {
	Cmd      *exec.Cmd
	Reaped   bool
	ExitCode int
	Output   io.Closer
	hooks    *processHooks
}

// processHooks isolates operating-system interactions without changing the
// ownership checks or cleanup ordering exercised by qualification tests.
type processHooks struct {
	group     func(int) (int, error)
	signal    func(int, syscall.Signal) error
	exited    func() (bool, error)
	wait      func(time.Duration) (bool, error)
	quiescent func(int, time.Duration) error
	reap      func() error
}

func Start(argv []string, dir string, output io.Writer) (*Process, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Dir = dir
	c.Stdout = output
	c.Stderr = output
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.WaitDelay = 2 * time.Second
	if e := c.Start(); e != nil {
		return nil, e
	}
	return &Process{Cmd: c}, nil
}
func (p *Process) PID() int { return p.Cmd.Process.Pid }
func (p *Process) Exited() (bool, error) {
	if p.Reaped {
		return true, nil
	}
	if p.hooks != nil && p.hooks.exited != nil {
		return p.hooks.exited()
	}
	var info unix.Siginfo
	e := unix.Waitid(unix.P_PID, p.PID(), &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
	if e != nil {
		return false, fmt.Errorf("owned process %d was reaped before cleanup: %w", p.PID(), e)
	}
	return info.Signo != 0, nil
}
func (p *Process) Group() (int, error) {
	if p.Reaped {
		return 0, fmt.Errorf("owned process %d was reaped before group cleanup", p.PID())
	}
	group := syscall.Getpgid
	if p.hooks != nil && p.hooks.group != nil {
		group = p.hooks.group
	}
	id, e := group(p.PID())
	if e != nil {
		return 0, e
	}
	if id != p.PID() {
		return 0, fmt.Errorf("owned process %d is no longer its process-group leader", p.PID())
	}
	return id, nil
}
func LiveProcessGroupMembers(pgid int) ([]int, error) {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	members := []int{}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		b, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		_, after, ok := strings.CutLast(string(b), ")")
		if !ok {
			return nil, fmt.Errorf("invalid process status for %d", pid)
		}
		f := strings.Fields(after)
		if len(f) < 3 {
			return nil, fmt.Errorf("invalid process status for %d", pid)
		}
		id, e := strconv.Atoi(f[2])
		if e != nil {
			return nil, e
		}
		if id == pgid && !slices.Contains([]string{"Z", "X", "x"}, f[0]) {
			members = append(members, pid)
		}
	}
	return members, nil
}
func WaitProcessGroupQuiescent(pgid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		members, e := LiveProcessGroupMembers(pgid)
		if e != nil {
			return e
		}
		if len(members) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("owned process group %d still has live members: %v", pgid, members)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (p *Process) WaitUnreaped(timeout time.Duration) (bool, error) {
	if p.hooks != nil && p.hooks.wait != nil {
		return p.hooks.wait(timeout)
	}
	deadline := time.Now().Add(timeout)
	for {
		done, e := p.Exited()
		if e != nil || done {
			return done, e
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (p *Process) Stop(timeout time.Duration, kill bool) error {
	id, e := p.Group()
	if e != nil {
		return e
	}
	if !kill {
		if e = p.signalGroup(id, syscall.SIGTERM); e != nil && !errors.Is(e, syscall.ESRCH) {
			return e
		}
		if _, e = p.WaitUnreaped(timeout); e != nil {
			return e
		}
		if _, e = p.Group(); e != nil {
			return e
		}
	}
	if e = p.signalGroup(id, syscall.SIGKILL); e != nil && !errors.Is(e, syscall.ESRCH) {
		return e
	}
	quiescent := WaitProcessGroupQuiescent
	if p.hooks != nil && p.hooks.quiescent != nil {
		quiescent = p.hooks.quiescent
	}
	if e = quiescent(id, timeout); e != nil {
		return e
	}
	if p.hooks != nil && p.hooks.reap != nil {
		e = p.hooks.reap()
	} else {
		e = p.Cmd.Wait()
	}
	p.Reaped = true
	if p.Cmd.ProcessState != nil {
		p.ExitCode = p.Cmd.ProcessState.ExitCode()
	}
	if _, ok := errors.AsType[*exec.ExitError](e); ok {
		e = nil
	}
	if p.Output != nil {
		e = errors.Join(e, p.Output.Close())
		p.Output = nil
	}
	return e
}
func (p *Process) signalGroup(id int, signal syscall.Signal) error {
	if p.hooks != nil && p.hooks.signal != nil {
		return p.hooks.signal(id, signal)
	}
	return syscall.Kill(-id, signal)
}
func SocketPath(directory, name string) (string, error) {
	p := filepath.Join(directory, name+".sock")
	if len([]byte(p)) > 107 {
		return "", fmt.Errorf("Firecracker API socket path is too long: %s", p)
	}
	return p, nil
}
func PrivateSocketDirectory() (string, error) {
	d, e := os.MkdirTemp("/tmp", "tsfc-")
	if e != nil {
		return "", e
	}
	if e = os.Chmod(d, 0o700); e != nil {
		os.Remove(d)
		return "", e
	}
	return d, nil
}
func UnixAPI(ctx context.Context, socket, path string, payload any) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, e := http.NewRequestWithContext(ctx, "PUT", "http://localhost"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 && response.StatusCode != 204 {
		return fmt.Errorf("Firecracker %s: %d %s", path, response.StatusCode, body)
	}
	return nil
}
