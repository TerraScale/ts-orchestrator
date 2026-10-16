//go:build linux

package memberstatus

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func TestOwnedProcessFixture(t *testing.T) {
	mode := os.Getenv("TS_MEMBERSTATUS_FIXTURE")
	if mode == "" {
		return
	}
	ready := os.Getenv("TS_MEMBERSTATUS_READY")
	progress := os.Getenv("TS_MEMBERSTATUS_PROGRESS")
	switch mode {
	case "exit":
		os.Exit(0)
	case "leader", "escaping_leader":
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessFixture$")
		cmd.Env = append(os.Environ(), "TS_MEMBERSTATUS_FIXTURE=ignore")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if mode == "escaping_leader" {
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		}
		if e := cmd.Start(); e != nil {
			os.Exit(2)
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if info, e := os.Stat(ready); e == nil && info.Size() > 0 {
				os.Exit(0)
			}
			time.Sleep(time.Millisecond)
		}
		os.Exit(3)
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
	case "graceful":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		go func() { <-ch; os.Exit(0) }()
	}
	os.WriteFile(ready, []byte("ready"), 0600)
	if path := os.Getenv("TS_MEMBERSTATUS_ESCAPED_PID"); path != "" {
		os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600)
	}
	for {
		if progress != "" {
			f, e := os.OpenFile(progress, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if e == nil {
				f.WriteString("x")
				f.Close()
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func TestCommandRunnerReapedOutputOwnerIsNotPending(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "commands"), 0700); e != nil {
		t.Fatal(e)
	}
	ready, pidPath := filepath.Join(root, "ready"), filepath.Join(root, "escaped-pid")
	t.Setenv("TS_MEMBERSTATUS_FIXTURE", "escaping_leader")
	t.Setenv("TS_MEMBERSTATUS_READY", ready)
	t.Setenv("TS_MEMBERSTATUS_ESCAPED_PID", pidPath)
	t.Cleanup(func() {
		b, e := os.ReadFile(pidPath)
		if os.IsNotExist(e) {
			return
		}
		pid, parseErr := strconv.Atoi(string(b))
		if e != nil || parseErr != nil || pid <= 1 {
			t.Errorf("escaped fixture PID: %v %v", e, parseErr)
			return
		}
		if e = syscall.Kill(-pid, syscall.SIGKILL); e != nil && !errors.Is(e, syscall.ESRCH) {
			t.Error(e)
		}
		if e = firecracker.WaitProcessGroupQuiescent(pid, time.Second); e != nil {
			t.Error(e)
		}
	})
	runner := &CommandRunner{Root: root, Events: &EventLog{Path: filepath.Join(root, "events.json")}}
	started := time.Now()
	_, _, err := runner.Run(t.Context(), "escaped-output-owner", []string{os.Args[0], "-test.run=^TestOwnedProcessFixture$"}, 5*time.Second, []int{0})
	if !errors.Is(err, exec.ErrWaitDelay) || runner.Pending() || time.Since(started) > 6*time.Second {
		t.Fatal("reaped output owner was retained or wait was unbounded", err, runner.Pending(), time.Since(started))
	}
}
func processFixture(t *testing.T, mode, ready, progress string) *firecracker.Process {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessFixture$")
	cmd.Env = append(os.Environ(), "TS_MEMBERSTATUS_FIXTURE="+mode, "TS_MEMBERSTATUS_READY="+ready, "TS_MEMBERSTATUS_PROGRESS="+progress)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	p := &firecracker.Process{Cmd: cmd}
	t.Cleanup(func() {
		if !p.Reaped {
			if e := p.Stop(time.Second, true); e != nil {
				t.Errorf("fixture process cleanup: %v", e)
			}
		}
	})
	return p
}
func waitFixtureFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, e := os.Stat(path); e == nil && info.Size() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("signal fixture did not produce", path)
}
func TestOwnedProcessGroupCleanup(t *testing.T) {
	for _, kind := range []string{"graceful_term", "kill_ignored_term", "already_reaped", "idempotent", "surviving_child", "unrelated_group"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			ready := filepath.Join(dir, "ready")
			progress := filepath.Join(dir, "progress")
			mode := "ignore"
			if kind == "graceful_term" || kind == "unrelated_group" {
				mode = "graceful"
			}
			if kind == "already_reaped" {
				mode = "exit"
			}
			if kind == "surviving_child" {
				mode = "leader"
			}
			p := processFixture(t, mode, ready, progress)
			stopTimeout := time.Second
			if mode == "graceful" {
				// Race-instrumented Go processes pause for one second at exit.
				stopTimeout = 3 * time.Second
			}
			if kind == "already_reaped" {
				if e := p.Cmd.Wait(); e != nil {
					t.Fatal(e)
				}
				p.Reaped = true
				reject(t, p.Stop(time.Second, false), "reaped before group cleanup")
				return
			}
			waitFixtureFile(t, ready)
			if kind == "surviving_child" {
				waitFixtureFile(t, progress)
				done, e := p.WaitUnreaped(2 * time.Second)
				if e != nil || !done || p.Reaped {
					t.Fatal(done, e, p.Reaped)
				}
				if e = p.Stop(time.Second, false); e != nil {
					t.Fatal(e)
				}
				info, e := os.Stat(progress)
				if e != nil {
					t.Fatal(e)
				}
				size := info.Size()
				time.Sleep(100 * time.Millisecond)
				info, e = os.Stat(progress)
				if e != nil || size != info.Size() {
					t.Fatal("child survived stopped group", info, e)
				}
				return
			}
			if kind == "unrelated_group" {
				other := processFixture(t, "ignore", filepath.Join(dir, "other-ready"), "")
				waitFixtureFile(t, filepath.Join(dir, "other-ready"))
				if e := p.Stop(time.Second, false); e != nil {
					t.Fatal(e)
				}
				exited, e := other.Exited()
				if e != nil || exited || other.PID() == p.PID() {
					t.Fatal("stopped unrelated process group", exited, e)
				}
				return
			}
			if e := p.Stop(stopTimeout, false); e != nil {
				t.Fatal(e)
			}
			if !p.Reaped {
				t.Fatal("leader not reaped after confirmed group cleanup")
			}
			if kind == "graceful_term" && p.ExitCode != 0 {
				t.Fatal(p.ExitCode)
			}
			if kind == "kill_ignored_term" && p.ExitCode != -1 {
				t.Fatal(p.ExitCode)
			}
			if kind == "idempotent" {
				vm := &VM{Process: p, ProcessGroupStopped: true, Output: Object{"collected": true}, Events: &EventLog{Path: filepath.Join(dir, "events.json")}}
				for range 2 {
					if errs := vm.Stop(t.Context()); len(errs) != 0 {
						t.Fatal(errs)
					}
				}
			}
		})
	}
}
func TestUnquiescedVMRetainsResourcesUntilProvenStopped(t *testing.T) {
	q := nativeQualification(t, false)
	script.Write(t, q.Image, []byte("guest evidence"), 0600)
	q.SocketDir = filepath.Join(q.Root, "api-socket")
	os.Mkdir(q.SocketDir, 0700)
	ready := filepath.Join(q.Root, "vmm-ready")
	p := processFixture(t, "ignore", ready, "")
	waitFixtureFile(t, ready)
	q.VM = &VM{Process: p, ProcessGroupStopped: false, SocketDir: q.SocketDir}
	q.CleanupSocketDirectory()
	q.CleanupImage()
	if p.Reaped || !lexists(q.SocketDir) || !lexists(q.Image) || len(q.CleanupErrors) != 1 || !strings.Contains(q.CleanupErrors[0], "while Firecracker is live") {
		t.Fatal(fmt.Sprint(q.Summary()))
	}
	if e := p.Stop(time.Second, true); e != nil {
		t.Fatal(e)
	}
}
