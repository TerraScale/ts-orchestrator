package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

const (
	sessionLockProbeEnvironment = "TS_VM_GUEST_SESSION_LOCK_PROBE"
	blockingFDProbeEnvironment  = "TS_VM_GUEST_BLOCKING_FD_PROBE"
	blockingFDOriginalEnv       = "TS_VM_GUEST_BLOCKING_FD_ORIGINAL"
)

func TestSessionLockExcludesAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.lock")
	fd, err := acquireSessionLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	command := exec.Command(os.Args[0], "-test.run=^TestSessionLockProbe$")
	command.Env = append(os.Environ(), sessionLockProbeEnvironment+"="+path)
	err = command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 23 {
		t.Fatalf("second process acquired the session lock: %v", err)
	}
}

func TestSessionLockProbe(t *testing.T) {
	path := os.Getenv(sessionLockProbeEnvironment)
	if path == "" {
		return
	}
	fd, err := acquireSessionLock(path)
	if err != nil {
		os.Exit(23)
	}
	_ = unix.Close(fd)
	os.Exit(0)
}

func TestSessionLockRejectsLinkedFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if fd, err := acquireSessionLock(symlink); err == nil {
		_ = unix.Close(fd)
		t.Fatal("session lock followed a symlink")
	}
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if fd, err := acquireSessionLock(target); err == nil {
		_ = unix.Close(fd)
		t.Fatal("session lock admitted a multiply linked file")
	}
}

func TestSessionLockRejectsUnexpectedModeOrContents(t *testing.T) {
	root := t.TempDir()
	permissive := filepath.Join(root, "permissive")
	if err := os.WriteFile(permissive, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if fd, err := acquireSessionLock(permissive); err == nil {
		_ = unix.Close(fd)
		t.Fatal("session lock admitted a permissive mode")
	}
	nonempty := filepath.Join(root, "nonempty")
	if err := os.WriteFile(nonempty, []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fd, err := acquireSessionLock(nonempty); err == nil {
		_ = unix.Close(fd)
		t.Fatal("session lock admitted unexpected contents")
	}
}

func TestGuestControlMemoryLimitLeavesRoomForTheGuest(t *testing.T) {
	const guestMemory = 256 << 20
	if guestControlMemoryLimit <= 0 || guestControlMemoryLimit > guestMemory/2 {
		t.Fatalf("guest-control memory limit %d does not fit the %d-byte guest", guestControlMemoryLimit, guestMemory)
	}
}

func TestServeSessionCancelsInheritedBlockingInput(t *testing.T) {
	input, heldInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer heldInput.Close()
	command, lockPath, ready := blockingFDCommand(t, "")
	command.Stdin = input
	command.Stdout = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	waitForBlockingFDReady(t, command, ready)
	stopBlockingFDProcess(t, command)
	assertSessionLockReleased(t, lockPath)
}

func TestServeSessionCancelsInheritedBlockingOutput(t *testing.T) {
	output, filledOutput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if _, err := unix.FcntlInt(filledOutput.Fd(), unix.F_SETPIPE_SZ, 4<<10); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(int(filledOutput.Fd()), true); err != nil {
		t.Fatal(err)
	}
	fill := make([]byte, 4<<10)
	for {
		if _, err := unix.Write(int(filledOutput.Fd()), fill); errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.SetNonblock(int(filledOutput.Fd()), false); err != nil {
		t.Fatal(err)
	}
	command, lockPath, ready := blockingFDCommand(t, "rejected")
	command.Stdin = strings.NewReader("")
	command.Stdout = filledOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = filledOutput.Close()
	waitForBlockingFDReady(t, command, ready)
	time.Sleep(100 * time.Millisecond)
	stopBlockingFDProcess(t, command)
	assertSessionLockReleased(t, lockPath)
}

func TestInheritedBlockingFDHelper(t *testing.T) {
	root := os.Getenv(blockingFDProbeEnvironment)
	if root == "" {
		return
	}
	lock, err := acquireSessionLock(filepath.Join(root, "session.lock"))
	if err != nil {
		os.Exit(31)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	_, _ = fmt.Fprintln(os.Stderr, "ready")
	config := vmguest.Config{
		InboxRoot:      filepath.Join(root, "inbox"),
		DataRoot:       filepath.Join(root, "data"),
		SeedPath:       filepath.Join(root, "seed.json"),
		SessionTimeout: 5 * time.Minute,
	}
	err = serveSession(ctx, os.Stdin, os.Stdout, os.Getenv(blockingFDOriginalEnv), config)
	_ = unix.Close(lock)
	if !errors.Is(err, context.Canceled) {
		os.Exit(32)
	}
	os.Exit(0)
}

func blockingFDCommand(t *testing.T, original string) (*exec.Cmd, string, *bufio.Reader) {
	t.Helper()
	root := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestInheritedBlockingFDHelper$")
	command.Env = append(os.Environ(), blockingFDProbeEnvironment+"="+root, blockingFDOriginalEnv+"="+original)
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	return command, filepath.Join(root, "session.lock"), bufio.NewReader(stderr)
}

func waitForBlockingFDReady(t *testing.T, command *exec.Cmd, ready *bufio.Reader) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		line, err := ready.ReadString('\n')
		if err == nil && line != "ready\n" {
			err = fmt.Errorf("unexpected helper marker %q", line)
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("blocking-FD helper did not become ready")
	}
}

func stopBlockingFDProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("blocking-FD helper exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("blocking inherited descriptor held the session after cancellation")
	}
}

func assertSessionLockReleased(t *testing.T, path string) {
	t.Helper()
	fd, err := acquireSessionLock(path)
	if err != nil {
		t.Fatalf("session lock remained held: %v", err)
	}
	_ = unix.Close(fd)
}
