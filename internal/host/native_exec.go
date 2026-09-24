//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const workloadHelperArgument = "--terrascale-internal-native-workload-helper"

type nativeExecRequest struct {
	Path      string           `json:"path"`
	Args      []string         `json:"args"`
	Env       []string         `json:"env"`
	Identity  WorkloadIdentity `json:"identity"`
	ParentPID int              `json:"parent_pid"`
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == workloadHelperArgument {
		runNativeWorkloadHelper()
	}
}

// The helper is part of the same binary. It is the only root userspace code
// launched into a role cgroup; it must drop all privilege before execing the
// artifact. Its status FD closes on successful exec and reports pre-exec errors.
func runNativeWorkloadHelper() {
	// prctl, credential changes, and exec must affect the same Linux task.
	// A Go scheduler migration here would silently undo the security boundary.
	runtime.LockOSThread()
	status := os.NewFile(4, "native-exec-status")
	fail := func(err error) {
		if status != nil {
			_, _ = io.WriteString(status, err.Error())
		}
		os.Exit(113)
	}
	requestFile := os.NewFile(3, "native-exec-request")
	if requestFile == nil || status == nil {
		fail(errors.New("native helper missing protocol files"))
	}
	data, err := io.ReadAll(io.LimitReader(requestFile, 128<<10+1))
	if err != nil || len(data) > 128<<10 {
		fail(errors.New("native helper request invalid"))
	}
	_ = requestFile.Close()
	var request nativeExecRequest
	if err := json.Unmarshal(data, &request); err != nil || request.Path == "" || len(request.Args) == 0 || request.ParentPID < 2 || request.Identity.UID == 0 || request.Identity.GID == 0 {
		fail(errors.New("native helper request malformed"))
	}
	// Move the status FD above target ExtraFiles before installing target FD 3.
	statusFD, err := unix.FcntlInt(status.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		fail(fmt.Errorf("native helper status fd: %w", err))
	}
	_ = status.Close()
	status = os.NewFile(uintptr(statusFD), "native-exec-status")
	for fd := 5; fd < 6; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			if err := unix.Dup3(fd, fd-2, 0); err != nil {
				fail(fmt.Errorf("native helper extra fd: %w", err))
			}
			_ = unix.Close(fd)
		}
	}
	if err := dropNativePrivileges(request.Identity, request.ParentPID); err != nil {
		fail(err)
	}
	if err := syscall.Exec(request.Path, request.Args, request.Env); err != nil {
		fail(fmt.Errorf("exec native workload: %w", err))
	}
}

func dropNativePrivileges(identity WorkloadIdentity, parentPID int) error {
	if os.Geteuid() != 0 || identity.UID == 0 || identity.GID == 0 {
		return errors.New("native helper requires root and nonzero workload identity")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set native no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear native ambient caps: %w", err)
	}
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return fmt.Errorf("read native cap bound: %w", err)
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || last < 0 || last > 255 {
		return errors.New("invalid native cap bound")
	}
	for capability := range last + 1 {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil {
			return fmt.Errorf("drop native bounding capability %d: %w", capability, err)
		}
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("clear native supplementary groups: %w", err)
	}
	if err := unix.Setresgid(int(identity.GID), int(identity.GID), int(identity.GID)); err != nil {
		return fmt.Errorf("drop native group: %w", err)
	}
	if err := unix.Setresuid(int(identity.UID), int(identity.UID), int(identity.UID)); err != nil {
		return fmt.Errorf("drop native user: %w", err)
	}
	// Credential transitions clear Pdeathsig. Rearm it and check for a parent
	// death between clone3 and this point before allowing target exec.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("rearm native parent death: %w", err)
	}
	if os.Getppid() != parentPID {
		return errors.New("native supervisor died before workload exec")
	}
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return fmt.Errorf("verify native capabilities: %w", err)
	}
	for _, capset := range caps {
		if capset.Effective != 0 || capset.Permitted != 0 || capset.Inheritable != 0 {
			return errors.New("native workload retained capabilities")
		}
	}
	return nil
}

// Starts a same-binary helper through clone3(CLONE_INTO_CGROUP), then waits
// until it has successfully execed the target. The returned command PID is the
// target PID because the helper uses execve rather than spawning again.
func launchNativeWorkload(ctx context.Context, target *exec.Cmd, cgroup *os.File, cgroupPath string, identity WorkloadIdentity) (*exec.Cmd, func(), <-chan error, error) {
	if !filepath.IsAbs(cgroupPath) || filepath.Clean(cgroupPath) != cgroupPath {
		return nil, nil, nil, errors.New("native launch requires an absolute cgroup path")
	}
	if err := requireNativeSupervisorKillCapability(); err != nil {
		return nil, nil, nil, err
	}
	request := nativeExecRequest{Path: target.Path, Args: target.Args, Env: target.Env, Identity: identity, ParentPID: os.Getpid()}
	data, err := json.Marshal(request)
	if err != nil || len(data) > 128<<10 {
		return nil, nil, nil, errors.New("native helper request too large")
	}
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer requestRead.Close()
	defer requestWrite.Close()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer statusRead.Close()
	defer statusWrite.Close()
	helper := exec.Command("/proc/self/exe", workloadHelperArgument)
	helper.Env = []string{}
	helper.Stdout, helper.Stderr = target.Stdout, target.Stderr
	helper.ExtraFiles = append([]*os.File{requestRead, statusWrite}, target.ExtraFiles...)
	helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	release, waited, err := startWorkloadOnLockedThreadWithCheck(helper, requireNativeSupervisorKillCapability)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(cause error) (*exec.Cmd, func(), <-chan error, error) {
		_ = helper.Process.Kill()
		release()
		<-waited
		return nil, nil, nil, cause
	}
	_ = requestRead.Close()
	_ = statusWrite.Close()
	deadline := time.Now().Add(10 * time.Second)
	if due, ok := ctx.Deadline(); ok && due.Before(deadline) {
		deadline = due
	}
	_ = requestWrite.SetWriteDeadline(deadline)
	_ = statusRead.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = requestWrite.Close(); _ = statusRead.Close() })
	defer stop()
	if _, err := requestWrite.Write(data); err != nil {
		return fail(fmt.Errorf("send native helper request: %w", err))
	}
	if err := requestWrite.Close(); err != nil {
		return fail(fmt.Errorf("close native helper request: %w", err))
	}
	status, err := io.ReadAll(io.LimitReader(statusRead, 4096))
	if err != nil {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		return fail(fmt.Errorf("native helper exec status: %w", err))
	}
	if len(status) != 0 {
		return fail(fmt.Errorf("native helper failed before target exec: %s", status))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := verifyNativeExec(helper.Process.Pid, cgroupPath, identity); err != nil {
		return fail(err)
	}
	return helper, release, waited, nil
}

// Pipe EOF alone also occurs if the helper dies before exec. Inspect the live
// PID after EOF before admitting a role; a zombie still has a /proc stat entry.
func verifyNativeExec(pid int, cgroupPath string, identity WorkloadIdentity) error {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return fmt.Errorf("native target exited before verification: %w", err)
	}
	closing := bytes.LastIndexByte(stat, ')')
	if closing < 0 {
		return errors.New("native target has invalid process status")
	}
	fields := strings.Fields(string(stat[closing+1:]))
	if len(fields) <= 19 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return errors.New("native target exited before verification")
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(cmdline) == 0 || bytes.Contains(cmdline, []byte(workloadHelperArgument)) {
		return errors.New("native helper did not exec the target")
	}
	if err := probeNativeTargetIdentity(pid, identity); err != nil {
		return err
	}
	contained, err := nativeCgroupContainsPID(cgroupPath, pid)
	if err != nil {
		return err
	}
	if !contained {
		return errors.New("native target escaped its role cgroup")
	}
	return nil
}

func nativeCgroupContainsPID(path string, pid int) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, fmt.Errorf("read native cgroup membership: %w", err)
	}
	want := strconv.Itoa(pid)
	for field := range strings.FieldsSeq(string(data)) {
		if field == want {
			return true, nil
		}
	}
	return false, nil
}
