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
const maxNativeTargetExtraFiles = 1
const nativeIOPriorityNeutral = 2<<13 | 4 // Best effort, ordinary priority.

type nativeExecRequest struct {
	Path      string           `json:"path"`
	Args      []string         `json:"args"`
	Env       []string         `json:"env"`
	Identity  WorkloadIdentity `json:"identity"`
	ParentPID int              `json:"parent_pid"`
	// A nil count is an invalid protocol request, including for zero files.
	ExtraFileCount *int `json:"extra_file_count"`
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
	if err := json.Unmarshal(data, &request); err != nil || !validNativeExecRequest(request) {
		fail(errors.New("native helper request malformed"))
	}
	// Move the status FD above target ExtraFiles before installing target FD 3.
	statusFD, err := unix.FcntlInt(status.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		fail(fmt.Errorf("native helper status fd: %w", err))
	}
	_ = status.Close()
	status = os.NewFile(uintptr(statusFD), "native-exec-status")
	if err := remapNativeTargetExtraFiles(*request.ExtraFileCount); err != nil {
		fail(err)
	}
	if err := dropNativePrivileges(request.Identity, request.ParentPID); err != nil {
		fail(err)
	}
	if err := syscall.Exec(request.Path, request.Args, request.Env); err != nil {
		fail(fmt.Errorf("exec native workload: %w", err))
	}
}

func validNativeExecRequest(request nativeExecRequest) bool {
	return request.Path != "" && len(request.Args) != 0 && request.ParentPID >= 2 &&
		request.Identity.UID != 0 && request.Identity.GID != 0 && request.ExtraFileCount != nil &&
		validateNativeTargetExtraFileCount(*request.ExtraFileCount) == nil
}

func validateNativeTargetExtraFileCount(count int) error {
	if count < 0 || count > maxNativeTargetExtraFiles {
		return errors.New("native target supports at most one inherited file")
	}
	return nil
}

// The helper's FDs 3 and 4 carry the request and status pipes. os/exec places
// the only optional target file at FD 5. A zero-file launch must leave FD 5
// alone: the Go runtime can allocate its epoll descriptor there during init.
func remapNativeTargetExtraFiles(count int) error {
	if err := validateNativeTargetExtraFileCount(count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if _, err := unix.FcntlInt(5, unix.F_GETFD, 0); err != nil {
		return fmt.Errorf("native helper missing inherited target fd 5: %w", err)
	}
	if err := unix.Dup3(5, 3, 0); err != nil {
		return fmt.Errorf("native helper target fd 3: %w", err)
	}
	if err := unix.Close(5); err != nil {
		return fmt.Errorf("close native helper inherited target fd 5: %w", err)
	}
	return nil
}

func dropNativePrivileges(identity WorkloadIdentity, parentPID int) error {
	if os.Geteuid() != 0 || identity.UID == 0 || identity.GID == 0 {
		return errors.New("native helper requires root and nonzero workload identity")
	}
	// The helper inherits the protected supervisor's scheduling attributes.
	// Reset them while root before the irreversible UID and capability drop.
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, 0); err != nil {
		return fmt.Errorf("reset native workload nice: %w", err)
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("0"), 0); err != nil {
		return fmt.Errorf("reset native workload OOM score adjustment: %w", err)
	}
	if err := setNativeIOPriority(0, nativeIOPriorityNeutral); err != nil {
		return fmt.Errorf("reset native workload I/O priority: %w", err)
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
	var inherited [2]unix.CapUserData
	inheritedHeader := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&inheritedHeader, &inherited[0]); err != nil {
		return fmt.Errorf("inspect native inheritable capabilities: %w", err)
	}
	for index := range inherited {
		inherited[index].Inheritable = 0
	}
	if err := unix.Capset(&inheritedHeader, &inherited[0]); err != nil {
		return fmt.Errorf("clear native inheritable capabilities: %w", err)
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
	if err := validateNativeTargetExtraFileCount(len(target.ExtraFiles)); err != nil {
		return nil, nil, nil, err
	}
	if err := requireNativeSupervisorKillCapability(); err != nil {
		return nil, nil, nil, err
	}
	request := nativeExecRequest{Path: target.Path, Args: target.Args, Env: target.Env, Identity: identity, ParentPID: os.Getpid(), ExtraFileCount: new(len(target.ExtraFiles))}
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
	nice, err := strconv.Atoi(fields[17]) // /proc/PID/stat field 20.
	if err != nil || nice < 0 {
		return errors.New("native target retained protected supervisor nice")
	}
	oomScore, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "oom_score_adj"))
	if err != nil {
		return fmt.Errorf("inspect native target OOM score adjustment: %w", err)
	}
	adjustment, err := strconv.Atoi(strings.TrimSpace(string(oomScore)))
	if err != nil || adjustment < 0 {
		return errors.New("native target retained protected supervisor OOM score adjustment")
	}
	ioPriority, err := readNativeIOPriority(pid)
	if err != nil {
		return fmt.Errorf("inspect native target I/O priority: %w", err)
	}
	if ioPriority != 0 && (ioPriority>>13 != 2 || ioPriority&((1<<13)-1) < 4) && ioPriority>>13 != 3 {
		return errors.New("native target retained protected supervisor I/O priority")
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

func setNativeIOPriority(pid, priority int) error {
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(pid), uintptr(priority))
	if errno != 0 {
		return errno
	}
	return nil
}

func readNativeIOPriority(pid int) (int, error) {
	value, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, 1, uintptr(pid), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(value), nil
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
