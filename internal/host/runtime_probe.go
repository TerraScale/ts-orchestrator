package host

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
)

const (
	probeSupervisorArgument = "--terrascale-internal-native-probe-supervisor"
	probeChildArgument      = "--terrascale-internal-native-runtime-probe"
	probeNonceEnv           = "TERRASCALE_INTERNAL_NATIVE_PROBE_NONCE"
	probeUIDEnv             = "TERRASCALE_INTERNAL_NATIVE_PROBE_UID"
	probeGIDEnv             = "TERRASCALE_INTERNAL_NATIVE_PROBE_GID"
)

// The probe re-executes this binary twice. Only the target child can send the
// acknowledgment proving that a clone3 child reached userspace.
func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case probeSupervisorArgument:
		runProbeSupervisor()
	case probeChildArgument:
		runProbeChild()
	}
}

func runProbeChild() {
	nonce, ok := os.LookupEnv(probeNonceEnv)
	if !ok || len(nonce) != 32 {
		os.Exit(111)
	}
	ack := os.NewFile(3, "runtime-probe-ack")
	if ack == nil {
		os.Exit(111)
	}
	var message [36]byte
	copy(message[:32], nonce)
	binary.LittleEndian.PutUint32(message[32:], uint32(os.Getpid()))
	if written, err := ack.Write(message[:]); err != nil || written != len(message) {
		os.Exit(111)
	}
	if err := ack.Close(); err != nil {
		os.Exit(111)
	}
	for {
		time.Sleep(time.Hour)
	}
}

// The supervisor alone owns the target cgroup FD while clone3 may block before
// exec. Killing this process on timeout also kills its target via Pdeathsig.
func runProbeSupervisor() {
	nonce, ok := os.LookupEnv(probeNonceEnv)
	if !ok || len(nonce) != 32 {
		os.Exit(111)
	}
	uid, uidErr := strconv.ParseUint(os.Getenv(probeUIDEnv), 10, 32)
	gid, gidErr := strconv.ParseUint(os.Getenv(probeGIDEnv), 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		os.Exit(111)
	}
	identity := WorkloadIdentity{UID: uint32(uid), GID: uint32(gid)}
	cgroup := os.NewFile(3, "runtime-probe-cgroup")
	ack := os.NewFile(4, "runtime-probe-ack")
	if cgroup == nil || ack == nil {
		os.Exit(111)
	}
	// os.NewFile's label is not the kernel path of an inherited FD. Read its
	// actual cgroup path so post-exec membership verification cannot silently
	// check a relative label instead of the role cgroup.
	cgroupPath, err := os.Readlink("/proc/self/fd/3")
	if err != nil || !strings.HasPrefix(cgroupPath, "/sys/fs/cgroup/") || filepath.Clean(cgroupPath) != cgroupPath {
		os.Exit(112)
	}
	target := exec.Command("/proc/self/exe", probeChildArgument)
	target.Env = []string{probeNonceEnv + "=" + nonce}
	target.ExtraFiles = []*os.File{ack}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command, release, waited, err := launchNativeWorkload(ctx, target, cgroup, cgroupPath, identity)
	_ = ack.Close()
	_ = cgroup.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "native probe supervisor launch failed class=%s\n", nativeProbeFailureClass(err))
		os.Exit(112)
	}
	release()
	waitErr := <-waited
	if !probeExitedByCgroupKill(command, waitErr) {
		var status syscall.WaitStatus
		if command.ProcessState != nil {
			status, _ = command.ProcessState.Sys().(syscall.WaitStatus)
		}
		fmt.Fprintf(os.Stderr, "native probe supervisor kill confirmation failed class=%s status=%d\n", nativeProbeFailureClass(waitErr), status)
		os.Exit(112)
	}
	os.Exit(0)
}

// ProbeNativeRuntime verifies the kernel and cgroup execution contract before a
// host acquires its signed session. runnerStateRoot must be the same fully scoped
// state path later passed to NewProcessRunner. The probe uses two executions in
// the same role name, separated by cgroup.kill and cgroup recreation.
func ProbeNativeRuntime(ctx context.Context, runnerStateRoot string, identity WorkloadIdentity) error {
	if ctx == nil || !filepath.IsAbs(runnerStateRoot) {
		return errors.New("native runtime probe requires a context and absolute runner state root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateWorkloadIdentity(identity); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := nativeCgroupRoot(runnerStateRoot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("native runtime probe requires writable cgroup v2: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return fmt.Errorf("native runtime probe requires cgroup v2: %w", err)
	}
	var roleID [8]byte
	if _, err := rand.Read(roleID[:]); err != nil {
		return fmt.Errorf("native runtime probe random role: %w", err)
	}
	rolePath := filepath.Join(root, "runtime-probe-"+hex.EncodeToString(roleID[:]))
	for attempt := range 2 {
		if err := probeNativeExecution(ctx, rolePath, identity); err != nil {
			return fmt.Errorf("native runtime probe execution %d: %w", attempt+1, err)
		}
	}
	return nil
}

func probeNativeExecution(ctx context.Context, rolePath string, identity WorkloadIdentity) (resultErr error) {
	if err := os.Mkdir(rolePath, 0700); err != nil {
		return fmt.Errorf("create probe cgroup: %w", err)
	}
	var supervisor *exec.Cmd
	locked := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sealErr := sealCgroup(cleanupCtx, rolePath)
		if sealErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("seal probe cgroup: %w", sealErr))
		}
		if supervisor != nil && supervisor.Process != nil {
			if resultErr != nil {
				_ = supervisor.Process.Kill()
			}
			waitCtx, stopWait := context.WithTimeout(context.Background(), 2*time.Second)
			status, err := waitProbeSupervisor(waitCtx, supervisor.Process.Pid)
			stopWait()
			if err != nil {
				_ = supervisor.Process.Kill()
				reapCtx, stopReap := context.WithTimeout(context.Background(), 2*time.Second)
				_, reapErr := waitProbeSupervisor(reapCtx, supervisor.Process.Pid)
				stopReap()
				resultErr = errors.Join(resultErr, fmt.Errorf("probe supervisor did not finish after cgroup seal: %w", err), reapErr)
			} else if resultErr == nil && (!status.Exited() || status.ExitStatus() != 0) {
				resultErr = fmt.Errorf("probe supervisor did not confirm target SIGKILL: %v", status)
			}
			_ = supervisor.Process.Release()
		}
		if locked {
			runtime.UnlockOSThread()
		}
		if resultErr == nil {
			resultErr = ctx.Err()
		}
	}()
	cgroup, err := os.Open(rolePath)
	if err != nil {
		return fmt.Errorf("open probe cgroup: %w", err)
	}
	defer cgroup.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create probe acknowledgment pipe: %w", err)
	}
	defer reader.Close()
	defer writer.Close()
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return fmt.Errorf("native runtime probe random nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	supervisor = exec.Command("/proc/self/exe", probeSupervisorArgument)
	supervisor.Env = []string{probeNonceEnv + "=" + nonce, probeUIDEnv + "=" + strconv.FormatUint(uint64(identity.UID), 10), probeGIDEnv + "=" + strconv.FormatUint(uint64(identity.GID), 10)}
	supervisor.Stderr = os.Stderr
	supervisor.ExtraFiles = []*os.File{cgroup, writer}
	supervisor.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// Keep the creator thread alive until the supervisor has been reaped.
	runtime.LockOSThread()
	locked = true
	if err := supervisor.Start(); err != nil {
		return fmt.Errorf("start native probe supervisor: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close parent probe pipe writer: %w", err)
	}
	stopRead := context.AfterFunc(ctx, func() { _ = reader.Close() })
	defer stopRead()
	ack := make([]byte, 36)
	if _, err := io.ReadFull(reader, ack); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("probe child did not execute userspace acknowledgment: %w", err)
	}
	if string(ack[:32]) != nonce {
		return errors.New("probe child userspace acknowledgment mismatch")
	}
	pid := int(binary.LittleEndian.Uint32(ack[32:]))
	if pid < 2 {
		return errors.New("probe child reported an invalid PID")
	}
	contained, err := probeCgroupContainsOnlyPID(rolePath, pid)
	if err != nil {
		return err
	}
	if !contained {
		return errors.New("probe child is not the sole process in its cgroup")
	}
	if err := probeNativeTargetIdentity(pid, identity); err != nil {
		return err
	}
	populated, err := cgroupPopulated(rolePath)
	if err != nil {
		return fmt.Errorf("observe probe cgroup: %w", err)
	}
	if !populated {
		return errors.New("probe cgroup was not populated after child userspace execution")
	}
	return ctx.Err()
}

// Poll without a Wait goroutine so a stuck kernel task cannot leave an
// unmanaged Go goroutine after the startup deadline. A successful call reaps
// the supervisor; timeout always fails host admission.
func waitProbeSupervisor(ctx context.Context, pid int) (syscall.WaitStatus, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if waited == pid {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func probeCgroupContainsOnlyPID(path string, pid int) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, fmt.Errorf("read probe cgroup membership: %w", err)
	}
	return strings.TrimSpace(string(data)) == strconv.Itoa(pid), nil
}

func probeNativeTargetIdentity(pid int, identity WorkloadIdentity) error {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return fmt.Errorf("read native probe target status: %w", err)
	}
	wantedUID := strconv.FormatUint(uint64(identity.UID), 10)
	wantedGID := strconv.FormatUint(uint64(identity.GID), 10)
	checks := map[string]func([]string) bool{
		"Uid:": func(values []string) bool {
			return len(values) == 4 && values[0] == wantedUID && values[1] == wantedUID && values[2] == wantedUID && values[3] == wantedUID
		},
		"Gid:": func(values []string) bool {
			return len(values) == 4 && values[0] == wantedGID && values[1] == wantedGID && values[2] == wantedGID && values[3] == wantedGID
		},
		"Groups:":     func(values []string) bool { return len(values) == 0 },
		"CapInh:":     func(values []string) bool { return len(values) == 1 && values[0] == "0000000000000000" },
		"CapPrm:":     func(values []string) bool { return len(values) == 1 && values[0] == "0000000000000000" },
		"CapEff:":     func(values []string) bool { return len(values) == 1 && values[0] == "0000000000000000" },
		"CapBnd:":     func(values []string) bool { return len(values) == 1 && values[0] == "0000000000000000" },
		"CapAmb:":     func(values []string) bool { return len(values) == 1 && values[0] == "0000000000000000" },
		"NoNewPrivs:": func(values []string) bool { return len(values) == 1 && values[0] == "1" },
	}
	seen := make(map[string]bool, len(checks))
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		check, ok := checks[fields[0]]
		if ok {
			if !check(fields[1:]) {
				return fmt.Errorf("native probe target has unsafe %s status", fields[0])
			}
			seen[fields[0]] = true
		}
	}
	if len(seen) != len(checks) {
		return errors.New("native probe target status lacks credential or privilege proof")
	}
	return nil
}

func probeExitedByCgroupKill(command *exec.Cmd, waitErr error) bool {
	if waitErr == nil || command == nil || command.ProcessState == nil {
		return false
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func nativeProbeFailureClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, os.ErrNotExist):
		return "not_exist"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, syscall.EBUSY):
		return "busy"
	default:
		return "other"
	}
}
