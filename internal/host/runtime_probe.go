package host

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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
		slog.WarnContext(ctx, "native probe supervisor launch failed", "class", nativeProbeFailureClass(err))
		os.Exit(112)
	}
	release()
	waitErr := <-waited
	if !probeExitedByCgroupKill(command, waitErr) {
		var status syscall.WaitStatus
		if command.ProcessState != nil {
			status, _ = command.ProcessState.Sys().(syscall.WaitStatus)
		}
		slog.WarnContext(ctx, "native probe supervisor kill confirmation failed", "class", nativeProbeFailureClass(waitErr), "status", status)
		os.Exit(112)
	}
	os.Exit(0)
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
