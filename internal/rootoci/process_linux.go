package rootoci

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"golang.org/x/sys/unix"
)

// ProcessWitness retains kernel process and executable identities across guards.
type ProcessWitness struct {
	mu         sync.Mutex
	pidfd      int
	executable *os.File
	identity   processIdentity
	closed     bool
}

type processIdentity struct {
	peer       nativerootoci.Peer
	parent     int
	start      uint64
	cgroup     string
	executable unix.Stat_t
}

func CaptureProcess(pid int) (*ProcessWitness, error) {
	if pid < 2 {
		return nil, ErrUnauthorized
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, ErrUnauthorized
	}
	witness := &ProcessWitness{pidfd: fd}
	identity, executable, err := observeProcess(pid)
	if err != nil {
		_ = unix.Close(fd)
		return nil, ErrUnauthorized
	}
	witness.identity, witness.executable = identity, executable
	if err := witness.Verify(); err != nil {
		_ = witness.Close()
		return nil, err
	}
	return witness, nil
}

func (witness *ProcessWitness) Peer() nativerootoci.Peer { return witness.identity.peer }
func (witness *ProcessWitness) ParentPID() int           { return witness.identity.parent }
func (witness *ProcessWitness) KernelStart() uint64      { return witness.identity.start }
func (witness *ProcessWitness) Cgroup() string           { return witness.identity.cgroup }
func (witness *ProcessWitness) ExecutablePath() string {
	return fmt.Sprintf("/proc/%d/exe", witness.identity.peer.PID)
}
func (witness *ProcessWitness) Binding() string {
	id := witness.identity
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d:%d:%d:%s:%d:%d",
		id.peer.PID, id.peer.UID, id.peer.GID, id.parent, id.start, id.cgroup, id.executable.Dev, id.executable.Ino))))
}

func (witness *ProcessWitness) Verify() error {
	if witness == nil {
		return ErrUnauthorized
	}
	witness.mu.Lock()
	defer witness.mu.Unlock()
	if witness.closed || unix.PidfdSendSignal(witness.pidfd, 0, nil, 0) != nil {
		return ErrUnauthorized
	}
	current, executable, err := observeProcess(witness.identity.peer.PID)
	if err != nil {
		return ErrUnauthorized
	}
	defer executable.Close()
	if current != witness.identity {
		return ErrUnauthorized
	}
	var pinned unix.Stat_t
	if unix.Fstat(int(witness.executable.Fd()), &pinned) != nil {
		return ErrUnauthorized
	}
	pinned.Atim = unix.Timespec{}
	if pinned != current.executable {
		return ErrUnauthorized
	}
	return nil
}

func (witness *ProcessWitness) Close() error {
	if witness == nil {
		return nil
	}
	witness.mu.Lock()
	defer witness.mu.Unlock()
	if witness.closed {
		return nil
	}
	witness.closed = true
	_ = unix.Close(witness.pidfd)
	return witness.executable.Close()
}

func observeProcess(pid int) (processIdentity, *os.File, error) {
	var identity processIdentity
	identity.peer.PID = pid
	base := fmt.Sprintf("/proc/%d/", pid)
	var err error
	identity.start, identity.parent, identity.cgroup, err = processKernelIdentity(pid)
	if err != nil {
		return identity, nil, err
	}
	status, err := os.ReadFile(base + "status")
	if err != nil {
		return identity, nil, err
	}
	var uidFound, gidFound bool
	for line := range strings.SplitSeq(string(status), "\n") {
		values := strings.Fields(line)
		if len(values) != 5 {
			continue
		}
		if values[0] != "Uid:" && values[0] != "Gid:" {
			continue
		}
		value, err := strconv.ParseUint(values[2], 10, 32)
		if err != nil {
			return identity, nil, err
		}
		if values[0] == "Uid:" {
			identity.peer.UID, uidFound = uint32(value), true
		} else {
			identity.peer.GID, gidFound = uint32(value), true
		}
	}
	if !uidFound || !gidFound {
		return identity, nil, ErrUnauthorized
	}
	executable, err := os.Open(base + "exe")
	if err != nil {
		return identity, nil, err
	}
	if unix.Fstat(int(executable.Fd()), &identity.executable) != nil ||
		identity.executable.Mode&unix.S_IFMT != unix.S_IFREG || identity.executable.Uid != 0 ||
		identity.executable.Gid != 0 || identity.executable.Mode&0o6022 != 0 || identity.executable.Mode&0o111 == 0 ||
		identity.executable.Nlink != 1 {
		_ = executable.Close()
		return identity, nil, ErrUnauthorized
	}
	// Access time changes when the verifier reads the pinned executable.
	identity.executable.Atim = unix.Timespec{}
	return identity, executable, nil
}

func processKernelIdentity(pid int) (uint64, int, string, error) {
	base := fmt.Sprintf("/proc/%d/", pid)
	stat, err := os.ReadFile(base + "stat")
	if err != nil {
		return 0, 0, "", ErrUnauthorized
	}
	_, suffix, ok := strings.CutLast(string(stat), ") ")
	fields := strings.Fields(suffix)
	if !ok || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, 0, "", ErrUnauthorized
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, "", ErrUnauthorized
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, 0, "", ErrUnauthorized
	}
	cgroup, err := os.ReadFile(base + "cgroup")
	if err != nil || len(cgroup) == 0 || len(cgroup) > 65536 {
		return 0, 0, "", ErrUnauthorized
	}
	return start, parent, string(cgroup), nil
}
