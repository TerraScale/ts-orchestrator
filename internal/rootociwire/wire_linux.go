// Package rootociwire contains only kernel transport authentication and framing.
// Domain packages expose their own finite typed methods, never a raw RPC API.
package rootociwire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const SocketPath = "/run/terrascale-orchestrator/oci.sock"
const MaxFrameBytes = 8 << 20

var ErrRejected = errors.New("root OCI transport rejected")

type Peer struct {
	PID      int
	UID, GID uint32
}

func PeerCredential(connection *net.UnixConn) (Peer, error) {
	if connection == nil {
		return Peer{}, ErrRejected
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, ErrRejected
	}
	var credentials *unix.Ucred
	var socketErr error
	if raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil ||
		socketErr != nil || credentials == nil || credentials.Pid < 2 {
		return Peer{}, ErrRejected
	}
	return Peer{PID: int(credentials.Pid), UID: credentials.Uid, GID: credentials.Gid}, nil
}

// Pin retains the first fixed-socket root process; errors never reset it.
type Pin struct {
	mu      sync.Mutex
	binding string
	closed  bool
}

func (pin *Pin) Verify(connection *net.UnixConn) error {
	if pin == nil {
		return ErrRejected
	}
	peer, err := PeerCredential(connection)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		return ErrRejected
	}
	for _, path := range []string{"/run", "/run/terrascale-orchestrator"} {
		var stat unix.Stat_t
		if unix.Lstat(path, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
			return ErrRejected
		}
	}
	var socket unix.Stat_t
	if unix.Lstat(SocketPath, &socket) != nil || socket.Uid != 0 || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0o7777 != 0o660 {
		return ErrRejected
	}
	start, parent, cgroup, err := KernelIdentity(peer.PID)
	if err != nil {
		return ErrRejected
	}
	binding := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s:%d:%d:%d", peer.PID, start, cgroup, parent, socket.Dev, socket.Ino))))
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.closed {
		return ErrRejected
	}
	if pin.binding == "" {
		pin.binding = binding
	}
	if pin.binding != binding {
		return ErrRejected
	}
	return nil
}

func (pin *Pin) Binding() string {
	if pin == nil {
		return ""
	}
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.closed {
		return ""
	}
	return pin.binding
}

func (pin *Pin) Close() error {
	if pin == nil {
		return nil
	}
	pin.mu.Lock()
	defer pin.mu.Unlock()
	pin.closed = true
	return nil
}

// KernelIdentity is an observation, not an admission proof or authorization.
func KernelIdentity(pid int) (uint64, int, string, error) {
	if pid < 2 {
		return 0, 0, "", ErrRejected
	}
	base := fmt.Sprintf("/proc/%d/", pid)
	stat, err := os.ReadFile(base + "stat")
	if err != nil {
		return 0, 0, "", ErrRejected
	}
	_, suffix, ok := strings.CutLast(string(stat), ") ")
	fields := strings.Fields(suffix)
	if !ok || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, 0, "", ErrRejected
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, "", ErrRejected
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, 0, "", ErrRejected
	}
	cgroup, err := os.ReadFile(base + "cgroup")
	if err != nil || len(cgroup) == 0 || len(cgroup) > 65536 {
		return 0, 0, "", ErrRejected
	}
	return start, parent, string(cgroup), nil
}

func ReadBoundedFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || maximum == 0 || length > maximum {
		return nil, ErrRejected
	}
	frame := make([]byte, length)
	_, err := io.ReadFull(reader, frame)
	return frame, err
}

func WriteBoundedFrame(writer io.Writer, frame []byte, maximum uint32) error {
	if len(frame) == 0 || maximum == 0 || uint64(len(frame)) > uint64(maximum) {
		return ErrRejected
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeAll(writer, frame)
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
