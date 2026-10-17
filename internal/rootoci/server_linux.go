package rootoci

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"golang.org/x/sys/unix"
)

type listenerHandle struct {
	once      sync.Once
	cancel    context.CancelFunc
	listener  *net.UnixListener
	done      chan struct{}
	directory int
	lock      int
	socket    unix.Stat_t
}

type dispatcher interface {
	validRequest(wireRequest) bool
	dispatch(context.Context, Call, wireRequest) (any, error)
}

// Listen belongs to the existing root managed runtime, before admission children.
func Listen(ctx context.Context, service *Service, authorize Authorize, controllerGID uint32) (io.Closer, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || service == nil || !validBackends(service.backends) || authorize == nil || controllerGID == 0 {
		return nil, ErrUnauthorized
	}
	return listen(ctx, service, authorize, controllerGID)
}

func listen(ctx context.Context, service dispatcher, authorize Authorize, controllerGID uint32) (io.Closer, error) {
	directory, err := openSocketDirectory()
	if err != nil {
		return nil, err
	}
	lock, err := unix.Openat(directory, "oci.sock.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = unix.Close(directory)
		return nil, ErrUnavailable
	}
	fail := func() { _ = unix.Close(lock); _ = unix.Close(directory) }
	var lockStat unix.Stat_t
	if unix.Fstat(lock, &lockStat) != nil || lockStat.Uid != 0 || lockStat.Gid != 0 || lockStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		lockStat.Mode&0o7777 != 0o600 || lockStat.Nlink != 1 || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		fail()
		return nil, ErrUnauthorized
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(directory, "oci.sock", &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Uid != 0 || existing.Gid != controllerGID || existing.Mode&unix.S_IFMT != unix.S_IFSOCK {
			fail()
			return nil, ErrUnauthorized
		}
		if unix.Unlinkat(directory, "oci.sock", 0) != nil {
			fail()
			return nil, ErrUnavailable
		}
	} else if !errors.Is(err, unix.ENOENT) {
		fail()
		return nil, ErrUnavailable
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if err != nil {
		fail()
		return nil, ErrUnavailable
	}
	listener.SetUnlinkOnClose(false)
	if unix.Fchownat(directory, "oci.sock", 0, int(controllerGID), unix.AT_SYMLINK_NOFOLLOW) != nil ||
		unix.Fchmodat(directory, "oci.sock", 0o660, 0) != nil {
		_ = listener.Close()
		_ = unix.Unlinkat(directory, "oci.sock", 0)
		fail()
		return nil, ErrUnavailable
	}
	var socket unix.Stat_t
	if unix.Fstatat(directory, "oci.sock", &socket, unix.AT_SYMLINK_NOFOLLOW) != nil || socket.Uid != 0 || socket.Gid != controllerGID ||
		socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0o7777 != 0o660 {
		_ = listener.Close()
		fail()
		return nil, ErrUnauthorized
	}
	serving, cancel := context.WithCancel(ctx)
	handle := &listenerHandle{cancel: cancel, listener: listener, done: make(chan struct{}), directory: directory, lock: lock, socket: socket}
	go func() { defer close(handle.done); serve(serving, listener, service, authorize) }()
	context.AfterFunc(ctx, func() { _ = handle.Close() })
	return handle, nil
}

func (handle *listenerHandle) Close() error {
	handle.once.Do(func() {
		handle.cancel()
		_ = handle.listener.Close()
		<-handle.done
		var current unix.Stat_t
		if unix.Fstatat(handle.directory, "oci.sock", &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			current.Dev == handle.socket.Dev && current.Ino == handle.socket.Ino {
			_ = unix.Unlinkat(handle.directory, "oci.sock", 0)
		}
		_ = unix.Close(handle.lock)
		_ = unix.Close(handle.directory)
	})
	return nil
}

func openSocketDirectory() (int, error) {
	// Resolve every component without following links or accepting writable ancestors.
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	for _, name := range []string{"run", filepath.Base(filepath.Dir(SocketPath))} {
		fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && name != "run" {
			if unix.Mkdirat(root, name, 0o755) == nil {
				fd, err = unix.Openat(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(root)
		if err != nil {
			return -1, ErrUnavailable
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			_ = unix.Close(fd)
			return -1, ErrUnauthorized
		}
		root = fd
	}
	return root, nil
}

func serve(ctx context.Context, listener *net.UnixListener, service dispatcher, authorize Authorize) {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, 2)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots }(); serveConnection(ctx, connection, service, authorize) })
		default:
			_ = connection.Close()
		}
	}
}

func serveConnection(parent context.Context, connection *net.UnixConn, service dispatcher, authorize Authorize) {
	defer connection.Close()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return
	}
	peer, err := nativerootoci.PeerCredential(connection)
	if err != nil {
		return
	}
	witness, err := CaptureProcess(peer.PID)
	if err != nil {
		return
	}
	defer witness.Close()
	if witness.Peer() != peer {
		return
	}
	frame, err := nativerootoci.ReadBoundedFrame(connection, maxFrameBytes)
	if err != nil {
		return
	}
	var request wireRequest
	if json.Unmarshal(frame, &request, json.RejectUnknownMembers(true)) != nil || request.Version != 1 || !validExpectations(request.Expected) {
		writeResponse(connection, wireResponse{Version: 1, Status: "invalid"})
		return
	}
	if !service.validRequest(request) {
		writeResponse(connection, wireResponse{Version: 1, Operation: request.Operation, Status: "invalid"})
		return
	}
	lease, err := authorize(ctx, peer, request.Operation)
	if err != nil || !validLease(lease) || witness.Verify() != nil {
		writeResponse(connection, wireResponse{Version: 1, Operation: request.Operation, Status: "unauthorized"})
		return
	}
	if lease.Deadline.Before(deadline) {
		deadline = lease.Deadline
	}
	bounded, boundedCancel := context.WithDeadline(ctx, deadline)
	defer boundedCancel()
	revoke := context.AfterFunc(lease.Context, boundedCancel)
	defer revoke()
	if connection.SetDeadline(deadline) != nil {
		return
	}
	stopBounded := context.AfterFunc(bounded, func() { _ = connection.Close() })
	defer stopBounded()
	join, err := witness.watchExit(bounded, boundedCancel)
	if err != nil {
		return
	}
	defer func() { boundedCancel(); <-join }()
	call := Call{state: &callState{ctx: bounded, expected: request.Expected, operation: request.Operation, witness: witness, authorize: authorize, lease: lease, deadline: deadline, sessionBinding: sessionBinding(witness, lease)}}
	if err := call.Guard(bounded); err != nil {
		writeResponse(connection, wireResponse{Version: 1, Operation: request.Operation, Status: "unauthorized"})
		return
	}
	result, err := service.dispatch(bounded, call, request)
	response := wireResponse{Version: 1, Operation: request.Operation, Status: errorStatus(err)}
	if err == nil {
		if call.Guard(bounded) != nil {
			response.Status = "unauthorized"
		} else {
			response.Payload, err = json.Marshal(result)
			if err != nil {
				response.Status = "unavailable"
				response.Payload = nil
			}
		}
	}
	writeResponse(connection, response)
}

func writeResponse(connection *net.UnixConn, response wireResponse) {
	wire, err := json.Marshal(response)
	if err != nil || len(wire) > maxFrameBytes {
		wire, _ = json.Marshal(wireResponse{Version: 1, Operation: response.Operation, Status: "unavailable"})
	}
	_ = nativerootoci.WriteBoundedFrame(connection, wire, maxFrameBytes)
}

// pidfd signals process death; eventfd joins the watcher when the call finishes.
func (witness *ProcessWitness) watchExit(ctx context.Context, cancel context.CancelFunc) (<-chan struct{}, error) {
	event, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, ErrUnauthorized
	}
	pid, err := unix.FcntlInt(uintptr(witness.pidfd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(event)
		return nil, ErrUnauthorized
	}
	done := make(chan struct{})
	written := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(written)
		var value [8]byte
		binary.NativeEndian.PutUint64(value[:], 1)
		for {
			_, err := unix.Write(event, value[:])
			if !errors.Is(err, unix.EINTR) {
				return
			}
		}
	})
	go func() {
		defer close(done)
		defer unix.Close(pid)
		defer unix.Close(event)
		defer func() {
			if !stop() {
				<-written
			}
		}()
		fds := []unix.PollFd{{Fd: int32(pid), Events: unix.POLLIN}, {Fd: int32(event), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			cancel()
			return
		}
	}()
	return done, nil
}
