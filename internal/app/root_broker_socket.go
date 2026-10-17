package app

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"golang.org/x/sys/unix"
)

const rootBrokerStartupSocket = "/run/terrascale-orchestrator/broker-startup.sock"
const rootBrokerReconnectSocket = "/run/terrascale-orchestrator/broker-reconnect.sock"

type rootBrokerSocket struct {
	listener        *net.UnixListener
	directory, lock int
	name            string
	socket          unix.Stat_t
	once            sync.Once
}

func listenRootBrokerSocket(path string, gid uint32) (*rootBrokerSocket, error) {
	if path != rootBrokerStartupSocket && path != rootBrokerObservationSocket && path != rootBrokerReconnectSocket || gid == 0 {
		return nil, rootoci.ErrUnauthorized
	}
	directory, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"run", "terrascale-orchestrator"} {
		next, openErr := unix.Openat(directory, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(directory)
		if openErr != nil {
			return nil, openErr
		}
		directory = next
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			_ = unix.Close(directory)
			return nil, rootoci.ErrUnauthorized
		}
	}
	name := filepath.Base(path)
	lock, err := unix.Openat(directory, name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = unix.Close(directory)
		return nil, err
	}
	fail := func(err error) (*rootBrokerSocket, error) {
		_ = unix.Close(lock)
		_ = unix.Close(directory)
		return nil, err
	}
	var held unix.Stat_t
	if unix.Fstat(lock, &held) != nil || held.Uid != 0 || held.Gid != 0 || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&0o7777 != 0o600 || held.Nlink != 1 || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail(rootoci.ErrUnauthorized)
	}
	var previous unix.Stat_t
	if err := unix.Fstatat(directory, name, &previous, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if previous.Uid != 0 || previous.Gid != gid || previous.Mode&unix.S_IFMT != unix.S_IFSOCK || previous.Mode&0o7777 != 0o660 {
			return fail(rootoci.ErrUnauthorized)
		}
		if err := unix.Unlinkat(directory, name, 0); err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fail(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	listener.SetUnlinkOnClose(false)
	handle := &rootBrokerSocket{listener: listener, directory: directory, lock: lock, name: name}
	if unix.Fstatat(directory, name, &handle.socket, unix.AT_SYMLINK_NOFOLLOW) != nil || handle.socket.Uid != 0 || handle.socket.Mode&unix.S_IFMT != unix.S_IFSOCK {
		_ = handle.Close()
		return nil, rootoci.ErrUnauthorized
	}
	var installed unix.Stat_t
	if unix.Fchownat(directory, name, 0, int(gid), unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fchmodat(directory, name, 0o660, 0) != nil ||
		unix.Fstatat(directory, name, &installed, unix.AT_SYMLINK_NOFOLLOW) != nil || installed.Dev != handle.socket.Dev || installed.Ino != handle.socket.Ino || installed.Uid != 0 || installed.Gid != gid || installed.Mode&unix.S_IFMT != unix.S_IFSOCK || installed.Mode&0o7777 != 0o660 {
		_ = handle.Close()
		return nil, rootoci.ErrUnauthorized
	}
	return handle, nil
}

func (socket *rootBrokerSocket) Close() error {
	socket.once.Do(func() {
		_ = socket.listener.Close()
		var current unix.Stat_t
		if unix.Fstatat(socket.directory, socket.name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && current.Dev == socket.socket.Dev && current.Ino == socket.socket.Ino {
			_ = unix.Unlinkat(socket.directory, socket.name, 0)
		}
		_ = unix.Close(socket.lock)
		_ = unix.Close(socket.directory)
	})
	return nil
}

func serveRootBrokerSocket(ctx context.Context, socket *rootBrokerSocket, handle func(context.Context, *net.UnixConn)) {
	stop := context.AfterFunc(ctx, func() { _ = socket.listener.Close() })
	defer stop()
	slots := make(chan struct{}, 2)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		conn, err := socket.listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots; _ = conn.Close() }(); handle(ctx, conn) })
		default:
			_ = conn.Close()
		}
	}
}

func watchRootBrokerPeer(conn *net.UnixConn, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		var extra [1]byte
		_, _ = conn.Read(extra[:])
		cancel()
	}()
	return func() { _ = conn.Close(); <-done }
}
