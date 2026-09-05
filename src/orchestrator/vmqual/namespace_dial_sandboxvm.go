//go:build sandboxvm && linux

package vmqual

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

var guestNamespacePathPattern = regexp.MustCompile(`^/run/netns/[a-zA-Z0-9_-]{1,64}$`)

// dialGuestNamespace creates the socket synchronously inside the exact guest
// namespace. Go's Dialer must not be used inside setns: it may create sockets
// on other OS threads. The socket retains its namespace after restoration.
func dialGuestNamespace(ctx context.Context, namespacePath, target string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: namespace dial context is nil")
	}
	if !guestNamespacePathPattern.MatchString(namespacePath) || filepath.Clean(namespacePath) != namespacePath {
		return nil, errors.New("vmqual: invalid guest namespace path")
	}
	peer, err := netip.ParseAddrPort(target)
	if err != nil || !peer.Addr().Is4() || !peer.Addr().IsPrivate() || peer.Port() != 22 {
		return nil, errors.New("vmqual: namespace SSH target must be a private IPv4 literal on port 22")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type socketResult struct {
		fd  int
		err error
	}
	result := make(chan socketResult)
	go func() {
		fd, err := socketInGuestNamespace(namespacePath)
		select {
		case result <- socketResult{fd, err}:
		case <-ctx.Done():
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}()
	var fd int
	select {
	case got := <-result:
		if got.err != nil {
			return nil, got.err
		}
		fd = got.fd
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer unix.Close(fd)
	address := peer.Addr().As4()
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: int(peer.Port()), Addr: address})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		return nil, fmt.Errorf("vmqual: connect guest namespace socket: %w", err)
	}
	if err != nil {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, 50)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if ready == 0 {
				continue
			}
			status, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				return nil, err
			}
			if status != 0 {
				return nil, fmt.Errorf("vmqual: connect guest namespace socket: %w", unix.Errno(status))
			}
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// FileConn duplicates the already-connected descriptor and installs Go's
	// network poller; it never creates a socket in a different namespace.
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "vmqual-guest-ssh")
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		conn.Close()
		return nil, closeErr
	}
	return conn, nil
}

func socketInGuestNamespace(namespacePath string) (fd int, err error) {
	fd = -1
	runtime.LockOSThread()
	// If restoration fails, exiting this dedicated locked goroutine destroys
	// its OS thread rather than returning a contaminated thread to the pool.
	restored := true
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	original, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(original)
	target, err := unix.Open(namespacePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(target)
	var stat unix.Stat_t
	if err := unix.Fstat(target, &stat); err != nil {
		return -1, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(target, &filesystem); err != nil {
		return -1, err
	}
	if stat.Uid != 0 || filesystem.Type != unix.NSFS_MAGIC {
		return -1, errors.New("vmqual: guest namespace is not a root-owned namespace handle")
	}
	namespaceType, err := unix.IoctlRetInt(target, unix.NS_GET_NSTYPE)
	if err != nil || namespaceType != unix.CLONE_NEWNET {
		return -1, errors.New("vmqual: guest namespace is not a network namespace")
	}
	if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
		return -1, err
	}
	restored = false
	defer func() {
		if restoreErr := unix.Setns(original, unix.CLONE_NEWNET); restoreErr != nil {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			fd = -1
			err = fmt.Errorf("vmqual: restore original network namespace: %w", restoreErr)
			return
		}
		restored = true
	}()
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	return fd, err
}
