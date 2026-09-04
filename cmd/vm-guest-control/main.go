// Command vm-guest-control is the forced SSH command installed only in I-12
// Firecracker qualification guests. It is never a production host backdoor.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

const (
	guestControlMemoryLimit = 96 << 20
	guestSeedMaxBytes       = 64 << 10
	sessionLockPath         = "/run/lock/terrascale-vmqual-control.lock"
)

func main() {
	if os.Geteuid() != 0 {
		os.Exit(1)
	}
	debug.SetMemoryLimit(guestControlMemoryLimit)
	lock, err := acquireSessionLock(sessionLockPath)
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(lock)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config, err := configFromGuestSeed(vmguest.DefaultConfig())
	if err != nil {
		os.Exit(1)
	}
	original := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(os.Args) != 1 && original == "" {
		original = "local arguments"
	}
	if err := serveSession(ctx, os.Stdin, os.Stdout, original, config); err != nil {
		os.Exit(1)
	}
}

func configFromGuestSeed(config vmguest.Config) (vmguest.Config, error) {
	path := config.SeedPath
	if path == "" {
		path = vmguest.DefaultSeedPath
		config.SeedPath = path
	}
	data, err := readTrustedGuestSeed(path)
	if err != nil {
		return vmguest.Config{}, err
	}
	seed, err := vmimage.DecodeGuestChannelSeed(data)
	if err != nil {
		return vmguest.Config{}, errors.New("vm-guest-control: guest seed is invalid")
	}
	config.NetworkExchangeEndpoint = seed.NetworkExchangeEndpoint
	config.DataDevice = seed.DataDiskPath
	return config, nil
}

func readTrustedGuestSeed(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("vm-guest-control: guest seed path is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("vm-guest-control: open filesystem root")
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return nil, errors.New("vm-guest-control: open guest seed directory")
		}
		if err := validateTrustedSeedDirectory(next); err != nil {
			_ = unix.Close(next)
			return nil, err
		}
		current = next
	}
	defer unix.Close(current)
	fd, err := unix.Openat(current, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("vm-guest-control: open guest seed")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("vm-guest-control: wrap guest seed")
	}
	defer file.Close()
	before, err := validateTrustedSeedFile(fd)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, guestSeedMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > guestSeedMaxBytes {
		return nil, errors.New("vm-guest-control: read guest seed")
	}
	after, err := validateTrustedSeedFile(fd)
	if err != nil || !sameSeedFileSnapshot(before, after) || int64(len(data)) != after.Size {
		return nil, errors.New("vm-guest-control: guest seed changed while reading")
	}
	return data, nil
}

func validateTrustedSeedDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("vm-guest-control: guest seed path component is not a directory")
	}
	mode := stat.Mode & 0o7777
	if int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid() {
		return errors.New("vm-guest-control: guest seed directory owner is unsafe")
	}
	if mode&0o022 != 0 && !(stat.Uid == 0 && mode&unix.S_ISVTX != 0) {
		return errors.New("vm-guest-control: guest seed directory mode is unsafe")
	}
	return nil
}

func validateTrustedSeedFile(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Geteuid() || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > guestSeedMaxBytes {
		return unix.Stat_t{}, errors.New("vm-guest-control: guest seed owner, mode, links, or size is unsafe")
	}
	return stat, nil
}

func sameSeedFileSnapshot(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev &&
		first.Ino == second.Ino &&
		first.Size == second.Size &&
		first.Mtim.Sec == second.Mtim.Sec &&
		first.Mtim.Nsec == second.Mtim.Nsec &&
		first.Ctim.Sec == second.Ctim.Sec &&
		first.Ctim.Nsec == second.Ctim.Nsec
}

func serveSession(ctx context.Context, input, output *os.File, original string, config vmguest.Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := config.SessionTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	sessionContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return vmguest.ServeForced(
		sessionContext,
		&pollFileReader{ctx: sessionContext, fd: int(input.Fd())},
		&pollFileWriter{ctx: sessionContext, fd: int(output.Fd())},
		original,
		config,
	)
}

const pollCancellationInterval = 50 * time.Millisecond

type pollFileReader struct {
	ctx context.Context
	fd  int
}

func (reader *pollFileReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) > 4<<10 {
		data = data[:4<<10]
	}
	for {
		if err := waitForFile(reader.ctx, reader.fd, unix.POLLIN); err != nil {
			return 0, err
		}
		read, err := unix.Read(reader.fd, data)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if read == 0 && err == nil {
			return 0, io.EOF
		}
		return read, err
	}
}

type pollFileWriter struct {
	ctx context.Context
	fd  int
}

func (writer *pollFileWriter) Write(data []byte) (int, error) {
	writtenTotal := 0
	for len(data) != 0 {
		if err := waitForFile(writer.ctx, writer.fd, unix.POLLOUT); err != nil {
			return writtenTotal, err
		}
		chunk := data
		if len(chunk) > 4<<10 {
			chunk = chunk[:4<<10]
		}
		written, err := unix.Write(writer.fd, chunk)
		if written < 0 || written > len(chunk) {
			return writtenTotal, io.ErrShortWrite
		}
		if written > 0 {
			writtenTotal += written
			data = data[written:]
		}
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return writtenTotal, err
		}
		if written == 0 {
			return writtenTotal, io.ErrShortWrite
		}
	}
	return writtenTotal, writer.ctx.Err()
}

func waitForFile(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout, err := pollTimeout(ctx)
		if err != nil {
			return err
		}
		descriptors := []unix.PollFd{{Fd: int32(fd), Events: events}}
		ready, err := unix.Poll(descriptors, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			continue
		}
		revents := descriptors[0].Revents
		if revents&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		if revents&(events|unix.POLLERR|unix.POLLHUP) != 0 {
			return nil
		}
	}
}

func pollTimeout(ctx context.Context) (int, error) {
	wait := pollCancellationInterval
	if deadline, present := ctx.Deadline(); present {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, context.DeadlineExceeded
		}
		if remaining < wait {
			wait = remaining
		}
	}
	return max(1, int((wait+time.Millisecond-1)/time.Millisecond)), nil
}

func acquireSessionLock(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Geteuid() || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size != 0 {
		_ = unix.Close(fd)
		return -1, syscall.EPERM
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Geteuid() || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size != 0 {
		_ = unix.Close(fd)
		return -1, syscall.EPERM
	}
	return fd, nil
}
