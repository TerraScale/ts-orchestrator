//go:build linux

package host

import (
	"context"
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SignalManagedReload uses a pidfd so a recycled PID cannot receive SIGHUP.
// The recorded start time and role cgroup must still match the running native
// process before the signal is sent.
func (p *processRunner) SignalManagedReload(ctx context.Context, role string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateToken(role, "role"); err != nil {
		return err
	}
	p.mu.Lock()
	record, exists := p.records[role]
	p.mu.Unlock()
	if !exists || record.PID < 2 || !nativeProcessAliveWithStart(record.PID, record.StartTime) {
		return errors.New("recorded native process is unavailable")
	}
	fd, err := unix.PidfdOpen(record.PID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	populated, err := cgroupPopulated(filepath.Join(p.cgroups, role))
	if err != nil || !populated || !nativeProcessAliveWithStart(record.PID, record.StartTime) {
		return errors.New("recorded native process changed before reload")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return unix.PidfdSendSignal(fd, unix.SIGHUP, nil, 0)
}
