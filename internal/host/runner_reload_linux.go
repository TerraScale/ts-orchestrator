//go:build linux

package host

import (
	"context"
	"errors"
	"path/filepath"
	"time"

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
	if !exists {
		return errors.New("recorded native process is unavailable")
	}
	return p.signalRecorded(ctx, record, unix.SIGHUP)
}

// drain asks the recorded process to shut down gracefully and waits until its
// cgroup is empty or the record's drain timeout passes. Stop kills whatever
// is left either way.
func (p *processRunner) drain(ctx context.Context, record processRecord) {
	if p.signalRecorded(ctx, record, unix.SIGTERM) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(record.DrainMillis)*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if populated, err := cgroupPopulated(filepath.Join(p.cgroups, record.Role)); err != nil || !populated {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *processRunner) signalRecorded(ctx context.Context, record processRecord, signal unix.Signal) error {
	role := record.Role
	if record.PID < 2 || !nativeProcessAliveWithStart(record.PID, record.StartTime) {
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
	return unix.PidfdSendSignal(fd, signal, nil, 0)
}
