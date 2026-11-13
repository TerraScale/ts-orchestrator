package swarmruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// SwarmKit restarts a crashed task after a fixed delay only; the executor
// stretches that per slot so a crash loop stops hammering the host and registry.
const (
	restartBackoffBase = time.Second
	restartBackoffMax  = time.Minute
	// A task that ran this long was healthy: its slot's next crash starts over at 1s.
	restartResetAfter = time.Minute
	// CrashLoopWindow and CrashLoopFailures mark a slot as crash-looping in `service ps`.
	CrashLoopWindow   = 5 * time.Minute
	CrashLoopFailures = 3
)

// slotRestart is one slot's run of consecutive exits under one spec.
type slotRestart struct {
	failures int
	exited   time.Time
	spec     string
}

func restartKey(t *api.Task) string { return fmt.Sprintf("%s/%d/%s", t.ServiceID, t.Slot, t.NodeID) }

// restartBackoff is the wait after the nth consecutive exit: 1s, 2s, 4s ... 1m.
func restartBackoff(n int) time.Duration {
	return min(restartBackoffBase<<min(max(n-1, 0), 6), restartBackoffMax)
}

// recordExitLocked counts an exit of a task that ran for ran; e.mu is held.
func (e *Executor) recordExitLocked(t *api.Task, spec string, ran time.Duration, now time.Time) {
	if e.restarts == nil {
		e.restarts = map[string]slotRestart{}
	}
	r := e.restarts[restartKey(t)]
	if ran >= restartResetAfter || r.spec != spec {
		r = slotRestart{spec: spec}
	}
	r.failures++
	r.exited = now
	e.restarts[restartKey(t)] = r
}

// restartDelayLocked is how long the slot's replacement still waits before it prepares; e.mu is held.
func (e *Executor) restartDelayLocked(t *api.Task, spec string, now time.Time) time.Duration {
	r, ok := e.restarts[restartKey(t)]
	if !ok || r.spec != spec {
		return 0
	}
	return max(r.exited.Add(restartBackoff(r.failures)).Sub(now), 0)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type taskOOMError struct {
	code     uint32
	limitMiB int64
}

func (e taskOOMError) Error() string {
	return fmt.Sprintf("container OOM-killed (memory limit %d MiB)", e.limitMiB)
}
func (e taskOOMError) ExitCode() int { return int(e.code) }

// oomKilled reads the exited task's cgroup v2 memory.events; runc keeps the
// cgroup until the task is deleted.
func (c *controller) oomKilled(ctx context.Context) bool {
	ctr, err := c.container(ctx)
	if err != nil {
		return false
	}
	spec, err := ctr.Spec(runtimeContext(ctx))
	if err != nil || spec.Linux == nil || !strings.HasPrefix(spec.Linux.CgroupsPath, "/") {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", filepath.Clean(spec.Linux.CgroupsPath), "memory.events"))
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "oom_kill" && f[1] != "0" {
			return true
		}
	}
	return false
}
