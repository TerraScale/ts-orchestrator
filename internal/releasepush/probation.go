package releasepush

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// A pushed binary is on probation until it serves: install writes a trial
// marker, every start counts itself in it before anything that can crash, and
// serving clears it. A start past trialStarts, or no serving probationWait
// after install, restores <binary>.prev and records the rollback.
const (
	// A third start rolls back, inside systemd's default 5 starts per 10 s.
	trialStarts = 2
	// Inside push's 3-minute serving wait, so CI reads the rollback.
	probationWait = 2 * time.Minute
)

// trial is the marker of a pushed binary that has not served yet.
type trial struct {
	SHA       string    `json:"sha"`
	RunID     string    `json:"run_id"`
	Installed time.Time `json:"installed"`
	Starts    int       `json:"starts"`
}

// Rollback records a pushed release that never served; its run is not reinstalled.
type Rollback struct {
	SHA    string `json:"sha"`
	RunID  string `json:"run_id"`
	Reason string `json:"reason"`
}

func trialFile(state string) string    { return filepath.Join(state, "nats", "release-trial") }
func rollbackFile(state string) string { return filepath.Join(state, "nats", "release-rolled-back") }

func readRollback(path string) *Rollback {
	var rollback Rollback
	if data, err := os.ReadFile(path); err != nil || json.Unmarshal(data, &rollback) != nil || rollback.SHA == "" {
		return nil
	}
	return &rollback
}

// Probation guards one start of a pushed binary; a nil Probation is no trial.
type Probation struct {
	state, binary string
	output        io.Writer
	trial         trial
	exit          func()

	mu     sync.Mutex
	served bool
	timer  *time.Timer
}

// Probe runs first at every single-host start. It returns an error after
// restoring <binary>.prev, so the caller exits and systemd starts that.
func Probe(state string, output io.Writer) (*Probation, error) {
	binary, err := executable()
	if err != nil {
		return nil, err
	}
	return probe(state, binary, Revision(), time.Now(), output, func() { os.Exit(1) })
}

func probe(state, binary, revision string, now time.Time, output io.Writer, exit func()) (*Probation, error) {
	data, err := os.ReadFile(trialFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Probation{state: state, binary: binary, output: output, exit: exit}
	if json.Unmarshal(data, &p.trial) != nil || p.trial.SHA != revision {
		// Not this binary's trial: its install never swapped, or this is the restored binary.
		return nil, removeIfExists(trialFile(state))
	}
	p.trial.Starts++
	if p.trial.Starts > trialStarts {
		return nil, p.rollBack(fmt.Sprintf("exited %d times before serving", trialStarts))
	}
	late := "not serving " + probationWait.String() + " after install"
	left := p.trial.Installed.Add(probationWait).Sub(now)
	if left <= 0 {
		return nil, p.rollBack(late)
	}
	if err := writeJSON(trialFile(state), p.trial); err != nil {
		return nil, err
	}
	p.timer = time.AfterFunc(left, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.served {
			return
		}
		if err := p.rollBack(late); err != nil {
			fmt.Fprintln(p.output, err)
			p.exit()
		}
	})
	return p, nil
}

// Served ends the probation: this binary now answers releases.
func (p *Probation) Served() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.served = true
	p.timer.Stop()
	if err := removeIfExists(trialFile(p.state)); err != nil {
		fmt.Fprintf(p.output, "release probation: %v\n", err)
	}
}

// rollBack records the rollback first, so a crash before the swap rolls
// back again at the next start. It returns nil when nothing was restored:
// this binary keeps running rather than looping on a missing .prev.
func (p *Probation) rollBack(reason string) error {
	record := Rollback{SHA: p.trial.SHA, RunID: p.trial.RunID, Reason: reason}
	err := writeJSON(rollbackFile(p.state), record)
	if err == nil {
		err = os.Rename(p.binary+".prev", p.binary)
	}
	if err != nil {
		err = errors.Join(err, removeIfExists(rollbackFile(p.state)), removeIfExists(trialFile(p.state)))
		fmt.Fprintf(p.output, "release %s %s; cannot restore %s.prev: %v\n", p.trial.SHA, reason, p.binary, err)
		return nil
	}
	_ = os.Remove(trialFile(p.state)) // the restored binary drops it too
	return fmt.Errorf("rolled back release %s (run %s): %s; restarting on %s.prev", p.trial.SHA, p.trial.RunID, reason, p.binary)
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
