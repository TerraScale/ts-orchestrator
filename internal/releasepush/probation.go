package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	trialStarts   = 2
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
	return probe(state, binary, Revision(), output, func() { os.Exit(1) })
}

func probe(state, binary, revision string, output io.Writer, exit func()) (*Probation, error) {
	data, err := os.ReadFile(trialFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Probation{state: state, binary: binary, output: output, exit: exit}
	if json.Unmarshal(data, &p.trial) != nil || p.trial.SHA != revision {
		return nil, removeIfExists(trialFile(state))
	}
	p.trial.Starts++
	if p.trial.Starts > trialStarts {
		return nil, p.rollBack(fmt.Sprintf("exited %d times before serving", trialStarts))
	}
	if err := writeJSON(trialFile(state), p.trial); err != nil {
		return nil, err
	}
	if os.Getenv("NOTIFY_SOCKET") != "" {
		changed, err := prepareUnit(context.Background(), binary, binary)
		if err != nil {
			return nil, err
		}
		if changed {
			return nil, errors.New("installed release unit; restarting under its settings")
		}
	}
	return p, nil
}

func (p *Probation) Planned() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.served || p.timer != nil {
		return
	}
	late := "not serving " + probationWait.String() + " after startup planning"
	p.timer = time.AfterFunc(probationWait, func() {
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
}

func (p *Probation) Served() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.served = true
	if p.timer != nil {
		p.timer.Stop()
	}
	if err := removeIfExists(trialFile(p.state)); err != nil {
		fmt.Fprintf(p.output, "release probation: %v\n", err)
		return false
	}
	return true
}

func (p *Probation) rollBack(reason string) error {
	record := Rollback{SHA: p.trial.SHA, RunID: p.trial.RunID, Reason: reason}
	err := writeJSON(rollbackFile(p.state), record)
	if err == nil {
		err = restoreUnit(context.Background(), p.binary, p.binary)
	}
	if err == nil {
		err = os.Rename(p.binary+".prev", p.binary)
	}
	if err != nil {
		return fmt.Errorf("release %s %s; cannot restore binary and unit: %w", p.trial.SHA, reason, err)
	}
	if err := removeIfExists(trialFile(p.state)); err != nil {
		return fmt.Errorf("remove restored release trial: %w", err)
	}
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
