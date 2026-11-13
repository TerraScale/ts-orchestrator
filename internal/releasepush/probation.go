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
	trialStarts     = 2
	probationWait   = 2 * time.Minute
	rootStepRuntime = 30 * time.Second
	rootStepWait    = rootStepRuntime + 15*time.Second
	guardMargin     = rootStepRuntime
	guardEvery      = time.Minute
	PlanningWindow  = 10 * time.Minute
)

type trial struct {
	SHA           string        `json:"sha"`
	RunID         string        `json:"run_id"`
	Installed     time.Time     `json:"installed"`
	Starts        int           `json:"starts"`
	Phase         string        `json:"phase"`
	StartTimeout  time.Duration `json:"startTimeout"`
	GuardAfter    time.Time     `json:"guardAfter"`
	Binary        string        `json:"binary"`
	BinaryBackup  string        `json:"binaryBackup"`
	UnitBackup    string        `json:"unitBackup"`
	OriginalUnit  bool          `json:"originalUnit,omitempty"`
	RestoreFailed bool          `json:"restoreFailed,omitempty"`
	Reason        string        `json:"reason,omitempty"`
}

type Rollback struct {
	SHA    string `json:"sha"`
	RunID  string `json:"run_id"`
	Reason string `json:"reason"`
}

func trialFile(state string) string    { return filepath.Join(state, "nats", "release-trial") }
func rollbackFile(state string) string { return filepath.Join(state, "nats", "release-rolled-back") }

func readTrial(state string) (*trial, error) {
	data, err := os.ReadFile(trialFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t trial
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.SHA == "" {
		return nil, errors.New("release trial is missing its revision")
	}
	return &t, nil
}

func readRollback(path string) *Rollback {
	var rollback Rollback
	if data, err := os.ReadFile(path); err != nil || json.Unmarshal(data, &rollback) != nil || rollback.SHA == "" {
		return nil
	}
	return &rollback
}

func (t *trial) extend(now time.Time, start time.Duration) {
	deadline := now.Add(start + probationWait + guardMargin)
	if deadline.After(t.GuardAfter) {
		t.GuardAfter = deadline
	}
}

func ExtendStart(state string, start time.Duration) error {
	if _, err := os.Stat(trialFile(state)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return withTrialLock(state, func() error {
		t, err := readTrial(state)
		if err != nil || t == nil {
			return err
		}
		t.StartTimeout = max(t.StartTimeout, start)
		t.extend(time.Now(), start)
		return writeJSON(trialFile(state), t)
	})
}

type Probation struct {
	state, binary string
	output        io.Writer
	trial         trial
	exit          func()
	mu            sync.Mutex
	served        bool
	timer         *time.Timer
}

func Probe(state string, output io.Writer) (*Probation, error) {
	binary, err := executable()
	if err != nil {
		return nil, err
	}
	return probe(state, binary, Revision(), output, func() { os.Exit(1) })
}

func probe(state, binary, revision string, output io.Writer, exit func()) (*Probation, error) {
	t, err := readTrial(state)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, nil
	}
	p := &Probation{state: state, binary: binary, output: output, trial: *t, exit: exit}
	if t.RestoreFailed {
		return nil, errors.New("release restore deferred to independent guard")
	}
	if t.Phase == "restoring" || t.Phase == "restored" || t.SHA != revision {
		return nil, p.rollBack("interrupted release installation")
	}
	if t.Phase == "" {
		budget, err := startBudget(context.Background(), nil)
		if err != nil {
			return nil, err
		}
		t.Binary, t.BinaryBackup, t.OriginalUnit = binary, binary+".prev", true
		t.Phase = "binary-swapped"
		t.StartTimeout = budget
		t.extend(time.Now(), budget)
		if err := writeJSON(trialFile(state), t); err != nil {
			return nil, err
		}
	}
	changed, err := reconcileUnit(context.Background(), binary, state)
	if err != nil {
		return nil, p.rollBack(fmt.Sprintf("reconcile release unit: %v", err))
	}
	if changed {
		return nil, errors.New("installed release unit; restarting under its settings without counting a trial start")
	}
	err = withTrialLock(state, func() error {
		current, err := readTrial(state)
		if err != nil || current == nil {
			return err
		}
		if current.StartTimeout <= 0 {
			return errors.New("release trial is missing its startup bound")
		}
		current.extend(time.Now(), current.StartTimeout)
		current.Starts++
		p.trial = *current
		return writeJSON(trialFile(state), current)
	})
	if err != nil {
		return nil, err
	}
	if p.trial.Starts > trialStarts {
		return nil, p.rollBack(fmt.Sprintf("exited %d times before serving", trialStarts))
	}
	return p, nil
}

func reconcileUnit(ctx context.Context, binary, state string) (bool, error) {
	t, err := readTrial(state)
	if err != nil || t == nil {
		return false, err
	}
	if t.Phase != "binary-swapped" && !t.OriginalUnit {
		return false, nil
	}
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return false, err
	}
	embedded, err := unitBytes()
	if err != nil {
		return false, err
	}
	if string(data) != string(embedded) || t.OriginalUnit && t.UnitBackup == "" {
		return prepareUnit(ctx, binary, binary, state)
	}
	return false, nil
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
	p.timer = time.AfterFunc(probationWait, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.served {
			return
		}
		fmt.Fprintln(p.output, p.rollBack("not serving "+probationWait.String()+" after startup planning"))
		p.exit()
	})
}

func (p *Probation) Served() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	err := withTrialLock(p.state, func() error {
		t, err := readTrial(p.state)
		if err != nil || t == nil {
			return err
		}
		if t.SHA != p.trial.SHA || t.Phase == "restoring" || t.Phase == "restored" {
			return errors.New("release recovery is already in progress")
		}
		return removeIfExists(trialFile(p.state))
	})
	if err != nil {
		fmt.Fprintf(p.output, "release probation: %v\n", err)
		p.exit()
		return false
	}
	p.served = true
	if p.timer != nil {
		p.timer.Stop()
	}
	if err := ensureGuard(context.Background(), p.binary, p.state); err != nil {
		fmt.Fprintf(p.output, "release confirmed; guard unit refresh: %v\n", err)
	}
	return true
}

func (p *Probation) rollBack(reason string) error {
	err := unitService(context.Background(), p.binary, "restore", p.binary, p.state)
	if err != nil {
		markErr := withTrialLock(p.state, func() error {
			t, err := readTrial(p.state)
			if err != nil || t == nil {
				return err
			}
			t.RestoreFailed, t.Reason = true, reason
			return writeJSON(trialFile(p.state), t)
		})
		return fmt.Errorf("release %s %s: restore deferred to independent guard: %w", p.trial.SHA, reason, errors.Join(err, markErr))
	}
	return fmt.Errorf("rolled back release %s (run %s): %s", p.trial.SHA, p.trial.RunID, reason)
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicMode(path, data, 0o600)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(path))
}
