package releasepush

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	trialStarts   = 2
	probationWait = 2 * time.Minute
)

type trial struct {
	SHA       string    `json:"sha"`
	SHA256    string    `json:"sha256"`
	RunID     string    `json:"run_id"`
	Previous  releaseID `json:"previous"`
	Requested time.Time `json:"requested"`
	Started   time.Time `json:"started"`
	Starts    int       `json:"starts"`
	Failure   string    `json:"failure,omitempty"`
}

type Rollback struct {
	SHA      string    `json:"sha"`
	SHA256   string    `json:"sha256"`
	RunID    string    `json:"run_id"`
	Previous releaseID `json:"previous"`
	Reason   string    `json:"reason"`
	Rejected releaseID `json:"rejected"`
}

func trialFile(state string) string    { return filepath.Join(state, "nats", "release-trial") }
func rollbackFile(state string) string { return filepath.Join(state, "nats", "release-rolled-back") }

type Probation struct {
	state, binary string
	output        io.Writer
	trial         trial
	exit          func()
	mu            sync.Mutex
	served        bool
	timer         *time.Timer
}

type startupResult struct {
	once      sync.Once
	probation *Probation
	err       error
}

var startups sync.Map

func Probe(state string, output io.Writer) (*Probation, error) {
	value, _ := startups.LoadOrStore(filepath.Clean(state), &startupResult{})
	result := value.(*startupResult)
	result.once.Do(func() {
		binary, err := executable()
		if err != nil {
			result.err = err
			return
		}
		result.probation, result.err = probe(state, binary, time.Now(), output, func() { os.Exit(1) })
	})
	return result.probation, result.err
}

func probe(state, binary string, now time.Time, output io.Writer, exit func()) (*Probation, error) {
	id, err := binaryIdentity(binary)
	if err != nil {
		return nil, err
	}
	record, ok := selected[trial](trialFile(state), id)
	if !ok {
		return nil, nil
	}
	p := &Probation{state: state, binary: binary, output: output, trial: record, exit: exit}
	p.trial.Starts++
	if p.trial.Started.IsZero() {
		p.trial.Started = now
	}
	if p.trial.Starts > trialStarts {
		if err := p.rollBack(fmt.Sprintf("exited %d times before serving", trialStarts)); err != nil {
			return nil, err
		}
	}
	left := p.trial.Started.Add(probationWait).Sub(now)
	if left <= 0 && p.trial.Failure == "" {
		if err := p.rollBack("not serving " + probationWait.String() + " after candidate startup"); err != nil {
			return nil, err
		}
	}
	if err := storeRecord(trialFile(state), p.trial, id); err != nil {
		stateWarning(trialFile(state), "crash counter not saved")
	}
	if p.trial.Failure == "" {
		p.timer = time.AfterFunc(left, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if !p.served {
				if err := p.rollBack("not serving " + probationWait.String() + " after candidate startup"); err != nil {
					fmt.Fprintln(p.output, err)
					p.exit()
				}
			}
		})
	}
	return p, nil
}

func (p *Probation) Served() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.trial.Failure != "" {
		return false
	}
	if err := dropRecord[trial](trialFile(p.state), p.trial.identity()); err != nil {
		fmt.Fprintf(p.output, "release probation confirmation failed: %v\n", err)
		return false
	}
	p.served = true
	if p.timer != nil {
		p.timer.Stop()
	}
	return true
}

func (p *Probation) rollBack(reason string) error {
	previous := previousBinary(p.binary, p.trial.Previous)
	id, err := binaryIdentity(previous)
	if err == nil && id != p.trial.Previous {
		err = errors.New("previous binary revision or digest differs")
	}
	if err == nil {
		record := Rollback{SHA: p.trial.SHA, SHA256: p.trial.SHA256, RunID: p.trial.RunID, Previous: p.trial.Previous, Reason: reason}
		err = storeRecord(rollbackFile(p.state), record, p.trial.identity())
	}
	if err == nil {
		restored := Rollback{SHA: p.trial.Previous.SHA, SHA256: p.trial.Previous.SHA256, RunID: p.trial.RunID, Rejected: p.trial.identity(), Previous: p.trial.Previous, Reason: reason}
		err = storeRecord(rollbackFile(p.state), restored, p.trial.identity())
	}
	if err == nil {
		err = os.Rename(previous, p.binary)
	}
	if err != nil {
		p.trial.Failure = "rollback unavailable: " + err.Error()
		if writeErr := storeRecord(trialFile(p.state), p.trial, p.trial.identity()); writeErr != nil {
			slog.Warn("release unconfirmed; failed to persist rollback failure", "error", writeErr)
		}
		slog.Error("release unconfirmed; staying on candidate", "revision", p.trial.SHA, "reason", reason, "error", err)
		fmt.Fprintf(p.output, "release %s unconfirmed; cannot restore previous binary: %v\n", p.trial.SHA, err)
		return nil
	}
	if err := syncDirectory(filepath.Dir(p.binary)); err != nil {
		slog.Warn("rollback installed; directory sync failed", "error", err)
	}
	return fmt.Errorf("rolled back release %s (run %s): %s; restarting on previous binary", p.trial.SHA, p.trial.RunID, reason)
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeState(path, data)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
