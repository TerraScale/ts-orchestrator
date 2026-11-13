package releasepush

import (
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
	SHA       string     `json:"sha"`
	SHA256    string     `json:"sha256,omitempty"`
	RunID     string     `json:"run_id"`
	Installed time.Time  `json:"installed"`
	Starts    int        `json:"starts"`
	Previous  *releaseID `json:"previous,omitempty"`
	Failure   string     `json:"failure,omitempty"`
}

func (t trial) valid() bool { return t.SHA != "" && t.RunID != "" }

func (t trial) names(id releaseID) bool {
	return t.SHA == id.SHA && (t.SHA256 == "" || t.SHA256 == id.SHA256)
}

type Rollback struct {
	SHA    string `json:"sha"`
	SHA256 string `json:"sha256,omitempty"`
	RunID  string `json:"run_id"`
	Reason string `json:"reason"`
}

func trialFile(state string) string    { return filepath.Join(state, "nats", "release-trial") }
func rollbackFile(state string) string { return filepath.Join(state, "nats", "release-rolled-back") }

func readRollback(path string) (*Rollback, error) {
	var record Rollback
	present, err := readRecord(path, &record)
	if !present {
		return nil, nil
	}
	if err == nil && record.SHA == "" {
		err = errors.New("no release named")
	}
	if err != nil {
		return nil, fmt.Errorf("rollback record %s damaged: %w", filepath.Base(path), err)
	}
	return &record, nil
}

type Probation struct {
	state, binary string
	output        io.Writer
	trial         trial
	unconfirmed   string
	exit          func()
	mu            sync.Mutex
	served        bool
	timer         *time.Timer
}

type startup struct {
	once      sync.Once
	probation *Probation
	err       error
}

var startups sync.Map

func Probe(state string, output io.Writer) (*Probation, error) {
	value, _ := startups.LoadOrStore(filepath.Clean(state), &startup{})
	result := value.(*startup)
	result.once.Do(func() {
		binary, err := executable()
		if err != nil {
			result.err = err
			return
		}
		result.probation, result.err = probe(state, binary, output, func() { os.Exit(1) })
	})
	return result.probation, result.err
}

func probe(state, binary string, output io.Writer, exit func()) (*Probation, error) {
	var record trial
	present, err := readRecord(trialFile(state), &record)
	if !present {
		return nil, nil
	}
	p := &Probation{state: state, binary: binary, output: output, trial: record, exit: exit}
	if err == nil && !record.valid() {
		err = errors.New("no release named")
	}
	if err != nil {
		return p.hold("release trial damaged: " + err.Error()), nil
	}
	self, err := binaryIdentity(binary)
	if err != nil {
		return p.hold("running binary identity unavailable: " + err.Error()), nil
	}
	if !record.names(self) {
		return nil, nil
	}
	if record.Failure != "" {
		return p.hold(record.Failure), nil
	}
	if decided, err := readRollback(rollbackFile(state)); err == nil && decided != nil && decided.SHA == record.SHA && decided.RunID == record.RunID {
		return p.finish(p.rollBack(decided.Reason))
	}
	p.trial.Starts++
	if p.trial.Starts > trialStarts {
		return p.finish(p.rollBack(fmt.Sprintf("exited %d times before serving", trialStarts)))
	}
	if err := writeJSON(trialFile(state), p.trial); err != nil {
		return p.finish(p.rollBack("start count not saved: " + err.Error()))
	}
	p.timer = time.AfterFunc(probationWait, p.expire)
	return p, nil
}

func (p *Probation) hold(reason string) *Probation {
	p.unconfirmed = reason
	slog.Error("release unconfirmed; serving without probation", "reason", reason)
	fmt.Fprintf(p.output, "release unconfirmed: %s\n", reason)
	return p
}

func (p *Probation) finish(restart error) (*Probation, error) {
	if restart != nil {
		return nil, restart
	}
	return p, nil
}

func (p *Probation) expire() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.served || p.unconfirmed != "" {
		return
	}
	if err := p.rollBack("not serving " + probationWait.String() + " after start"); err != nil {
		fmt.Fprintln(p.output, err)
		p.exit()
	}
}

func (p *Probation) status() (string, string) {
	if p == nil {
		return "", ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unconfirmed != "" {
		return "unconfirmed", p.unconfirmed
	}
	if !p.served {
		return "probation", ""
	}
	return "", ""
}

func (p *Probation) Served() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unconfirmed != "" {
		return false
	}
	p.served = true
	if p.timer != nil {
		p.timer.Stop()
	}
	if err := removeDurable(trialFile(p.state)); err != nil {
		fmt.Fprintf(p.output, "release probation confirmation not saved: %v\n", err)
		return false
	}
	return true
}

func (p *Probation) rollBack(reason string) error {
	previous := p.binary + ".prev"
	recorded := false
	err := p.checkPrevious(previous)
	if err == nil {
		err = writeJSON(rollbackFile(p.state), Rollback{SHA: p.trial.SHA, SHA256: p.trial.SHA256, RunID: p.trial.RunID, Reason: reason})
		recorded = err == nil
	}
	if err == nil {
		err = os.Rename(previous, p.binary)
	}
	if err != nil {
		p.trial.Failure = "rollback unavailable: " + err.Error()
		if recorded {
			err = errors.Join(err, removeDurable(rollbackFile(p.state)))
		}
		if writeErr := writeJSON(trialFile(p.state), p.trial); writeErr != nil {
			slog.Warn("release unconfirmed; failure not saved", "error", writeErr)
		}
		p.hold(fmt.Sprintf("release %s %s; cannot restore %s: %v", p.trial.SHA, reason, previous, err))
		p.unconfirmed = p.trial.Failure
		return nil
	}
	if err := syncDirectory(filepath.Dir(p.binary)); err != nil {
		slog.Warn("rollback installed; directory sync failed", "error", err)
	}
	if err := removeIfExists(trialFile(p.state)); err != nil {
		slog.Warn("rollback installed; trial not removed", "error", err)
	}
	return fmt.Errorf("rolled back release %s (run %s): %s; restarting on %s", p.trial.SHA, p.trial.RunID, reason, previous)
}

func (p *Probation) checkPrevious(path string) error {
	if p.trial.Previous == nil {
		_, err := os.Lstat(path)
		return err
	}
	id, err := binaryIdentity(path)
	if err == nil && id != *p.trial.Previous {
		err = errors.New("previous binary is not the recorded build")
	}
	return err
}
