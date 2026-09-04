package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type networkController struct {
	mu          sync.Mutex
	plan        vmnet.NetworkPlan
	runner      vmnet.Runner
	journalPath string
}

// DynamicNetworkController is the live fault surface implemented by the real
// qualification network. The base Stack interface remains lifecycle-only.
type DynamicNetworkController interface {
	NetworkController
	Partition(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
	Heal(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
	SetNetem(context.Context, vmnet.FaultSpec) error
	ClearNetem(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
}

func NewNetworkController(config vmnet.Config, runner vmnet.Runner, journalPath string) (NetworkController, error) {
	if runner == nil {
		return nil, errors.New("vmqual: network runner is required")
	}
	if journalPath != "" && (!filepath.IsAbs(journalPath) || filepath.Clean(journalPath) == string(filepath.Separator)) {
		return nil, errors.New("vmqual: network journal path must be an absolute file path")
	}
	plan, err := vmnet.Plan(config)
	if err != nil {
		return nil, err
	}
	return &networkController{plan: plan, runner: runner, journalPath: journalPath}, nil
}
func (n *networkController) Apply(ctx context.Context) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	if ctx == nil {
		return errors.New("vmqual: network context is nil")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.journalPath != "" {
		return n.plan.ApplyWithJournal(ctx, n.runner, networkJournalWriter{path: n.journalPath})
	}
	return n.plan.Apply(ctx, n.runner)
}
func (n *networkController) Cleanup(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.CleanupPlan().Run(context.WithoutCancel(ctx), n.runner)
}

func (n *networkController) Partition(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.Partition(ctx, n.runner, from, to)
}

func (n *networkController) Heal(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.Heal(ctx, n.runner, from, to)
}

func (n *networkController) SetNetem(ctx context.Context, fault vmnet.FaultSpec) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.SetNetem(ctx, n.runner, fault)
}

func (n *networkController) ClearNetem(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.ClearNetem(ctx, n.runner, from, to)
}
func (n *networkController) writeJournal() error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	return writeNetworkJournal(n.journalPath, n.plan.Journal)
}
func (n *networkController) Plan() vmnet.NetworkPlan {
	if n == nil {
		return vmnet.NetworkPlan{}
	}
	return n.plan
}
func (n *networkController) Journal() vmnet.Journal {
	if n == nil {
		return vmnet.Journal{}
	}
	return n.plan.Journal
}

type networkJournalWriter struct{ path string }

func (w networkJournalWriter) WriteJournal(_ context.Context, journal vmnet.Journal) error {
	return writeNetworkJournal(w.path, journal)
}
func writeNetworkJournal(path string, journal vmnet.Journal) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("vmqual: network journal path must be absolute")
	}
	if err := validateNetworkJournal(journal); err != nil {
		return err
	}
	b, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write network journal: %w", err)
	}
	tmp := f.Name()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("secure network journal: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write network journal: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync network journal: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close network journal: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		syncErr := dir.Sync()
		_ = dir.Close()
		if syncErr != nil {
			return fmt.Errorf("sync network journal directory: %w", syncErr)
		}
	}
	return nil
}

// validateNetworkJournal rejects hand-edited cleanup records before they reach
// a privileged runner. vmnet binds every namespace deletion to the journal's
// full run identity, prefix, fingerprint, and absolute tool paths.
func validateNetworkJournal(journal vmnet.Journal) error {
	if err := journal.Validate(); err != nil {
		return fmt.Errorf("vmqual: invalid network journal: %w", err)
	}
	return nil
}

var _ DynamicNetworkController = (*networkController)(nil)
