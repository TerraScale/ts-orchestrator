package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type networkController struct {
	plan        vmnet.NetworkPlan
	runner      vmnet.Runner
	journalPath string
}

func NewNetworkController(config vmnet.Config, runner vmnet.Runner, journalPath string) (NetworkController, error) {
	if runner == nil {
		return nil, errors.New("vmqual: network runner is required")
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
	return n.plan.Apply(ctx, n.runner)
}
func (n *networkController) Cleanup(ctx context.Context) error {
	if n == nil {
		return nil
	}
	return n.plan.CleanupPlan().Run(ctx, n.runner)
}
func (n *networkController) writeJournal() error {
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
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("vmqual: network journal path must be absolute")
	}
	b, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return fmt.Errorf("write network journal: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
