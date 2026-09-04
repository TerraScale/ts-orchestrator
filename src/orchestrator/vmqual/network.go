package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	return n.plan.CleanupPlan().Run(context.WithoutCancel(ctx), n.runner)
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
// a privileged runner. vmnet emits only ip argv; names must carry the
// qualification prefix and launch-Region marker, so an unrelated host object
// cannot be selected by a stale journal.
func validateNetworkJournal(journal vmnet.Journal) error {
	if journal.Version != 1 || journal.Fingerprint == "" || journal.Cleanup.Version != 1 || journal.Cleanup.Fingerprint != journal.Fingerprint {
		return errors.New("vmqual: invalid network journal")
	}
	for _, command := range journal.Cleanup.Commands {
		if err := validateNetworkCleanupCommand(command); err != nil {
			return err
		}
	}
	return nil
}

func validateNetworkCleanupCommand(command vmnet.Command) error {
	if command.Executable != "ip" {
		return fmt.Errorf("vmqual: network cleanup executable %q is not admitted", command.Executable)
	}
	for _, arg := range command.Args {
		if arg == "" || strings.ContainsAny(arg, ";|&$`\n\r\x00") {
			return errors.New("vmqual: network cleanup contains unsafe argv")
		}
	}
	args := command.Args
	if len(args) >= 3 && args[0] == "netns" && args[1] == "del" {
		if len(args) != 3 || !networkName(args[2], "-n-") {
			return errors.New("vmqual: network cleanup namespace is not TerraScale-owned")
		}
		return nil
	}
	if len(args) >= 5 && args[0] == "-n" && args[2] == "link" && args[3] == "del" {
		if len(args) != 5 || !networkName(args[1], "-n-") || !networkName(args[4], "-v-") {
			return errors.New("vmqual: network cleanup veth is not TerraScale-owned")
		}
		return nil
	}
	if len(args) >= 8 && args[0] == "netns" && args[1] == "exec" && args[3] == "nft" && args[4] == "delete" && args[5] == "table" {
		if len(args) != 8 || !networkName(args[2], "-n-") || args[6] != "inet" || !networkTable(args[7]) {
			return errors.New("vmqual: network cleanup nft table is not TerraScale-owned")
		}
		return nil
	}
	return fmt.Errorf("vmqual: network cleanup argv is not admitted: %v", args)
}

func networkName(value, kind string) bool {
	parts := strings.Split(value, kind)
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 5 {
		return false
	}
	if kind == "-n-" {
		if parts[1] != "gru" && parts[1] != "sfo" && parts[1] != "fra" {
			return false
		}
	} else if kind == "-v-" {
		regions := strings.Split(parts[1], "-")
		if len(regions) != 2 || regions[0] == regions[1] {
			return false
		}
		for _, region := range regions {
			if region != "gru" && region != "sfo" && region != "fra" {
				return false
			}
		}
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func networkTable(value string) bool {
	prefix, ok := strings.CutSuffix(value, "_vmnet")
	if !ok || len(prefix) < 1 || len(prefix) > 5 {
		return false
	}
	for _, r := range prefix {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
