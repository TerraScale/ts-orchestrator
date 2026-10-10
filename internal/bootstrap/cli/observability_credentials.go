package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func (c command) issueObservabilityCredentialsAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("issue-observability-credentials", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	currentPath := flags.String("credentials", "", "current owner-only controller credentials")
	signerPath := flags.String("account-seed", "", "offline owner-only issuer-cell.seed")
	interregionDir := flags.String("interregion-directory", "", "reviewed immutable interregion material directory")
	slot := flags.String("slot", "", "controller slot")
	account := flags.String("cell-account", "", "cell account NKey from the signed generation")
	outputPath := flags.String("out", "", "new owner-only controller credentials")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *currentPath == "" || *signerPath == "" || *interregionDir == "" || *slot == "" || *account == "" ||
		!filepath.IsAbs(*outputPath) || flags.NArg() != 0 || pathInside(*interregionDir, *outputPath) {
		return errors.New("issue-observability-credentials requires --credentials, --account-seed, --interregion-directory, --slot, --cell-account and an absolute --out")
	}
	record, err := bootstrapmaterial.LoadInterRegion(*interregionDir)
	if err != nil {
		return fmt.Errorf("load interregion material: %w", err)
	}
	if now.Before(record.IssuedAt) {
		return errors.New("interregion material is not yet valid")
	}
	if !now.Before(record.ExpiresAt) {
		return errors.New("interregion material has expired")
	}
	if !slices.ContainsFunc(record.Slots, func(candidate bootstrapmaterial.Slot) bool { return candidate.Name == *slot }) {
		return errors.New("controller slot is absent from the interregion material")
	}
	if err := bootstrapmaterial.WriteControllerObservabilityCredentials(*currentPath, *signerPath, *outputPath,
		record.Cell, *slot, *account, record.Config.Topology.Peers(record.Cell), record.Config.Topology.Hub == record.Cell); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "controller observability credentials issued cell=%s slot=%s; sign and install a successor material generation\n",
		record.Cell, *slot)
	return nil
}
