package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
)

const clusterUsage = `Usage: ts-orch cluster recover-quorum <command> [flags]

Break-glass quorum-loss recovery. Run on a survivor whose controller service
is stopped. Every changing step asks for a typed confirmation.

  runbook        Print the full recovery procedure
  preflight      Check the broker is stopped and inventory its store
  backup         Copy the stopped survivor store with a SHA-256 manifest
  verify-backup  Recompute a backup's manifest
  render-retirement
                 Render <slot>.retirement-request.json for a lost peer whose
                 pinned instance OCI reports TERMINATED (no quorum needed)
  refound        Relaunch one lost peer slot from root-signed retirement
`

// recoveryInput is the operator's terminal; tests replace it.
var recoveryInput io.Reader = os.Stdin

// renderRetirement renders a lost slot's unsigned retirement request from the
// ledger and OCI; tests replace it.
var renderRetirement = func(ctx context.Context, slot, dir string) (string, error) {
	return app.RenderBreakGlassRetirementRequest(ctx, slot, dir, time.Now())
}

// refoundReplacer opens the seed founder replacer; tests replace it.
var refoundReplacer = func(ctx context.Context) (interface {
	Replace(context.Context, string, []byte) error
}, error) {
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, err
	}
	accepted, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return nil, err
	}
	if accepted.Slot != accepted.SeedSlot {
		return nil, errors.New("refound must run on the seed controller, which alone holds the founder signer")
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 {
		return nil, errors.New("refound must run as the controller service account")
	}
	return bootstrapstart.NewAdmittedFounderReplacer(ctx, baked, accepted, uint32(uid), uint32(gid))
}

func runCluster(ctx context.Context, args []string, out io.Writer) error {
	help := func(arg string) bool { return arg == "--help" || arg == "-h" || arg == "help" }
	if len(args) > 0 && !help(args[0]) && args[0] != "recover-quorum" {
		return fmt.Errorf("unknown cluster command %q", args[0])
	}
	if len(args) < 2 || help(args[0]) || help(args[1]) {
		_, err := io.WriteString(out, clusterUsage)
		return err
	}
	command, args := args[1], args[2:]
	flags := flag.NewFlagSet("recover-quorum "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "survivor controller.json")
	destination := flags.String("out", "", "new absolute backup directory, or render-retirement output directory")
	backupDir := flags.String("dir", "", "backup directory to verify")
	slot := flags.String("slot", "", "lost peer slot to re-found")
	retirement := flags.String("retirement", "", "root-signed <slot>.retirement envelope")
	backup := flags.String("backup", "", "verified survivor backup directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("recover-quorum takes only flags")
	}
	if command == "verify-backup" {
		if *backupDir == "" {
			return errors.New("verify-backup requires --dir")
		}
		files, err := membership.VerifyBackup(*backupDir)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "backup %s verified: %d files\n", *backupDir, files)
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("%s requires --config", command)
	}
	target, err := recoveryTarget(*configPath)
	if err != nil {
		return err
	}
	switch command {
	case "runbook":
		_, err := io.WriteString(out, membership.Runbook(target))
		return err
	case "preflight":
		_, err := membership.Preflight(ctx, target, out)
		return err
	case "backup":
		return membership.Backup(ctx, target, *destination, recoveryInput, out)
	case "render-retirement":
		if *slot == "" || *destination == "" || !filepath.IsAbs(*destination) {
			return errors.New("render-retirement requires --slot and an absolute --out directory")
		}
		if *slot == target.Slot {
			return errors.New("render-retirement cannot retire the local survivor slot")
		}
		path, err := renderRetirement(ctx, *slot, *destination)
		if err != nil {
			return fmt.Errorf("render %s retirement request: %w", *slot, err)
		}
		_, err = fmt.Fprintf(out, "wrote %s; root-sign it offline with ts-orch bootstrap sign-slot-retirement\n", path)
		return err
	case "refound":
		return refound(ctx, target, *slot, *retirement, *backup, out)
	default:
		return fmt.Errorf("unknown recover-quorum command %q", command)
	}
}

func recoveryTarget(path string) (membership.RecoveryTarget, error) {
	cfg, err := app.LoadConfig(path)
	if err != nil {
		return membership.RecoveryTarget{}, err
	}
	embedded := cfg.NATS.Embedded
	if embedded == nil || cfg.NATS.Cell == "" || cfg.NATS.Instance == "" {
		return membership.RecoveryTarget{}, errors.New("recovery needs a controller config with an embedded broker")
	}
	target := membership.RecoveryTarget{Cell: cfg.NATS.Cell, Slot: cfg.NATS.Instance, StoreDir: embedded.StoreDir}
	if embedded.Port > 0 {
		target.ClientAddress = net.JoinHostPort(embedded.Host, strconv.Itoa(embedded.Port))
	}
	if embedded.RoutePort > 0 {
		target.RouteAddress = net.JoinHostPort(embedded.RouteHost, strconv.Itoa(embedded.RoutePort))
	}
	return target, nil
}

func refound(ctx context.Context, target membership.RecoveryTarget, slot, retirementPath, backup string,
	out io.Writer,
) error {
	if slot == "" || retirementPath == "" || backup == "" {
		return errors.New("refound requires --slot, --retirement and --backup")
	}
	if slot == target.Slot {
		return errors.New("refound cannot relaunch the local survivor slot")
	}
	if err := membership.BrokerStopped(ctx, target); err != nil {
		return err
	}
	files, err := membership.VerifyBackup(backup)
	if err != nil {
		return fmt.Errorf("refound requires a verified survivor backup: %w", err)
	}
	info, err := os.Lstat(retirementPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return errors.New("retirement evidence must be a bounded regular file")
	}
	wire, err := os.ReadFile(retirementPath)
	if err != nil {
		return err
	}
	evidence, err := bootstrap.DecodeSlotRetirementCandidate(wire)
	if err != nil {
		return err
	}
	if evidence.Slot != slot {
		return errors.New("retirement evidence names a different slot")
	}
	fmt.Fprintf(out, "survivor backup %s verified (%d files)\nretiring %s attempt %d instance %s (signed observation %s)\n",
		backup, files, evidence.Slot, evidence.PreviousAttempt, evidence.PriorInstanceOCID,
		evidence.ObservedAt.Format("2006-01-02T15:04:05Z"))
	if err := membership.Confirm(recoveryInput, out,
		"this launches a new OCI instance for the slot at its old private IP. The retired instance must be TERMINATED.",
		"re-found "+target.Cell+"/"+slot); err != nil {
		return err
	}
	replacer, err := refoundReplacer(ctx)
	if err != nil {
		return err
	}
	if err := replacer.Replace(ctx, slot, wire); err != nil {
		return fmt.Errorf("re-found %s: %w", slot, err)
	}
	_, err = fmt.Fprintf(out, "re-founded %s as attempt %d; start the survivor controller once every lost slot is re-founded\n",
		slot, evidence.PreviousAttempt+1)
	return err
}
