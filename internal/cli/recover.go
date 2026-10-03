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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
)

const clusterUsage = `Usage: ts-orch cluster recover-quorum <command> [flags]

Break-glass quorum-loss recovery on a survivor controller. preflight and backup
need its controller service stopped; refound needs it running again. Every
changing step asks for a typed confirmation; see runbook for the order.

  runbook        Print the full recovery procedure
  preflight      Check the broker is stopped and inventory its store
  backup         Copy the stopped survivor store with a SHA-256 manifest
  verify-backup  Recompute a backup's manifest
  render-retirement
                 Render <slot>.retirement-request.json for a lost peer whose
                 pinned instance OCI reports TERMINATED (no quorum needed)
  refound        Relaunch one lost peer slot from root-signed retirement
                 (the survivor broker must be running)
`

// recoveryInput is the operator's terminal; tests replace it.
var recoveryInput io.Reader = os.Stdin

// renderRetirement renders a lost slot's unsigned retirement request from the
// ledger and OCI; tests replace it.
var renderRetirement = func(ctx context.Context, slot, dir string) (string, error) {
	return app.RenderBreakGlassRetirementRequest(ctx, slot, dir, time.Now())
}

// localAdmittedInstall reads this host's accepted controller install; tests
// replace it.
var localAdmittedInstall = func() (bootstrapstart.AcceptedInstall, error) {
	return bootstrapstart.NewMarkerStore().Read()
}

// refoundReplacer opens the seed founder replacer for the accepted install
// the recovery config was bound to; tests replace it.
var refoundReplacer = func(ctx context.Context, accepted bootstrapstart.AcceptedInstall) (interface {
	Replace(context.Context, string, []byte) error
}, error) {
	baked, err := bootstrapstart.LoadBakedInputs()
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

// refoundLedger reads every controller slot's verified ledger HEAD; tests
// replace it.
var refoundLedger = func(ctx context.Context) (map[string]membership.LedgerSlot, error) {
	return app.ControllerSlotLedger(ctx)
}

// refoundGuard keeps re-founding to one slot at a time and waits for each
// re-founded slot to report current; tests replace it and the wait bounds.
var (
	refoundGuard = membership.RefoundGuard{PendingPath: membership.DefaultRefoundPendingFile,
		HealthPath: membership.DefaultClusterHealthFile}
	refoundPoll = 5 * time.Second
	refoundWait = 30 * time.Minute
)

// recoverFlags lists the flags each recover-quorum command honours; any
// other flag is an error rather than silently ignored.
var recoverFlags = map[string][]string{
	"runbook":           {"config"},
	"preflight":         {"config"},
	"backup":            {"config", "out"},
	"verify-backup":     {"dir"},
	"render-retirement": {"config", "slot", "out"},
	"refound":           {"config", "slot", "retirement", "backup"},
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
	allowed, known := recoverFlags[command]
	if !known {
		return fmt.Errorf("unknown recover-quorum command %q", command)
	}
	flags := flag.NewFlagSet("recover-quorum "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "survivor controller.json")
	destination := flags.String("out", "", "new absolute backup directory, or render-retirement output directory")
	backupDir := flags.String("dir", "", "backup directory to verify")
	slot := flags.String("slot", "", "lost peer slot to re-found")
	retirement := flags.String("retirement", "", "root-signed <slot>.retirement envelope")
	backup := flags.String("backup", "", "verified survivor backup directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := io.WriteString(out, clusterUsage)
			return err
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("recover-quorum takes only flags")
	}
	var unused []string
	flags.Visit(func(set *flag.Flag) {
		if !slices.Contains(allowed, set.Name) {
			unused = append(unused, "--"+set.Name)
		}
	})
	if len(unused) != 0 {
		return fmt.Errorf("recover-quorum %s does not take %s", command, strings.Join(unused, ", "))
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
	}
	// Every changing command acts for the locally admitted controller, so
	// the recovery config must describe that controller before any check or
	// confirmation uses it.
	accepted, err := bindLocalAdmittedInstall(target)
	if err != nil {
		return err
	}
	switch command {
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
	default: // refound
		return refound(ctx, target, accepted, *slot, *retirement, *backup, out)
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
	// Without a fixed client and route port neither a stopped nor a
	// running broker can be established.
	if embedded.Port <= 0 || embedded.RoutePort <= 0 || embedded.Host == "" || embedded.RouteHost == "" {
		return membership.RecoveryTarget{}, errors.New("recovery needs the embedded broker's fixed client and route listeners")
	}
	return membership.RecoveryTarget{Cell: cfg.NATS.Cell, Slot: cfg.NATS.Instance, StoreDir: embedded.StoreDir,
		ClientAddress: net.JoinHostPort(embedded.Host, strconv.Itoa(embedded.Port)),
		RouteAddress:  net.JoinHostPort(embedded.RouteHost, strconv.Itoa(embedded.RoutePort))}, nil
}

// bindLocalAdmittedInstall requires the recovery config to name the cell,
// slot and broker address of the controller admitted on this host.
func bindLocalAdmittedInstall(target membership.RecoveryTarget) (bootstrapstart.AcceptedInstall, error) {
	accepted, err := localAdmittedInstall()
	if err != nil {
		return bootstrapstart.AcceptedInstall{}, fmt.Errorf("read the locally admitted controller: %w", err)
	}
	host, _, err := net.SplitHostPort(target.ClientAddress)
	if err != nil || !strings.EqualFold(accepted.Cell, target.Cell) || accepted.Slot != target.Slot ||
		accepted.PrimaryPrivateIP != host {
		return bootstrapstart.AcceptedInstall{}, fmt.Errorf(
			"--config describes %s/%s at %s, not the controller admitted on this host (%s/%s at %s)",
			target.Cell, target.Slot, host, accepted.Cell, accepted.Slot, accepted.PrimaryPrivateIP)
	}
	return accepted, nil
}

// readRetirementEvidence opens the envelope once and checks the type and
// size of the very file it reads, so a path swapped after a check cannot
// turn the read into a FIFO block or an unbounded allocation.
func readRetirementEvidence(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRetirementEvidenceBytes {
		return nil, errors.New("retirement evidence must be a bounded regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxRetirementEvidenceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 || len(wire) > maxRetirementEvidenceBytes {
		return nil, errors.New("retirement evidence must be a bounded regular file")
	}
	return wire, nil
}

const maxRetirementEvidenceBytes = 64 << 10

func refound(ctx context.Context, target membership.RecoveryTarget, accepted bootstrapstart.AcceptedInstall,
	slot, retirementPath, backup string, out io.Writer,
) error {
	if slot == "" || retirementPath == "" || backup == "" {
		return errors.New("refound requires --slot, --retirement and --backup")
	}
	if slot == target.Slot {
		return errors.New("refound cannot relaunch the local survivor slot")
	}
	// The data-bearing survivor must already run, so the empty replacement
	// joins its metadata group instead of forming one with another empty
	// replacement.
	if err := membership.BrokerRunning(ctx, target); err != nil {
		return err
	}
	// One slot at a time: no other slot may be mid-replacement in the
	// ledger, and the slot re-founded before must report current. The host
	// lock covers admission through the wait, so a concurrent refound for
	// another slot cannot pass admission on the same old ledger.
	release, err := refoundGuard.Lock()
	if err != nil {
		return err
	}
	defer release()
	ledger, err := refoundLedger(ctx)
	if err != nil {
		return fmt.Errorf("read the controller slot ledger: %w", err)
	}
	if err := refoundGuard.Admit(target.Cell, slot, ledger); err != nil {
		return err
	}
	files, err := membership.VerifyBackupFor(backup, target, time.Now(), membership.BackupMaxAge)
	if err != nil {
		return fmt.Errorf("refound requires a verified backup of this survivor: %w", err)
	}
	wire, err := readRetirementEvidence(retirementPath)
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
	if err := membership.Confirm(ctx, recoveryInput, out,
		"this launches a new OCI instance for the slot at its old private IP. The retired instance must be TERMINATED.",
		"re-found "+target.Cell+"/"+slot); err != nil {
		return err
	}
	replacer, err := refoundReplacer(ctx, accepted)
	if err != nil {
		return err
	}
	serverName := membership.Topology{Cell: target.Cell}.ServerName(slot)
	pending := membership.RefoundPending{Cell: target.Cell, Slot: slot, ServerName: serverName,
		Attempt: evidence.PreviousAttempt + 1, StartedAt: time.Now().UTC()}
	if err := refoundGuard.Begin(pending); err != nil {
		return fmt.Errorf("record the pending refound: %w", err)
	}
	if err := replacer.Replace(ctx, slot, wire); err != nil {
		return fmt.Errorf("re-found %s: %w", slot, err)
	}
	fmt.Fprintf(out, "re-founded %s as attempt %d; waiting until it reports current\n", slot, evidence.PreviousAttempt+1)
	if err := refoundGuard.WaitCurrent(ctx, pending, refoundPoll, refoundWait, out); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s reports current; the next lost slot may be re-founded\n", serverName)
	return err
}
