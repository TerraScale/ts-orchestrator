// Package cli provides the self-update commands of the unified executable.
// prepare and watchdog run as root from the opt-in systemd drop-ins; stage
// and activate are the root-run steps a rollout executor performs on a node.
package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const usage = `Usage: ts-orch selfupdate <command> [flags]

Commands:
  prepare    Seed the baked release and resolve an expired activation (ExecStartPre)
  watchdog   Confirm or roll back a pending activation (timer)
  stage      Verify a release receipt and stage its binary
  activate   Flip the current link to a staged release
  status     Print the current release and any pending activation
`

// Restarter restarts a systemd unit after a rollback or activation.
type Restarter func(ctx context.Context, unit string) error

// SystemctlRestart asks systemd for a non-blocking restart, exactly like the
// existing host-setup unit does.
func SystemctlRestart(ctx context.Context, unit string) error {
	output, err := exec.CommandContext(ctx, "systemctl", "--no-block", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart %s: %w: %s", unit, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type command struct {
	ctx     context.Context
	output  io.Writer
	now     func() time.Time
	restart Restarter
}

// Run executes one self-update command.
func Run(ctx context.Context, args []string, output io.Writer) error {
	return run(ctx, args, output, time.Now, SystemctlRestart)
}

func run(ctx context.Context, args []string, output io.Writer, now func() time.Time, restart Restarter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	writer := commandio.NewWriter(output)
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(writer, usage)
		return errors.Join(err, writer.Err())
	}
	c := command{ctx: ctx, output: writer, now: now, restart: restart}
	var err error
	switch args[0] {
	case "prepare":
		err = c.prepare(args[1:])
	case "watchdog":
		err = c.watchdog(args[1:])
	case "stage":
		err = c.stage(args[1:])
	case "activate":
		err = c.activate(args[1:])
	case "status":
		err = c.status(args[1:])
	default:
		err = fmt.Errorf("unknown selfupdate command %q", args[0])
	}
	return errors.Join(err, writer.Err())
}

type layoutFlags struct {
	root  *string
	owner *int
}

func addLayout(flags *flag.FlagSet) layoutFlags {
	return layoutFlags{
		root:  flags.String("root", selfupdate.DefaultRoot, "release root"),
		owner: flags.Int("owner", 0, "uid that must own the release root"),
	}
}

func (l layoutFlags) layout() selfupdate.Layout {
	return selfupdate.Layout{Root: *l.root, Owner: *l.owner}
}

type proofFlags struct {
	file *string
	key  *string
}

func addProof(flags *flag.FlagSet) proofFlags {
	return proofFlags{
		file: flags.String("proof-file", "", "version proof written by the unit's healthy process"),
		key:  flags.String("proof-key-file", "", "the unit's base64 Ed25519 identity key; only its public half is used"),
	}
}

func (p proofFlags) check() (selfupdate.ProofCheck, error) {
	if *p.file == "" && *p.key == "" {
		return selfupdate.ProofCheck{}, nil
	}
	if *p.file == "" || *p.key == "" {
		return selfupdate.ProofCheck{}, errors.New("--proof-file and --proof-key-file are required together")
	}
	public, err := readIdentityPublicKey(*p.key)
	if err != nil {
		// An unusable key disables confirmation, never rollback: the
		// deadline logic still runs and restores the previous release.
		slog.Warn("self-update proof key is unusable; activations cannot be confirmed and roll back at their deadline",
			"key", *p.key, "error", err)
		return selfupdate.ProofCheck{File: *p.file}, nil
	}
	return selfupdate.ProofCheck{File: *p.file, PublicKey: public}, nil
}

func parse(flags *flag.FlagSet, args []string) error {
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s takes no positional arguments", flags.Name())
	}
	return nil
}

func (c command) prepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	layout := addLayout(flags)
	proof := addProof(flags)
	unit := flags.String("unit", "", "systemd unit that executes the current release")
	baked := flags.String("baked-binary", selfupdate.DefaultBakedBinary, "image-installed binary")
	if err := parse(flags, args); err != nil {
		return err
	}
	check, err := proof.check()
	if err != nil {
		return err
	}
	unlock, err := layout.layout().Lock()
	if err != nil {
		return err
	}
	defer unlock()
	outcome, err := selfupdate.Prepare(layout.layout(), *unit, *baked, check, c.now())
	if err != nil {
		return err
	}
	current, err := layout.layout().Current()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "selfupdate prepare unit=%s outcome=%s current=%s\n", *unit, outcome, current)
	return err
}

func (c command) watchdog(args []string) error {
	flags := flag.NewFlagSet("watchdog", flag.ContinueOnError)
	layout := addLayout(flags)
	proof := addProof(flags)
	unit := flags.String("unit", "", "systemd unit that executes the current release")
	restart := flags.Bool("restart", false, "restart the unit after a rollback")
	if err := parse(flags, args); err != nil {
		return err
	}
	check, err := proof.check()
	if err != nil {
		return err
	}
	unlock, err := layout.layout().Lock()
	if err != nil {
		return err
	}
	outcome, activation, err := selfupdate.Watch(layout.layout(), *unit, check, c.now())
	if err != nil {
		unlock()
		return err
	}
	// A rollback leaves a restart obligation until the unit restarts, so a
	// failed systemctl call, an output error or a crash after the link moved
	// is retried by the next timer run instead of reading as idle.
	owed, err := layout.layout().RestartPending(*unit)
	unlock()
	if err != nil {
		return err
	}
	_, printErr := fmt.Fprintf(c.output, "selfupdate watchdog unit=%s outcome=%s activation=%s target=%s\n",
		*unit, outcome, activation.ActivationID, activation.Target)
	if owed && *restart {
		if err := c.restart(c.ctx, *unit); err != nil {
			return errors.Join(err, printErr)
		}
		unlock, err := layout.layout().Lock()
		if err != nil {
			return errors.Join(err, printErr)
		}
		defer unlock()
		return errors.Join(layout.layout().ClearRestartPending(*unit), printErr)
	}
	return printErr
}

func (c command) stage(args []string) error {
	flags := flag.NewFlagSet("stage", flag.ContinueOnError)
	layout := addLayout(flags)
	binary := flags.String("binary", "", "binary to stage")
	receipt := flags.String("receipt", "", "signed binary receipt or update receipt")
	delegation := flags.String("delegation", "", "root-signed release or binary update delegation")
	rootKey := flags.String("root-key", "", "offline root Ed25519 PKIX public key PEM")
	environment := flags.String("environment", "", "this node's release environment")
	cell := flags.String("cell", "", "this node's logical cell: GRU, SFO or FRA")
	architecture := flags.String("arch", runtime.GOARCH, "this node's architecture")
	allowAuto := flags.Bool("allow-scoped-auto-sign", false, "accept update receipts signed under a scoped binary update delegation")
	if err := parse(flags, args); err != nil {
		return err
	}
	if *binary == "" || *receipt == "" || *delegation == "" || *rootKey == "" || *environment == "" {
		return errors.New("stage requires --binary, --receipt, --delegation, --root-key and --environment")
	}
	roots, err := readRootKeyring(*rootKey)
	if err != nil {
		return err
	}
	receiptWire, err := readSmall(*receipt)
	if err != nil {
		return err
	}
	delegationWire, err := readSmall(*delegation)
	if err != nil {
		return err
	}
	source, err := os.Open(*binary)
	if err != nil {
		return err
	}
	defer source.Close()
	policy := selfupdate.ReceiptPolicy{Roots: roots, Environment: *environment, Cell: *cell,
		Architecture: *architecture, AllowScopedAutoSign: *allowAuto}
	unlock, err := layout.layout().Lock()
	if err != nil {
		return err
	}
	defer unlock()
	digest, err := selfupdate.Stage(layout.layout(), source, receiptWire, delegationWire, policy, c.now().UTC())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "selfupdate staged release=%s\n", digest)
	return err
}

func (c command) activate(args []string) error {
	flags := flag.NewFlagSet("activate", flag.ContinueOnError)
	layout := addLayout(flags)
	digest := flags.String("release", "", "staged release SHA-256")
	unit := flags.String("unit", "", "systemd unit that executes the current release")
	window := flags.Duration("proof-window", 5*time.Minute, "deadline for the new process's signed version proof")
	restart := flags.Bool("restart", false, "restart the unit after flipping the current link")
	if err := parse(flags, args); err != nil {
		return err
	}
	unlock, err := layout.layout().Lock()
	if err != nil {
		return err
	}
	activation, err := selfupdate.Activate(layout.layout(), *digest, *unit, c.now(), *window)
	unlock()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.output, "selfupdate activated release=%s previous=%s activation=%s deadline=%s\n",
		activation.Target, activation.Previous, activation.ActivationID, activation.Deadline.Format(time.RFC3339)); err != nil {
		return err
	}
	if *restart {
		return c.restart(c.ctx, *unit)
	}
	return nil
}

func (c command) status(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	layout := addLayout(flags)
	if err := parse(flags, args); err != nil {
		return err
	}
	current, err := layout.layout().Current()
	if err != nil {
		return err
	}
	activation, pending, err := layout.layout().Pending()
	if err != nil {
		return err
	}
	if !pending {
		_, err = fmt.Fprintf(c.output, "current=%s pending=none\n", current)
		return err
	}
	_, err = fmt.Fprintf(c.output, "current=%s pending=%s target=%s previous=%s deadline=%s\n", current,
		activation.ActivationID, activation.Target, activation.Previous, activation.Deadline.Format(time.RFC3339))
	return err
}

func readSmall(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, trust.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > trust.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return bytes.TrimSuffix(data, []byte("\n")), nil
}

func readRootKeyring(path string) (trust.Keyring, error) {
	data, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("root key must be one PKIX public key PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("root key must be Ed25519")
	}
	return trust.ParseKeyring(public)
}

// readIdentityPublicKey derives the public key from the unit's base64
// Ed25519 identity key file, the same format the runtime loads.
func readIdentityPublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("proof key must be a regular file readable only by its owner")
	}
	data, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("proof key must contain 64 base64 Ed25519 bytes")
	}
	return ed25519.PrivateKey(decoded).Public().(ed25519.PublicKey), nil
}
