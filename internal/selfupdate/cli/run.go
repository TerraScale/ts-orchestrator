// Package cli provides the self-update commands of the unified executable.
// prepare and watchdog run as root from the image's systemd drop-ins; stage
// and activate are the root-run steps a rollout executor performs on a node.
package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
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

// maxRoleConfigBytes matches the controller and host config bound.
const maxRoleConfigBytes = 1 << 20

// delegatedEnv marks a root step that the image-baked binary handed to the
// known-good release, which then runs it itself.
const delegatedEnv = "TS_SELFUPDATE_DELEGATED"

// delegateTimeout bounds a delegated step, leaving the image-baked binary
// time to run it within the watchdog unit's TimeoutStartSec=60s when the
// known-good release hangs.
var delegateTimeout = 30 * time.Second

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
	file   *string
	key    *string
	config *string
}

func addProof(flags *flag.FlagSet) proofFlags {
	return proofFlags{
		file:   flags.String("proof-file", "", "version proof written by the unit's healthy process"),
		key:    flags.String("proof-key-file", "", "the unit's base64 Ed25519 identity key; only its public half is used"),
		config: flags.String("config", "", "the unit's role config, which names its proof file and key instead of --proof-file and --proof-key-file"),
	}
}

func (p proofFlags) check(root, unit string) (selfupdate.ProofCheck, error) {
	if *p.config != "" {
		if *p.file != "" || *p.key != "" {
			return selfupdate.ProofCheck{}, errors.New("--config replaces --proof-file and --proof-key-file")
		}
		file, key, err := roleProof(*p.config, root, unit)
		if errors.Is(err, os.ErrNotExist) {
			// The role is not configured on this node, so no process of
			// this unit can prove anything; deadlines still roll back.
			return selfupdate.ProofCheck{}, nil
		}
		if err != nil {
			slog.Warn("self-update role config is unusable; activations cannot be confirmed and roll back at their deadline",
				"config", *p.config, "error", err)
			return selfupdate.ProofCheck{}, nil
		}
		*p.file, *p.key = file, key
	}
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
	systemd := flags.String("systemd-dir", "/etc/systemd/system", "unit directory that takes the host-setup and bootstrap drop-ins")
	if err := parse(flags, args); err != nil {
		return err
	}
	if c.delegate(layout.layout(), append([]string{"prepare"}, args...)) {
		return c.backstopPrepare(layout.layout(), *unit)
	}
	check, err := proof.check(*layout.root, *unit)
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
	if _, err = fmt.Fprintf(c.output, "selfupdate prepare unit=%s outcome=%s current=%s\n", *unit, outcome, current); err != nil {
		return err
	}
	// The controller process cannot write its credential directory or
	// controller.json; its armed material generation installs here (TS-668).
	if *unit == selfupdate.ControllerUnit {
		material, err := installGeneration(c.now())
		if err != nil {
			return err
		}
		if material != "" {
			if _, err := fmt.Fprintf(c.output, "selfupdate prepare material-generation: %s\n", material); err != nil {
				return err
			}
		}
	}
	// A node whose image predates a drop-in gets it from the release that
	// runs this step; a failure must not stop the unit's start.
	for _, dropin := range []struct {
		name    string
		install func(string) (bool, error)
	}{{"host-setup", selfupdate.InstallHostSetupDropin}, {"bootstrap", selfupdate.InstallBootstrapDropin}} {
		if installed, err := dropin.install(*systemd); err != nil {
			slog.Warn("self-update could not install the "+dropin.name+" drop-in", "error", err)
		} else if installed {
			if _, err := fmt.Fprintf(c.output, "selfupdate prepare installed the %s drop-in; it applies from the next boot\n", dropin.name); err != nil {
				return err
			}
		}
	}
	return nil
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
	delegated := c.delegate(layout.layout(), append([]string{"watchdog"}, args...))
	var check selfupdate.ProofCheck
	if !delegated {
		var err error
		if check, err = proof.check(*layout.root, *unit); err != nil {
			return err
		}
	}
	unlock, err := layout.layout().Lock()
	if err != nil {
		return err
	}
	var outcome selfupdate.Outcome
	var activation selfupdate.Activation
	if delegated {
		outcome, activation, err = selfupdate.Backstop(layout.layout(), c.now())
	} else {
		outcome, activation, err = selfupdate.Watch(layout.layout(), *unit, check, c.now())
	}
	if err != nil {
		unlock()
		return err
	}
	// The rollout step runs after the check, so a slow or stuck step never
	// delays a rollback, and before the restart below serves what it owes.
	if !delegated && *restart && (*unit == selfupdate.ControllerUnit || *unit == selfupdate.HostUnit) && *proof.config != "" {
		unlock()
		c.rolloutStep(layout.layout(), *unit, *proof.config)
		if unlock, err = layout.layout().Lock(); err != nil {
			return err
		}
	}
	// A rollback leaves a restart obligation until the unit restarts, so a
	// failed systemctl call, an output error or a crash after the link moved
	// is retried by the next timer run instead of reading as idle.
	owed, err := layout.layout().RestartPending(*unit)
	unlock()
	if err != nil {
		return err
	}
	var printErr error
	if !delegated || outcome == selfupdate.OutcomeRolledBack {
		_, printErr = fmt.Fprintf(c.output, "selfupdate watchdog unit=%s outcome=%s activation=%s target=%s\n",
			*unit, outcome, activation.ActivationID, activation.Target)
	}
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

// delegate runs a root step (prepare or watchdog) with the node's known-good
// release instead of the image-baked binary, so the self-update logic moves
// with every confirmed release and the image's copy is only the entry point
// and fallback. It reports whether that release ran the step. When it could
// not (missing, unverified, known bad, or the step failed or hung), the caller runs
// the step itself: a release with broken root steps degrades to the image's
// logic instead of disabling rollback or blocking the unit's start.
func (c command) delegate(layout selfupdate.Layout, args []string) bool {
	if os.Getenv(delegatedEnv) != "" {
		return false
	}
	digest, err := layout.Delegate()
	if err != nil {
		slog.Warn("self-update known-good release is unusable; the image-baked binary runs the step", "error", err)
	}
	if err != nil || digest == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(c.ctx, delegateTimeout)
	defer cancel()
	step := exec.CommandContext(ctx, layout.BinaryPath(digest), append([]string{"selfupdate"}, args...)...)
	step.Env = append(os.Environ(), delegatedEnv+"=1")
	step.Stdout, step.Stderr = c.output, os.Stderr
	step.WaitDelay = time.Second
	if err := step.Run(); err != nil {
		slog.Warn("self-update known-good release failed the step; the image-baked binary runs it", "release", digest, "error", err)
		return false
	}
	return true
}

// backstopPrepare keeps the image's start invariants after the known-good
// release ran prepare: an activation long past its deadline is rolled back
// and a current release whose bytes do not verify never starts.
func (c command) backstopPrepare(layout selfupdate.Layout, unit string) error {
	unlock, err := layout.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	outcome, activation, err := selfupdate.Backstop(layout, c.now())
	if err != nil {
		return err
	}
	// This start serves the restart the rollback owes the unit.
	if outcome == selfupdate.OutcomeRolledBack && activation.Unit == unit {
		if err := layout.ClearRestartPending(unit); err != nil {
			return err
		}
	}
	current, err := layout.Current()
	if err != nil {
		return err
	}
	if err := layout.VerifyRelease(current); err != nil {
		return fmt.Errorf("current release does not verify: %w", err)
	}
	return nil
}

// The step spools of the controller and the host, and the image's trust
// roots; tests replace them.
var (
	rolloutSpoolDir = rolloutexec.DefaultSpoolDir
	hostSpoolDir    = rolloutexec.HostSpoolDir
	bakedInputs     = bootstrapstart.LoadBakedInputs
	// installGeneration is prepare's material step for the controller unit.
	installGeneration = bootstrapstart.InstallGeneration
)

// rolloutStep is the node's root step agent for unit: it applies the
// rollout step the unit's process spooled (rolloutexec.ApplySpooled),
// verifying the leader's signature and staging a release only from a
// receipt this node's baked roots verify. It runs where the unit takes part
// in rollouts, with the same production defaults as the unit's process
// (app.rolloutSettings, app.hostRolloutSpool): a controller config without
// a rollouts block or with the executor on, and a host that is not a lab.
// A problem is logged, never returned, so the watchdog's own check always
// runs.
func (c command) rolloutStep(layout selfupdate.Layout, unit, configPath string) {
	role, err := readRolloutRole(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("rollout step agent: role config is unusable", "config", configPath, "error", err)
		}
		return
	}
	node, spool, allowScoped := role.Host.Node, hostSpoolDir, true
	var public ed25519.PublicKey
	if unit == selfupdate.ControllerUnit {
		defaults := role.Controller.Rollouts == nil && !role.NATS.Lab
		if !defaults && (role.Controller.Rollouts == nil || !role.Controller.Rollouts.Executor) {
			return
		}
		node, spool = role.NATS.Instance, rolloutSpoolDir
		allowScoped = defaults || role.Controller.Rollouts.AllowScopedAutoSign
		public, err = readIdentityPublicKey(role.Controller.ResponseKeyFile)
	} else {
		// A host on a controller's VM shares its release root and moves with
		// the controller; a step for it would move the controller's link.
		if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), "controller.json")); err == nil {
			return
		}
		if role.NATS.Lab || role.Host.Node == "" {
			return
		}
		var decoded []byte
		decoded, err = base64.StdEncoding.DecodeString(strings.TrimSpace(role.Host.ControllerPublicKey))
		if err == nil && len(decoded) != ed25519.PublicKeySize {
			err = errors.New("not an Ed25519 public key")
		}
		public = decoded
	}
	if err != nil {
		slog.Warn("rollout step agent: the leaders' key is unusable", "error", err)
		return
	}
	leaders, err := trust.ParseKeyring(public)
	if err != nil {
		slog.Warn("rollout step agent: the leaders' key is unusable", "error", err)
		return
	}
	baked, err := bakedInputs()
	if err != nil {
		slog.Warn("rollout step agent: image trust roots are unusable", "error", err)
		return
	}
	// Only the chain's current roots admit a release, as on the leader.
	roots, err := trust.VerifyRootChain(baked.Genesis, baked.Identity.ChainIdentity(), baked.Chain)
	if err != nil {
		slog.Warn("rollout step agent: the adopted root chain does not verify", "error", err)
		return
	}
	verifier := selfupdate.ReceiptPolicy{Roots: roots.Current, Environment: baked.Identity.Environment,
		Cell: strings.ToUpper(role.NATS.Cell), Architecture: runtime.GOARCH, AllowScopedAutoSign: allowScoped}
	agent := &rolloutexec.Agent{Cell: role.NATS.Cell, Unit: node, SystemdUnit: unit, Layout: layout, Leaders: leaders,
		Now: c.now, Restart: func(context.Context, string) error { return nil }}
	if err := rolloutexec.ApplySpooled(c.ctx, agent, spool, verifier); err != nil {
		slog.Warn("rollout step agent", "error", err)
	}
}

// rolloutRole is the part of a controller or host config the step agent
// reads, decoded leniently like roleProof.
type rolloutRole struct {
	NATS struct {
		Cell     string `json:"cell"`
		Instance string `json:"instance"`
		Lab      bool   `json:"lab"`
	} `json:"nats"`
	Controller struct {
		ResponseKeyFile string `json:"response_key_file"`
		Rollouts        *struct {
			Executor            bool `json:"executor"`
			AllowScopedAutoSign bool `json:"allow_scoped_auto_sign"`
		} `json:"rollouts"`
	} `json:"controller"`
	Host struct {
		Node                string `json:"node"`
		ControllerPublicKey string `json:"controller_public_key"`
	} `json:"host"`
}

func readRolloutRole(path string) (rolloutRole, error) {
	var role rolloutRole
	file, err := os.Open(path)
	if err != nil {
		return role, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRoleConfigBytes+1))
	if err != nil {
		return role, err
	}
	if len(data) > maxRoleConfigBytes {
		return role, errors.New("role config is too large")
	}
	return role, json.Unmarshal(data, &role)
}

// roleProof returns the proof file and identity key that a controller or
// host config names for unit. The watchdog runs the image-baked binary, so
// the config is decoded leniently: a self-updated release may have added
// fields this binary does not know.
func roleProof(path, root, unit string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRoleConfigBytes+1))
	if err != nil {
		return "", "", err
	}
	if len(data) > maxRoleConfigBytes {
		return "", "", errors.New("role config is too large")
	}
	var config struct {
		Controller struct {
			ResponseKeyFile     string `json:"response_key_file"`
			SelfUpdateProofFile string `json:"self_update_proof_file"`
			SelfUpdateRoot      string `json:"self_update_root"`
		} `json:"controller"`
		Host struct {
			IdentityKeyFile     string `json:"identity_key_file"`
			SelfUpdateProofFile string `json:"self_update_proof_file"`
			SelfUpdateRoot      string `json:"self_update_root"`
		} `json:"host"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", "", err
	}
	var proof, key, configured string
	switch unit {
	case selfupdate.ControllerUnit:
		proof, key, configured = config.Controller.SelfUpdateProofFile, config.Controller.ResponseKeyFile, config.Controller.SelfUpdateRoot
	case selfupdate.HostUnit:
		proof, key, configured = config.Host.SelfUpdateProofFile, config.Host.IdentityKeyFile, config.Host.SelfUpdateRoot
	default:
		return "", "", fmt.Errorf("unit %s has no role config", unit)
	}
	if key == "" {
		return "", "", errors.New("role config names no identity key")
	}
	// The process proves activations under its own root only.
	if configured != "" && configured != root {
		return "", "", fmt.Errorf("role config self_update_root %s differs from --root %s", configured, root)
	}
	if proof == "" {
		proof = selfupdate.DefaultProofFile(root, unit)
	}
	return proof, key, nil
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
