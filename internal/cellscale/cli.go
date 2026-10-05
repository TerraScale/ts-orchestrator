package cellscale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

const usage = `Usage: ts-orch cell-autoscaler <command> [flags]

  check   Validate a cell autoscaler config and print its cost range;
          --oci also checks the template, shape and quota against OCI (read only)
  run     Run the cell autoscaler loop (dry run unless --live)
`

const cellLockDirectory = "/run/lock/ts-orch-cell-autoscaler"

// FileConfig is the cell autoscaler's configuration file.
type FileConfig struct {
	Cell            string `json:"cell"`
	IntervalSeconds int    `json:"interval_seconds"`
	// Endpoint is every node's base URL, with {node} for the node name.
	Endpoint string   `json:"endpoint"`
	Policy   Policy   `json:"policy"`
	Template Template `json:"template"`
}

// Validate checks the whole file before anything reads OCI.
func (f FileConfig) Validate() error {
	if err := ValidateCell(f.Cell); err != nil {
		return err
	}
	if f.IntervalSeconds < 10 || f.IntervalSeconds > 3600 {
		return errors.New("interval_seconds must be within 10..3600")
	}
	endpoint, err := url.Parse(strings.ReplaceAll(f.Endpoint, "{node}", "node"))
	if err != nil || !strings.Contains(f.Endpoint, "{node}") || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Opaque != "" {
		return errors.New("endpoint must be an http(s) URL with a hostname and {node}")
	}
	if err := f.Policy.Validate(); err != nil {
		return err
	}
	return f.Template.Validate()
}

// Run dispatches ts-orch cell-autoscaler.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}
	fs := flag.NewFlagSet("cell-autoscaler "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "cell autoscaler config JSON")
	once := fs.Bool("once", false, "run one evaluation and exit")
	preflight := fs.Bool("oci", false, "check: read the template's image, subnet, shape and quota from OCI")
	live := fs.Bool("live", false, "apply actions to OCI and TerraBase; without it every action is a dry run")
	gate := fs.String("rollout-gate", "", `URL answering {"in_flight": bool}; required with --live`)
	if args[0] != "check" && args[0] != "run" {
		return fmt.Errorf("unknown cell-autoscaler command %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.PrintDefaults()
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	config, err := readConfig(*path)
	if err != nil {
		return err
	}
	if args[0] == "check" {
		bounds := config.Policy.Shape
		report := map[string]any{
			"cell":                   config.Cell,
			"lock_file":              filepath.Join(cellLockDirectory, cellLockName(config)),
			"launch_journal":         launchJournalPath(config),
			"initial_launch_journal": initialLaunchJournal(config),
			"min_monthly_cost":       config.Policy.MonthlyCost(config.Policy.Nodes.Min, bounds.at(bounds.MinOCPUs)),
			"max_monthly_cost":       config.Policy.MonthlyCost(config.Policy.Nodes.Max, bounds.at(bounds.MaxOCPUs)),
			"monthly_budget":         config.Policy.MonthlyBudget,
		}
		var problems []string
		if *preflight {
			cloud, err := NewOCICloud(config.Cell, config.Template)
			if err != nil {
				return err
			}
			oci, err := cloud.Preflight(ctx, config.Policy)
			if err != nil {
				return err
			}
			report["oci"], problems = oci, oci.Problems
		}
		if err := writeJSON(out, report); err != nil {
			return err
		}
		if len(problems) > 0 {
			return fmt.Errorf("OCI preflight found %d problems: %s", len(problems), strings.Join(problems, "; "))
		}
		return nil
	}
	if !*live {
		config.Policy.DryRun = true
	} else if *gate == "" {
		return errors.New("--live requires --rollout-gate: the autoscaler must never act during a rollout it cannot see")
	}
	lock, err := lockCell(config)
	if err != nil {
		return err
	}
	defer lock.Close()
	journal, states, err := openLaunchJournal(config)
	if err != nil {
		return err
	}
	defer journal.directory.Close()
	cloud, err := NewOCICloud(config.Cell, config.Template)
	if err != nil {
		return err
	}
	if err := restoreRunLaunchState(cloud, states, journal.save, config.Policy.DryRun); err != nil {
		return err
	}
	endpoint := EndpointTemplate(config.Endpoint)
	logf := func(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
	// An action that cannot be audited must not run: a failed audit write
	// cancels the run before the action's first effect.
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	defer decisionlog.SetDefault(jsonLines{out: os.Stderr, fail: stop})()
	controllerConfig := Config{Cell: config.Cell, Policy: config.Policy, Cloud: cloud,
		Members: HTTPMembers{Endpoint: endpoint}, Source: HTTPSource{Endpoint: endpoint}, Logf: logf}
	if *gate != "" {
		controllerConfig.Rollouts = RolloutGate(nil, *gate)
	}
	controller, err := New(controllerConfig)
	if err != nil {
		return err
	}
	if config.Policy.DryRun {
		logf("cellscale %s: dry run: reads OCI and node pressure, changes nothing; pass --live with dry_run false to act", config.Cell)
	}
	interval := time.Duration(config.IntervalSeconds) * time.Second
	for {
		action, err := controller.Tick(ctx)
		if err == nil {
			err = writeJSON(out, action)
		}
		if *once || ctx.Err() != nil {
			return errors.Join(err, context.Cause(ctx))
		}
		if err != nil {
			logf("cellscale %s: %v", config.Cell, err)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(interval):
		}
	}
}

func restoreRunLaunchState(cloud *OCICloud, states []OCILaunchState, save func([]OCILaunchState) error, dryRun bool) error {
	if dryRun {
		save = func([]OCILaunchState) error { return nil }
	}
	return cloud.RestoreLaunchState(states, save)
}

// lockCell uses a provisioned root-owned inode that runner users cannot replace.
// ponytail: local flock only; use a distributed lease for multi-host runners.
func lockCell(config FileConfig) (*os.File, error) {
	return lockCellAt(config, cellLockDirectory, 0)
}

func cellLockName(config FileConfig) string {
	scope, _ := json.Marshal([2]string{config.Template.Region, config.Cell})
	return fmt.Sprintf("%x.lock", sha256.Sum256(scope))
}

// owner is the trusted provisioner's UID; production requires root.
func lockCellAt(config FileConfig, path string, owner uint32) (*os.File, error) {
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open provisioned cell autoscaler lock directory %s: %w", path, err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, err
	}
	if info.Sys().(*syscall.Stat_t).Uid != owner || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("cell autoscaler lock directory must be owned by the trusted provisioner and not group or world writable")
	}
	name := cellLockName(config)
	path = filepath.Join(directory.Name(), name)
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	fd, err := syscall.Openat(int(directory.Fd()), name, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open provisioned cell autoscaler lock %s: %w", path, err)
	}
	lock := os.NewFile(uintptr(fd), path)
	info, err = lock.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("cell autoscaler lock must be a regular file")
	}
	if err == nil && (info.Sys().(*syscall.Stat_t).Uid != owner || info.Mode().Perm()&0o022 != 0) {
		err = errors.New("cell autoscaler lock must be owned by the trusted provisioner and not group or world writable")
	}
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("cannot acquire cell autoscaler lock %s (another cell autoscaler may hold it): %w", path, err)
	}
	return lock, nil
}

func readConfig(path string) (FileConfig, error) {
	if path == "" {
		return FileConfig{}, errors.New("--config is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return FileConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return FileConfig{}, err
	}
	if len(data) > 1<<20 {
		return FileConfig{}, errors.New("config exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config FileConfig
	if err := decoder.Decode(&config); err != nil {
		return FileConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return FileConfig{}, fmt.Errorf("parse %s: config must contain exactly one JSON value", path)
	}
	return config, config.Validate()
}

// jsonLines journals every decision, with its signals and attributes, as
// one JSON line: the audit trail of a run outside the regional journal.
type jsonLines struct {
	out  io.Writer
	fail func(error)
}

func (j jsonLines) Record(_ context.Context, decision decisionlog.Decision) string {
	decision = decision.Normalize(time.Now())
	if err := writeJSON(j.out, decision); err != nil {
		j.fail(fmt.Errorf("audit write failed: %w", err))
	}
	return decision.ID
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
