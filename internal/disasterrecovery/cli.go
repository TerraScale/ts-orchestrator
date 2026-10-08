package disasterrecovery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const usage = `Usage: ts-orch disaster-recovery replicate --config FILE [--apply]

Prepare gru-1 <-> sfo-1 Object Storage mirrors, verified historical backfills
and Vault key replicas. Without --apply, inspect and print the plan. With
--apply, create only missing DR resources. Never changes nodes, cell specs,
load balancers, DNS, or source objects. See docs/disaster-recovery.md.

This preparation command does not rebuild a cell or perform a recovery drill.
`

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	if args[0] != "replicate" {
		return fmt.Errorf("unknown disaster-recovery command %q", args[0])
	}
	fs := flag.NewFlagSet("disaster-recovery replicate", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { _, _ = io.WriteString(out, usage) }
	path := fs.String("config", "", "pinned cross-region recovery configuration")
	apply := fs.Bool("apply", false, "create the missing recovery resources")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return errors.New("replicate requires --config and takes only flags")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	var config Config
	if err := protocol.DecodeStrict(data, &config, 64<<10); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return fmt.Errorf("unset %s before preparing recovery keys", name)
		}
	}
	gru, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.GRU))
	if err != nil {
		return err
	}
	sfo, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.SFO))
	if err != nil {
		return err
	}
	// Bind both Vaults and keys before any create, even when only the first
	// direction would otherwise have passed its source bucket checks.
	if err := requireVaultKey(ctx, gru, config.GRU); err != nil {
		return err
	}
	if err := requireVaultKey(ctx, sfo, config.SFO); err != nil {
		return err
	}
	// Print the complete scope before any mutation, including the fact that
	// the mirrors and seeds are different buckets from the serving buckets.
	if err := writeJSON(out, struct {
		Apply  bool   `json:"apply"`
		Config Config `json:"config"`
		Scope  string `json:"scope"`
	}{*apply, config, "TS-641 DR buckets, backfills, source replication policies and Vault key replicas only"}); err != nil {
		return err
	}
	for _, direction := range []struct {
		source, target             *ociclient.Factory
		sourceCell, targetCell     string
		sourceConfig, targetConfig Region
	}{{gru, sfo, "gru", "sfo", config.GRU, config.SFO}, {sfo, gru, "sfo", "gru", config.SFO, config.GRU}} {
		replica, err := EnsureVaultReplica(ctx, direction.source, direction.sourceConfig.VaultID, direction.target.Region(), *apply)
		if outputErr := writeJSON(out, replica); outputErr != nil {
			return errors.Join(err, outputErr)
		}
		if err != nil {
			return err
		}
		copier, err := newCopier(direction.source, direction.target, config, direction.sourceCell, direction.targetCell,
			direction.sourceConfig, direction.targetConfig, *apply)
		if err != nil {
			return err
		}
		for _, role := range []string{"backup", "head"} {
			report, err := copier.copy(ctx, role)
			if outputErr := writeJSON(out, report); outputErr != nil {
				return errors.Join(err, outputErr)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}
