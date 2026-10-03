package cli

import (
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// runGenerateInterRegionMaterial issues the interregion account, the
// reissued cell and system accounts, and one scoped signing key and leaf
// credential per child region, from a region's controller material and the
// reviewed leaf topology. The public output records every file digest and
// the ledger digest; private material stays in the owner-only directory.
func (c command) runGenerateInterRegionMaterial(args []string) error {
	return c.generateInterRegionMaterialAt(args, time.Now().UTC())
}

func (c command) generateInterRegionMaterialAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("generate-interregion-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	materialDirectory := flags.String("material-directory", "", "this region's controller material directory")
	configPath := flags.String("config", "", "reviewed interregion configuration JSON (topology, listenPort)")
	configSHA := flags.String("config-sha256", "", "SHA-256 of the reviewed configuration")
	directory := flags.String("directory", "", "new owner-only interregion material directory outside the checkout")
	outputPath := flags.String("out", "", "new public interregion inventory JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *materialDirectory == "" || *configPath == "" || *configSHA == "" || *directory == "" || *outputPath == "" ||
		flags.NArg() != 0 || !filepath.IsAbs(*materialDirectory) || !filepath.IsAbs(*directory) ||
		!filepath.IsAbs(*outputPath) || pathInside(*directory, *outputPath) || pathInside(*materialDirectory, *outputPath) {
		return errors.New("generate-interregion-material requires --material-directory, --config, --config-sha256, --directory, and --out")
	}
	if _, err := os.Lstat(*outputPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("public interregion output path must not already exist")
	}
	wire, err := c.readBoundedRegular(*configPath, 16<<10)
	if err != nil || !matchesSHA256(wire, *configSHA) {
		return errors.New("reviewed interregion configuration digest does not match")
	}
	var config bootstrapmaterial.InterRegionConfig
	if err := json.Unmarshal(wire, &config, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode interregion configuration: %w", err)
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	record, err := bootstrapmaterial.GenerateInterRegion(*materialDirectory, *directory, config, now)
	if err != nil {
		return err
	}
	public, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, public, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "interregion material ready inventory=%s account=%s ledger-digest=%s expires=%s\n",
		*outputPath, record.InterRegionAccountNKey, record.LedgerDigest, record.ExpiresAt.Format(time.RFC3339))
	return nil
}
