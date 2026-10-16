package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// runGenerateInterRegionMaterial issues the interregion account, the
// reissued cell and system accounts, one scoped signing key and leaf
// credential per child region, and the interregion TLS files, from a
// region's controller material and the reviewed leaf topology. The public
// output records every file digest and the ledger digest; private material
// stays in the owner-only directory.
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
	cellJWTPath := flags.String("cell-jwt", "", "the cell account JWT the brokers hold, when newer than the material's cell.jwt")
	caCertPath := flags.String("interregion-ca-cert", "", "the hub's interregion-ca.pem (every region but the hub)")
	caKeyPath := flags.String("interregion-ca-key", "", "the hub's owner-only interregion-ca.key (every region but the hub)")
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
	var inputs bootstrapmaterial.InterRegionInputs
	if *cellJWTPath != "" {
		current, err := c.readBoundedRegular(*cellJWTPath, 64<<10)
		if err != nil {
			return err
		}
		inputs.CellJWT = strings.TrimSpace(string(current))
	}
	if *caCertPath != "" {
		if inputs.CACert, err = c.readBoundedRegular(*caCertPath, 16<<10); err != nil {
			return err
		}
	}
	if *caKeyPath != "" && !filepath.IsAbs(*caKeyPath) {
		return errors.New("--interregion-ca-key must be an absolute path")
	}
	inputs.CAKeyFile = *caKeyPath
	if err := c.ctx.Err(); err != nil {
		return err
	}
	record, err := bootstrapmaterial.GenerateInterRegion(*materialDirectory, *directory, config, inputs, now)
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

// runRenderInterRegionConfig writes the nats.embedded.interregion block of
// one controller slot, with its files at their installed paths in the
// controller credential directory. A child region also needs its parent's
// public inventory, the reviewed private-peer receipt, optionally the
// reviewed NetBird inventory, and its copy of the parent's leaf credentials.
func (c command) runRenderInterRegionConfig(args []string) error {
	return c.renderInterRegionConfigAt(args, time.Now().UTC())
}

func (c command) renderInterRegionConfigAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("render-interregion-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	materialPath := flags.String("material", "", "this region's public interregion inventory")
	slot := flags.String("slot", "", "controller slot, e.g. controller-a")
	parentPath := flags.String("parent-material", "", "the parent region's public interregion inventory (child only)")
	credentialsPath := flags.String("leaf-credentials", "", "this region's copy of the parent's leaf-<child>.creds (child only)")
	receiptPath := flags.String("receipt", "", "reviewed private-peer receipt (child only)")
	receiptSHA := flags.String("receipt-sha256", "", "reviewed private-peer receipt SHA-256")
	netbirdPath := flags.String("netbird-inventory", "", "optional reviewed ts-orch netbird inventory output (child only)")
	netbirdSHA := flags.String("netbird-inventory-sha256", "", "reviewed NetBird inventory SHA-256")
	outputPath := flags.String("out", "", "new interregion block JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *materialPath == "" || *slot == "" || *outputPath == "" || flags.NArg() != 0 || !filepath.IsAbs(*outputPath) {
		return errors.New("render-interregion-config requires --material, --slot and an absolute --out")
	}
	readRecord := func(path string) (bootstrapmaterial.InterRegionRecord, error) {
		var record bootstrapmaterial.InterRegionRecord
		wire, err := c.readBoundedRegular(path, 1<<20)
		if err != nil {
			return record, err
		}
		return record, json.Unmarshal(wire, &record, json.RejectUnknownMembers(true))
	}
	record, err := readRecord(*materialPath)
	if err != nil {
		return fmt.Errorf("read interregion inventory: %w", err)
	}
	var link *bootstrapmaterial.ParentLink
	if *parentPath != "" || *credentialsPath != "" || *receiptPath != "" || *netbirdPath != "" {
		if *parentPath == "" || *credentialsPath == "" || *receiptPath == "" || *receiptSHA == "" ||
			(*netbirdPath == "") != (*netbirdSHA == "") {
			return errors.New("a child needs --parent-material, --leaf-credentials, --receipt and --receipt-sha256, and --netbird-inventory with its --netbird-inventory-sha256")
		}
		link = &bootstrapmaterial.ParentLink{CredentialsFile: *credentialsPath,
			Receipt: bootstrapmaterial.Readback{SHA256: *receiptSHA}, NetBird: bootstrapmaterial.Readback{SHA256: *netbirdSHA}}
		if link.Record, err = readRecord(*parentPath); err != nil {
			return fmt.Errorf("read parent interregion inventory: %w", err)
		}
		if link.Receipt.Body, err = c.readBoundedRegular(*receiptPath, 1<<20); err != nil {
			return err
		}
		if *netbirdPath != "" {
			if link.NetBird.Body, err = c.readBoundedRegular(*netbirdPath, 4<<20); err != nil {
				return err
			}
		}
	}
	block, err := bootstrapmaterial.RenderInterRegion(record, *slot, bootstrapstart.MaterialDirectory, link, now)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(block, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	fmt.Fprintf(c.output, "interregion config rendered cell=%s slot=%s sha256=%s\n", record.Cell, *slot,
		hex.EncodeToString(sum[:]))
	return nil
}
