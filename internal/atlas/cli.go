package atlas

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const usage = `Usage: ts-orch atlas <command> [flags]

  key      --plan FILE
      Store a new P-256 publish key as the cell's Vault secret
      <cell>-atlas-publish-key unless the Vault holds one, and print
      {"secret","publish_keys"}: PUBLISH_KEYS, the JWKS of its public key, for
      the ts-atlas Worker. The private key is never printed.
  publish  --plan FILE --section FILE
      Publish the cell spec atlas section FILE once, as the authority leader
      does every 10 s: read its publish key from the Vault (operator
      ~/.oci/config), probe each region's readyz and post the signed
      topology. Prints {"published":UPDATED}.
`

// Run dispatches the atlas commands. Output never carries a secret.
func Run(ctx context.Context, args []string, output io.Writer, loadPlan func(string) (map[string]any, error)) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, usage)
		return err
	}
	flags := flag.NewFlagSet("atlas "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.String("plan", "", "reviewed cell plan (deploy/oci-region/plan.json)")
	section := flags.String("section", "", "the cell spec atlas section")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected atlas arguments")
	}
	switch args[0] {
	case "key":
		if *plan == "" {
			return errors.New("key requires --plan")
		}
		cell, target, client, bundles, err := tsauth.OperatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		name := vaultsecret.Name(cell, KeyName)
		stored, err := vaultsecret.Ensure(ctx, client, target, name,
			"Atlas publish key of cell "+cell+"; created once by ts-orch.", NewKey)
		if err != nil {
			return err
		}
		value, err := vaultsecret.ReadBack(ctx, bundles, target.VaultID, name, stored.Created || stored.Provisioning)
		if err != nil {
			return err
		}
		key, err := ParseKey(value)
		if err != nil {
			return err
		}
		jwks, err := JWKS(key)
		if err != nil {
			return err
		}
		return printLine(output, map[string]any{"secret": stored, "publish_keys": jwks})
	case "publish":
		if *plan == "" || *section == "" {
			return errors.New("publish requires --plan and --section")
		}
		data, err := os.ReadFile(*section)
		if err != nil {
			return err
		}
		var config Config
		if err := protocol.DecodeStrict(data, &config, 64<<10); err != nil {
			return fmt.Errorf("atlas section: %w", err)
		}
		// Refuse what the controllers would, before any secret or request.
		cellPlan, err := loadPlan(*plan)
		if err != nil {
			return err
		}
		if err := config.Validate(strings.ToLower(fmt.Sprint(cellPlan["cell"]))); err != nil {
			return fmt.Errorf("atlas section: %w", err)
		}
		_, target, _, bundles, err := tsauth.OperatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		if config.PublishKey.Vault != target.VaultID {
			return errors.New("the atlas section's publish key must live in the plan's Vault")
		}
		value, err := vaultsecret.Read(ctx, bundles, config.PublishKey.Vault, config.PublishKey.Name)
		if err != nil {
			return err
		}
		key, err := ParseKey(value)
		if err != nil {
			return err
		}
		publisher := Publisher{HTTP: &http.Client{Timeout: Interval}, Key: key}
		now := time.Now()
		if err := publisher.Publish(ctx, config, now, nil); err != nil {
			return err
		}
		return printLine(output, map[string]any{"published": publisher.last})
	default:
		_, _ = io.WriteString(output, usage)
		return fmt.Errorf("unknown atlas command %q", args[0])
	}
}

func printLine(output io.Writer, value any) error {
	if err := json.MarshalWrite(output, value); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output)
	return err
}
