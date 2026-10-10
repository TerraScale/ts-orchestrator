package ocicost

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

const costUsage = "Usage: ts-orch cost report --region <cell>\n"

// Run is `ts-orch cost`. report reads one region's cost with the operator's
// OCI config and prints the report and its forecast as JSON.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, err := io.WriteString(out, costUsage)
		return err
	}
	switch args[0] {
	case "report":
		return runReport(ctx, args[1:], out)
	default:
		return fmt.Errorf("unknown cost command %q; want report", args[0])
	}
}

func runReport(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("cost report", flag.ContinueOnError)
	flags.SetOutput(out)
	cell := flags.String("region", "", "cell token such as gru or sfo (required)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("cost report takes no positional arguments, got %q", flags.Args())
	}
	if *cell == "" {
		return errors.New("cost report needs --region <cell>")
	}
	ociRegion, err := oci.Region(strings.ToUpper(*cell)).OCIRegion()
	if err != nil {
		return fmt.Errorf("cost report: %w", err)
	}
	return printReport(ctx, *cell, ociRegion, out)
}

// printReport reads the cell's OCI cost through the operator's config and
// writes it with its forecast.
func printReport(ctx context.Context, cell, ociRegion string, out io.Writer) error {
	factory, err := ociclient.OperatorConfig(ociRegion)
	if err != nil {
		return fmt.Errorf("cost report: operator OCI config: %w", err)
	}
	usage, err := Connect(ctx, factory, cell, ociRegion)
	if err != nil {
		return fmt.Errorf("cost report: %w", err)
	}
	now := time.Now()
	report, err := usage.Read(ctx, now)
	if err != nil {
		return fmt.Errorf("cost report: read usage: %w", err)
	}
	forecast := Project(report, now, nil)
	encoded, err := json.MarshalIndent(struct {
		Report   Report   `json:"report"`
		Forecast Forecast `json:"forecast"`
	}{report, forecast}, "", "  ")
	if err != nil {
		return fmt.Errorf("cost report: encode: %w", err)
	}
	_, err = out.Write(append(encoded, '\n'))
	return err
}
