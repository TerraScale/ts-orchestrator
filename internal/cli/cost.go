package cli

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/runtimecostsnapshot"
)

func runCost(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || slices.Contains([]string{"-h", "--help", "help"}, args[0]) {
		_, err := io.WriteString(out, "Usage: ts-orch cost report --region <cell>\n       ts-orch cost tag --region <cell> --compartment <ocid> [--compartment <ocid>...] [--apply]\n")
		return err
	}
	if args[0] == "tag" {
		return ocicost.Run(ctx, args, out)
	}
	if args[0] != "report" {
		return fmt.Errorf("unknown cost command %q; want report or tag", args[0])
	}
	flags := flag.NewFlagSet("cost report", flag.ContinueOnError)
	flags.SetOutput(out)
	region := flags.String("region", "", "cell token such as gru or sjc (required)")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("cost report takes no positional arguments, got %q", flags.Args())
	}
	if *region == "" {
		return errors.New("cost report needs --region <cell>")
	}
	entry, ok := catalog.Lookup(strings.ToUpper(*region))
	if !ok {
		entry, ok = catalog.CellForOCIRegion(*region)
	}
	if !ok {
		return fmt.Errorf("unsupported TerraScale region %q", *region)
	}
	access, err := controlaccess.Resolve(ctx, entry.Cell)
	if err != nil {
		return err
	}
	snapshot, readErr := (runtimecostsnapshot.Client{Access: access}).Read(ctx, entry.Cell)
	if snapshot.SchemaVersion == 0 {
		return readErr
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		return errors.Join(readErr, err)
	}
	_, err = out.Write(append(wire, '\n'))
	return errors.Join(readErr, err)
}
