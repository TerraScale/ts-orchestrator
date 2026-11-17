package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func Check(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release mesh-check", flag.ContinueOnError)
	flags.SetOutput(output)
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: ts-orch release mesh-check [--regions FILE]")
	}
	regions, err := releasepush.LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	token, err := releasepush.MintToken(ctx)
	if err != nil {
		return err
	}
	fmt.Fprint(output, "| From | To | Server | RTT ms |\n|---|---|---|---|\n")
	for _, region := range regions {
		observation, err := releasepush.ReadObservation(ctx, region, token)
		if err != nil {
			return err
		}
		var rows []Reply
		if err := json.Unmarshal(observation.Ping, &rows); err != nil {
			return err
		}
		if len(rows) != len(regions) {
			return fmt.Errorf("mesh ping from %s: got %d peers, want %d", region.Region, len(rows), len(regions))
		}
		seen := map[string]bool{}
		for _, row := range rows {
			if row.Error != "" || row.Server == "" || row.ElapsedMS < 0 || seen[row.Region] {
				return fmt.Errorf("mesh ping from %s: invalid answer %+v", region.Region, row)
			}
			seen[row.Region] = true
			fmt.Fprintf(output, "| %s | %s | %s | %d |\n", region.Region, row.Region, row.Server, row.ElapsedMS)
		}
		for _, expected := range regions {
			if !seen[expected.Region] {
				return fmt.Errorf("mesh ping from %s: missing %s", region.Region, expected.Region)
			}
		}
		for name, image := range observation.Images {
			if observation.Running[name] != image {
				return fmt.Errorf("%s: %s is not serving the desired digest", region.Region, name)
			}
		}
	}
	return nil
}
