package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	client := http.Client{Timeout: 10 * time.Second}
	for _, region := range regions {
		observation, err := releasepush.ReadObservation(ctx, region, token)
		if err != nil {
			return err
		}
		var rows []Reply
		if err := json.Unmarshal(observation.Ping, &rows); err != nil {
			return err
		}
		seen := map[string]bool{}
		var server string
		for _, row := range rows {
			if row.Error != "" || row.Server == "" || seen[row.Region] {
				return fmt.Errorf("mesh ping from %s: invalid answer %+v", region.Region, row)
			}
			seen[row.Region] = true
			if row.Region == region.Region {
				server = row.Server
			}
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
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+region.Region+"."+Domain+"/", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		closeErr := response.Body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK || server == "" || !strings.Contains(string(body), "Hostname: "+server) {
			return fmt.Errorf("%s: mesh HTTPS returned %s without host identity", region.Region, response.Status)
		}
	}
	return nil
}
