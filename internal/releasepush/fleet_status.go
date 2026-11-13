package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/nats-io/nats.go"
)

func FleetStatus(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release fleet-status", flag.ContinueOnError)
	flags.SetOutput(output)
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list with pinned release endpoints; authentication requires GitHub Actions OIDC, as for release push")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: ts-orch release fleet-status [--regions deploy/m1/regions.json]")
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	var failed error
	for _, region := range regions {
		reply, err := fleetHealth(ctx, region)
		if err == nil {
			switch {
			case reply.Error != "":
				err = errors.New(reply.Error)
			case reply.Version == "":
				err = errors.New("empty serving version")
			case reply.Health != "ok":
				err = fmt.Errorf("unhealthy: %q", reply.Health)
			}
		}
		line := struct {
			Region  string `json:"region"`
			Version string `json:"version"`
			Health  string `json:"health"`
			Error   string `json:"error,omitempty"`
		}{Region: region.Region, Version: reply.Version, Health: reply.Health}
		if err != nil {
			line.Error = err.Error()
			failed = errors.Join(failed, fmt.Errorf("region %s: %w", region.Region, err))
		}
		if err := json.NewEncoder(output).Encode(line); err != nil {
			return errors.Join(failed, err)
		}
	}
	return failed
}

func fleetHealth(ctx context.Context, region Region) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, versionProbe)
	defer cancel()
	token, err := MintToken(ctx)
	if err != nil {
		return Reply{}, err
	}
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	deadline, _ := ctx.Deadline()
	conn, err := Dial(region, token, nats.Name("ts-orch release fleet-status"), nats.Timeout(time.Until(deadline)))
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	return request(ctx, conn, SubjectHealth, nil, healthRequestTimeout)
}
