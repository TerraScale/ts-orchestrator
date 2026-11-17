package releaseclient

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

const nudgeWait = 15 * time.Second

func SendNudge(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release nudge", flag.ContinueOnError)
	flags.SetOutput(output)
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: ts-orch release nudge [--regions FILE]")
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	token, err := MintToken(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(Nudge{Token: token})
	if err != nil {
		return err
	}
	var failures []error
	for _, region := range regions {
		reply, err := nudgeRegion(ctx, region, token, payload)
		if err == nil && reply.State != "nudged" && reply.State != "throttled" {
			err = fmt.Errorf("%s: %s", reply.State, reply.Error)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", region.Region, err))
			fmt.Fprintf(output, "%s: nudge failed: %v\n", region.Region, err)
			continue
		}
		fmt.Fprintf(output, "%s: %s (running %s)\n", region.Region, reply.State, reply.Version)
	}
	return errors.Join(failures...)
}

func nudgeRegion(ctx context.Context, region Region, token string, payload []byte) (Reply, error) {
	conn, err := Dial(region, token)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	return request(ctx, conn, SubjectNudge, payload, nudgeWait)
}
