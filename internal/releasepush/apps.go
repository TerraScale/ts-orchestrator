package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func Digests(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release digests", flag.ContinueOnError)
	flags.SetOutput(output)
	out := flags.String("out", "", "destination")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *out == "" || flags.NArg() != 0 {
		return errors.New("usage: ts-orch release digests --out FILE")
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	token, err := MintToken(ctx)
	if err != nil {
		return err
	}
	var images map[string]string
	for _, region := range regions {
		observation, err := ReadObservation(ctx, region, token)
		if err != nil {
			return err
		}
		if len(observation.Running) != len(observation.Images) {
			return errors.New("an app rollout has not finished")
		}
		if images == nil {
			images = observation.Running
			continue
		}
		before, _ := json.Marshal(images)
		after, _ := json.Marshal(observation.Running)
		if string(before) != string(after) {
			return errors.New("regional running images disagree")
		}
	}
	data, err := json.MarshalIndent(images, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(data, '\n'), 0600)
}

func WaitApp(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release wait", flag.ContinueOnError)
	flags.SetOutput(output)
	service := flags.String("service", "", "service")
	image := flags.String("image", "", "selected immutable image")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *service == "" || appImage.FindStringSubmatch(*image) == nil || flags.NArg() != 0 {
		return errors.New("usage: ts-orch release wait --service NAME --image IMAGE")
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	if err := waitObservations(ctx, regions, func(observation Observation) bool {
		return observation.Running[*service] == *image
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "{\"state\":\"done\",\"service\":%q,\"image\":%q}\n", *service, *image)
	return err
}

func WaitHosts(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 1 || !hex40.MatchString(args[0]) {
		return errors.New("usage: ts-orch release hosts REVISION")
	}
	regions, err := LoadRegions("deploy/m1/regions.json")
	if err != nil {
		return err
	}
	if err := waitObservations(ctx, regions, func(observation Observation) bool {
		if len(observation.Hosts) == 0 {
			return false
		}
		for _, host := range observation.Hosts {
			if host.Version != args[0] || host.Error != "" || host.Refusal != nil {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "Every registered host runs", args[0])
	return err
}

func waitObservations(ctx context.Context, regions []Region, ready func(Observation) bool) error {
	ctx, cancel := context.WithTimeout(ctx, HandlerWait)
	defer cancel()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		token, err := MintToken(ctx)
		if err != nil {
			return err
		}
		complete := true
		for _, region := range regions {
			observation, status, err := fetchObservation(ctx, region, "", token)
			if status == 401 || status == 403 {
				return fmt.Errorf("%s: observation HTTP %d", region.Region, status)
			}
			if err != nil {
				complete = false
				continue
			}
			if status != 200 && status != 503 {
				return fmt.Errorf("%s: observation HTTP %d", region.Region, status)
			}
			if status != 200 || observation.Health != "ok" || !ready(observation) {
				complete = false
			}
		}
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
