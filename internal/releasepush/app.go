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

const appUsage = "usage: ts-orch release app --service <name> --image ghcr.io/terrascale/<name>@sha256:<64 hex> [--regions deploy/m1/regions.json]"

// AppResult is the one JSON line PushApp prints.
type AppResult struct {
	// Via is the region whose ts-orch ran the release on the mesh.
	Via       string          `json:"via,omitempty"`
	State     string          `json:"state,omitempty"`
	ServingMS int64           `json:"serving_ms"`
	Error     string          `json:"error,omitempty"`
	Regions   json.RawMessage `json:"regions,omitempty"`
}

// PushApp releases one service's image to every region from an app
// repository's image workflow (id-token: write). The first region that
// accepts the connection runs it over the mesh for all regions.
func PushApp(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release app", flag.ContinueOnError)
	flags.SetOutput(output)
	service := flags.String("service", "", "service to release")
	image := flags.String("image", "", "image pinned by digest")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *service == "" || appImage.FindStringSubmatch(*image) == nil {
		return errors.New(appUsage)
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	token, err := MintToken(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(AppRelease{Service: *service, Image: *image, Token: token})
	if err != nil {
		return err
	}
	start := time.Now()
	result, unreachable := AppResult{}, error(nil)
	for _, region := range regions {
		conn, err := Dial(region, token, nats.Name("ts-orch release app"))
		if err != nil {
			unreachable = errors.Join(unreachable, fmt.Errorf("region %s: %w", region.Region, err))
			continue
		}
		reply, err := request(ctx, conn, SubjectApp, payload, 2*time.Minute+10*time.Second)
		conn.Close()
		result = AppResult{Via: region.Region, State: reply.State, Error: reply.Error, Regions: reply.Result, ServingMS: time.Since(start).Milliseconds()}
		if err != nil {
			result.Error = err.Error()
		}
		break
	}
	if result.Via == "" {
		return errors.Join(errors.New("no region accepted the release"), unreachable)
	}
	line, _ := json.Marshal(result)
	if _, err := fmt.Fprintf(output, "%s\n", line); err != nil {
		return err
	}
	if result.State != "done" {
		return fmt.Errorf("release %s %s: %s %s", *service, *image, result.State, result.Error)
	}
	return nil
}
