package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

const checkUsage = "usage: ts-orch release mesh-check [--regions deploy/m1/regions.json] [--spec deploy/m1/services/whoami.json]"

// Check re-proves the live mesh from GitHub Actions (multi-region.yml) over
// each region's public release listener: every listed region pings every
// ordered region, one region applies spec with this run's marker in
// WHOAMI_NAME everywhere, and each region's https://<region>.mesh.terrascale.tech/
// must answer from that region's host with the marker. It prints Markdown for
// the job summary and fails on any miss.
func Check(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release mesh-check", flag.ContinueOnError)
	flags.SetOutput(output)
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	specFile := flags.String("spec", "deploy/m1/services/whoami.json", "test service")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New(checkUsage)
	}
	regions, err := releasepush.LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*specFile)
	if err != nil {
		return err
	}
	var spec swarmruntime.ServiceSpec
	if err := protocol.DecodeStrict(data, &spec, 64<<10); err != nil {
		return fmt.Errorf("decode %s: %w", *specFile, err)
	}
	token, err := releasepush.MintToken(ctx)
	if err != nil {
		return err
	}
	marker := "ts-test-run-" + os.Getenv("GITHUB_RUN_ID") + "-" + os.Getenv("GITHUB_RUN_ATTEMPT")
	var failed error

	fmt.Fprint(output, "### Mesh ping\n\n| From | To | Server | RTT ms |\n|---|---|---|---|\n")
	conns := map[string]*nats.Conn{}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()
	var entry string
	servers := map[string]string{}
	for _, region := range regions {
		conn, err := releasepush.Dial(region, token, nats.Name("ts-orch release mesh-check"))
		if err != nil {
			fmt.Fprintf(output, "| %s | - | - | %s |\n", region.Region, err)
			failed = errors.Join(failed, fmt.Errorf("%s: %w", region.Region, err))
			continue
		}
		conns[region.Region] = conn
		if entry == "" {
			entry = region.Region
		}
		rows, err := call(ctx, conn, releasepush.SubjectPing, releasepush.MeshRequest{Token: token}, 30*time.Second)
		for _, row := range rows {
			if row.Error != "" {
				fmt.Fprintf(output, "| %s | %s | - | %s |\n", region.Region, row.Region, strings.ToUpper(row.Error))
				continue
			}
			servers[row.Region] = row.Server
			fmt.Fprintf(output, "| %s | %s | %s | %d |\n", region.Region, row.Region, row.Server, row.ElapsedMS)
		}
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("ping from %s: %w", region.Region, err))
		}
	}
	if entry == "" {
		return failed
	}

	spec.Env = maps.Clone(spec.Env)
	if spec.Env == nil {
		spec.Env = map[string]string{}
	}
	spec.Env["WHOAMI_NAME"] = marker
	encoded, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	// Remove first so every run creates the service: in-place updates wait on
	// the executor's host-port handover (W14), which this check does not test.
	if _, err := call(ctx, conns[entry], releasepush.SubjectRemove, releasepush.MeshRequest{Token: token, Spec: encoded}, 150*time.Second); err != nil {
		failed = errors.Join(failed, fmt.Errorf("remove before apply: %w", err))
	}
	fmt.Fprintf(output, "\n### Apply %s from %s (WHOAMI_NAME=%s)\n\n| Region | Result | Ms until running |\n|---|---|---|\n", spec.Name, entry, marker)
	rows, err := call(ctx, conns[entry], releasepush.SubjectApply, releasepush.MeshRequest{Token: token, Spec: encoded}, releasepush.HandlerWait+10*time.Second)
	if err != nil {
		failed = errors.Join(failed, fmt.Errorf("apply: %w", err))
	}
	var applied []string
	for _, row := range rows {
		if row.Error != "" {
			fmt.Fprintf(output, "| %s | ERROR %s | - |\n", row.Region, row.Error)
			continue
		}
		fmt.Fprintf(output, "| %s | %s | %d |\n", row.Region, row.Result, row.ElapsedMS)
		if row.Result == "applied" || row.Result == "unchanged" {
			applied = append(applied, row.Region)
		}
	}

	fmt.Fprint(output, "\n### HTTPS\n\n| URL | Result | Ms until answered |\n|---|---|---|\n")
	for _, region := range applied {
		url := "https://" + region + "." + Domain + "/"
		want := []string{"Name: " + marker}
		if server := servers[region]; server != "" {
			want = append(want, "Hostname: "+server)
		}
		start := time.Now()
		pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := answers(pollCtx, url, want)
		cancel()
		if err != nil {
			fmt.Fprintf(output, "| %s | %s | - |\n", url, err)
			failed = errors.Join(failed, fmt.Errorf("%s: %w", url, err))
			continue
		}
		fmt.Fprintf(output, "| %s | ok | %d |\n", url, time.Since(start).Milliseconds())
	}
	if failed != nil {
		fmt.Fprintf(output, "\n**FAIL** %s\n", failed)
	}
	return failed
}

// call sends one bridge request and decodes its rows, also when it failed.
func call(ctx context.Context, conn *nats.Conn, subject string, request releasepush.MeshRequest, timeout time.Duration) ([]Reply, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return nil, err
	}
	var reply releasepush.Reply
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return nil, err
	}
	var rows []Reply
	if len(reply.Result) != 0 {
		if err := json.Unmarshal(reply.Result, &rows); err != nil {
			return nil, err
		}
	}
	if reply.State != "done" {
		return rows, fmt.Errorf("%s: %s", reply.State, reply.Error)
	}
	return rows, nil
}

// answers polls url until its body holds every want, the first certificate
// included, or ctx ends.
func answers(ctx context.Context, url string, want []string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	last := errors.New("no answer")
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if response, err := client.Do(request); err != nil {
			last = err
		} else {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			last = fmt.Errorf("%s without %q", response.Status, want)
			if response.StatusCode == http.StatusOK && containsAll(string(body), want) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(3 * time.Second):
		}
	}
}

func containsAll(body string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(body, w) {
			return false
		}
	}
	return true
}
