package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// ReadSecret uses the operator's OCI profile, not an instance principal on a laptop.
func ReadSecret(ctx context.Context, ref vaultsecret.Ref) (string, error) {
	values, err := vaultsecret.Resolve(ctx, map[string]vaultsecret.Ref{"value": ref}, func(region string) (vaultsecret.BundleClient, error) {
		factory, err := ociclient.OperatorConfig(region)
		if err != nil {
			return nil, err
		}
		return vaultsecret.SecretsClient(factory)
	})
	return values["value"], err
}

type Client struct {
	URLs  []string
	Token string
	HTTP  *http.Client
}

func (c Client) Query(ctx context.Context, region string, from, to time.Time) (Usage, error) {
	if err := ValidateWindow(region, from, to, time.Now()); err != nil {
		return Usage{}, err
	}
	if len(c.Token) < 32 || len(c.Token) > 4096 || strings.ContainsAny(c.Token, "\r\n") {
		return Usage{}, errors.New("usage requires a valid bearer token")
	}
	hc := http.Client{Timeout: 15 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	} else {
		transport := &http.Transport{Proxy: nil, IdleConnTimeout: 30 * time.Second}
		defer transport.CloseIdleConnections()
		hc.Transport = transport
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithCancel(ctx)
	var pending sync.WaitGroup
	defer func() { cancel(); pending.Wait() }()
	requests := make([]*http.Request, 0, len(c.URLs))
	for _, base := range c.URLs {
		u, err := url.Parse(base)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return Usage{}, errors.New("invalid usage URL")
		}
		if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && !strings.HasSuffix(u.Hostname(), ".nb.ts.internal") {
			return Usage{}, errors.New("HTTP usage URL must use loopback or the encrypted NetBird overlay")
		}
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/usage"
		u.RawQuery = url.Values{"region": {region}, "from": {from.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}}.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return Usage{}, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		requests = append(requests, req)
	}
	results := make(chan *Usage, len(requests))
	for _, req := range requests {
		pending.Go(func() {
			var result *Usage
			defer func() { results <- result }()
			response, err := hc.Do(req)
			if err != nil {
				return
			}
			defer response.Body.Close()
			var usage Usage
			err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&usage)
			if response.StatusCode == 200 && err == nil && usage.Region == region && usage.From.Equal(from) && usage.To.Equal(to) {
				result = &usage
			}
		})
	}
	var best *Usage
	for range requests {
		var result *Usage
		select {
		case <-ctx.Done():
			return Usage{}, ctx.Err()
		case result = <-results:
		}
		if err := ctx.Err(); err != nil {
			return Usage{}, err
		}
		if result == nil {
			continue
		}
		if result.Complete {
			return *result, nil
		}
		if best == nil || len(result.Replicas) > len(best.Replicas) {
			best = result
		}
	}
	if err := ctx.Err(); err != nil {
		return Usage{}, err
	}
	if best != nil {
		return *best, nil
	}
	return Usage{}, errors.New("no regional controller returned usage; check Vault token, connectivity and binary version")
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("usage", flag.ContinueOnError)
	flags.SetOutput(out)
	region := flags.String("region", "", "gru or sfo")
	fromText := flags.String("from", "", "RFC3339 window start")
	toText := flags.String("to", "", "RFC3339 window end")
	format := flags.String("format", "table", "table or json")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage accepts flags only")
	}
	from, err := time.Parse(time.RFC3339Nano, *fromText)
	if err != nil {
		return errors.New("--from requires RFC3339")
	}
	to, err := time.Parse(time.RFC3339Nano, *toText)
	if err != nil {
		return errors.New("--to requires RFC3339")
	}
	if err := ValidateWindow(*region, from, to, time.Now()); err != nil {
		return err
	}
	if *format != "json" && *format != "table" {
		return errors.New("--format must be json or table")
	}
	access, err := controlaccess.Resolve(ctx, *region)
	if err != nil {
		return err
	}
	result, err := (Client{URLs: access.URLs, Token: access.Token}).Query(ctx, *region, from, to)
	if err != nil {
		return err
	}
	if *format == "json" {
		return json.NewEncoder(out).Encode(result)
	}
	return WriteTable(out, result)
}

func WriteTable(out io.Writer, result Usage) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, err := fmt.Fprintf(w, "REGION\tCOMPLETE\tFROM\tTO\n%s\t%t\t%s\t%s\n", result.Region, result.Complete, result.From.Format(time.RFC3339), result.To.Format(time.RFC3339))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, "ENTITY\tCPU USED/REQUEST/LIMIT/FREE cores\tMEM USED/REQUEST/LIMIT/FREE MiB")
	if err != nil {
		return err
	}
	for _, rows := range [][]Row{result.Nodes, result.Services} {
		for _, row := range rows {
			name := row.Node
			if row.Service != "" {
				name = row.Environment + "/" + row.Service
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", name, resourceText(row.CPU, 1), resourceText(row.Memory, 1<<20)); err != nil {
				return err
			}
		}
	}
	if len(result.Missing) > 0 {
		if _, err := fmt.Fprintf(w, "MISSING\t%s\n", strings.Join(result.Missing, ",")); err != nil {
			return err
		}
	}
	return w.Flush()
}

func resourceText(r Resource, divisor float64) string {
	var values []string
	for _, stat := range []*Stats{r.Usage, r.Request, r.Limit, r.Headroom} {
		if stat == nil {
			values = append(values, "?")
			continue
		}
		value := stat.Mean
		if stat == r.Headroom {
			value = stat.Min
		}
		text := fmt.Sprintf("%.2f", value/divisor)
		if !stat.Complete {
			text += "*"
		}
		values = append(values, text)
	}
	return strings.Join(values, " / ")
}
