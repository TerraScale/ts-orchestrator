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
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
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
	var best *Usage
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
		response, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return Usage{}, ctx.Err()
			}
			continue
		}
		var result Usage
		err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result)
		_ = response.Body.Close()
		if response.StatusCode != 200 || err != nil || result.Region != region || !result.From.Equal(from) || !result.To.Equal(to) {
			continue
		}
		if result.Complete {
			return result, nil
		}
		if best == nil || len(result.Replicas) > len(best.Replicas) {
			best = &result
		}
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
	base := flags.String("url", "", "controller origin; default tries all three regional controllers")
	tokenFile := flags.String("token-file", "", "0600 bearer token file")
	vault := flags.String("token-vault", "", "regional OCI Vault OCID")
	name := flags.String("token-name", "", "dashboard bearer token secret name")
	configFile := flags.String("config", "", "shared benchmark.json config, default ~/.config/ts-orch/benchmark.json")
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
	var token string
	urls := RegionalURLs(*region)
	if *tokenFile != "" {
		info, err := os.Lstat(*tokenFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
			return errors.New("token file must be a private regular file of at most 4096 bytes")
		}
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(data))
	} else {
		if *vault == "" && *name == "" {
			if *configFile == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				*configFile = filepath.Join(home, ".config", "ts-orch", "benchmark.json")
			}
			data, err := os.ReadFile(*configFile)
			if err != nil {
				return fmt.Errorf("read usage config: %w", err)
			}
			if len(data) > 1<<20 {
				return errors.New("usage config exceeds 1 MiB")
			}
			var config struct {
				Regions map[string]struct {
					URLs  []string        `json:"usage_urls"`
					Token vaultsecret.Ref `json:"usage_token"`
				} `json:"regions"`
			}
			if err := json.Unmarshal(data, &config); err != nil {
				return err
			}
			settings, ok := config.Regions[*region]
			if !ok {
				return errors.New("usage config has no selected region")
			}
			*vault, *name = settings.Token.Vault, settings.Token.Name
			if len(settings.URLs) > 0 {
				urls = settings.URLs
			}
		}
		token, err = ReadSecret(ctx, vaultsecret.Ref{Vault: *vault, Name: *name})
		if err != nil {
			return err
		}
	}
	if *base != "" {
		urls = []string{*base}
	}
	result, err := (Client{URLs: urls, Token: token}).Query(ctx, *region, from, to)
	if err != nil {
		return err
	}
	if *format == "json" {
		return json.NewEncoder(out).Encode(result)
	}
	return WriteTable(out, result)
}

func RegionalURLs(region string) []string {
	var urls []string
	for i := 1; i <= 3; i++ {
		urls = append(urls, fmt.Sprintf("http://ts-%s-%d.nb.ts.internal:9463", region, i))
	}
	return urls
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
