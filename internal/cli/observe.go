package cli

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const observeHelp = `Usage: ts-orch observe <metrics|history|snapshot|cluster|events|regions|region|nodes|node|services|service|functions|function|volumes|volume> [flags]

Read the same authenticated APIs as the dashboard. JSON output has version 1.
  --region REGION        Select an admitted region; authenticated discovery supplies endpoints
  --cell CELL            Resource region; defaults to the authenticated endpoint's local region
  --node NAME            Node selector; omit for regional SwarmKit services
  --service ID           Managed service ID; node-local role when --node is given
  --tenant ID            Tenant selector for one admitted function
  --function ID          Function selector; requires --tenant
  --volume ID            Managed volume selector
  --format table|json    Readable output or versioned JSON
  --search TEXT          Filter the metric catalog by name, description or source
  --metric NAME          History metric; --range 1h or --start/--end RFC3339
  --label NAME=VALUE     Repeatable history label filter
  --tier raw|1m|5m|1h     History resolution; automatic when omitted
  --rate                 History counter rate per second
  --max 64               History series bound (1..512)
  --limit 200            Recent events bound (1..2048); --after SEQUENCE resumes
  --url ORIGIN           Diagnostic endpoint; requires --token-file
  --token-file FILE      Private diagnostic token file; requires --url

Endpoints and read credentials resolve from admitted OCI authority and Vault.
Missing authority remains pending. No token is accepted as a command argument.
Requests have a fixed 15-second deadline and 8 MiB limit.
Partial or truncated results are printed and return an error.
`

func runObserve(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || slices.Contains([]string{"help", "--help", "-h"}, args[0]) {
		_, err := io.WriteString(out, observeHelp)
		return err
	}
	view := args[0]
	if !slices.Contains([]string{"metrics", "history", "snapshot", "cluster", "events", "regions", "region", "nodes", "node", "services", "service", "functions", "function", "volumes", "volume"}, view) {
		return fmt.Errorf("unknown observe view %q; use ts-orch observe --help", view)
	}
	flags := flag.NewFlagSet("observe "+view, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cell := flags.String("cell", "", "resource region")
	node := flags.String("node", "", "node selector")
	service := flags.String("service", "", "service selector")
	tenant := flags.String("tenant", "", "function tenant selector")
	function := flags.String("function", "", "function selector")
	volume := flags.String("volume", "", "volume selector")
	region := flags.String("region", "", "region selector")
	format := flags.String("format", "table", "table or json")
	origin := flags.String("url", "", "diagnostic endpoint")
	tokenFile := flags.String("token-file", "", "private diagnostic token file")
	search := flags.String("search", "", "metric search")
	metric := flags.String("metric", "", "history metric")
	window := flags.String("range", "1h", "history range")
	start := flags.String("start", "", "history start")
	end := flags.String("end", "", "history end")
	tier := flags.String("tier", "", "history tier")
	rate := flags.Bool("rate", false, "counter rate")
	maximum := flags.Int("max", 64, "history series limit")
	limit := flags.Int("limit", 200, "event limit")
	after := flags.Uint64("after", 0, "event sequence")
	labels := url.Values{}
	flags.Func("label", "history label NAME=VALUE", func(value string) error {
		name, value, ok := strings.Cut(value, "=")
		if !ok || name == "" {
			return errors.New("label must be NAME=VALUE")
		}
		labels.Set("label."+name, value)
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, observeHelp)
			return err
		}
		return fmt.Errorf("observe: %w", err)
	}
	if flags.NArg() != 0 || (*format != "table" && *format != "json") {
		return errors.New("observe accepts flags only; --format must be table or json")
	}
	var wrongFlag string
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cell":
			if !isObserveResource(view) || view == "regions" {
				wrongFlag = f.Name
			}
		case "node":
			if view != "node" && view != "services" && view != "service" {
				wrongFlag = f.Name
			}
		case "service":
			if view != "service" {
				wrongFlag = f.Name
			}
		case "volume":
			if view != "volume" {
				wrongFlag = f.Name
			}
		case "tenant", "function":
			if view != "function" {
				wrongFlag = f.Name
			}
		case "search":
			if view != "metrics" {
				wrongFlag = f.Name
			}
		case "metric", "range", "start", "end", "tier", "rate", "max", "label":
			if view != "history" {
				wrongFlag = f.Name
			}
		case "after", "limit":
			if view != "events" {
				wrongFlag = f.Name
			}
		}
	})
	if wrongFlag != "" {
		return fmt.Errorf("--%s does not apply to observe %s", wrongFlag, view)
	}
	query := url.Values{}
	path := "/v1/" + view
	switch view {
	case "metrics":
		path = "/v1/metrics/catalog"
	case "history":
		query = labels
		query.Set("metric", *metric)
		query.Set("range", *window)
		query.Set("tier", *tier)
		query.Set("max", strconv.Itoa(*maximum))
		query.Set("start", *start)
		query.Set("end", *end)
		if *rate {
			query.Set("rate", "1")
		}
		if *maximum < 1 {
			return errors.New("--max must be between 1 and 512")
		}
		if _, err := observability.ParseHistoryQuery(query, time.Now()); err != nil {
			return err
		}
	case "events":
		if *limit < 1 || *limit > observability.DefaultEventCapacity {
			return errors.New("--limit must be between 1 and 2048")
		}
		query.Set("limit", strconv.Itoa(*limit))
		query.Set("after", strconv.FormatUint(*after, 10))
	}
	if isObserveResource(view) {
		var err error
		path, err = observeResourcePath(view, *cell, *node, *service, *volume, *tenant, *function)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	urls, token, err := observeAccess(ctx, *region, *origin, *tokenFile)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, IdleConnTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var failures []error
	var partialData []byte
	var partialSource string
	type answer struct {
		source string
		data   []byte
		err    error
	}
	answers := make(chan answer, len(urls))
	for _, base := range urls {
		go func() {
			resourcePath := path
			if isObserveResource(view) && view != "regions" && *cell == "" {
				data, err := observeFetch(ctx, client, base, "/v1/regions", nil, token)
				if err != nil {
					answers <- answer{source: base, err: err}
					return
				}
				local, err := observeLocalCell(data)
				if err != nil {
					answers <- answer{source: base, err: err}
					return
				}
				resourcePath, err = observeResourcePath(view, local, *node, *service, *volume, *tenant, *function)
				if err != nil {
					answers <- answer{source: base, err: err}
					return
				}
			}
			data, err := observeFetch(ctx, client, base, resourcePath, query, token)
			answers <- answer{base, data, err}
		}()
	}
gather:
	for range urls {
		var result answer
		select {
		case result = <-answers:
		case <-ctx.Done():
			failures = append(failures, ctx.Err())
			break gather
		}
		base, data, err := result.source, result.data, result.err
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var buffer strings.Builder
		partial, err := writeObserve(&buffer, view, *format, base, *search, data)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if partial {
			if partialData == nil {
				partialData, partialSource = data, base
			}
			continue
		}
		_, err = io.WriteString(out, buffer.String())
		return err
	}
	if partialData != nil {
		_, err := writeObserve(out, view, *format, partialSource, *search, partialData)
		return errors.Join(errors.New("observe returned partial or truncated data; inspect the reported gaps"), err)
	}
	return fmt.Errorf("observe %s: %w", view, errors.Join(failures...))
}

func observeAccess(ctx context.Context, region, origin, tokenFile string) ([]string, string, error) {
	var urls []string
	var token string
	if (origin == "") != (tokenFile == "") {
		return nil, "", errors.New("diagnostic access requires --url and --token-file together")
	}
	if origin == "" {
		access, err := controlaccess.Resolve(ctx, region)
		if err != nil {
			if errors.Is(err, controlaccess.ErrPending) {
				return nil, "", fmt.Errorf("observe access pending: %w", err)
			}
			return nil, "", fmt.Errorf("resolve admitted observe access: %w", err)
		}
		urls, token = access.URLs, access.Token
	}
	if tokenFile != "" {
		file, err := os.Open(tokenFile)
		if err != nil {
			return nil, "", fmt.Errorf("open observe token file: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, "", errors.New("observe token file must be a private regular file")
		}
		data, err := io.ReadAll(io.LimitReader(file, 4097))
		if err != nil {
			return nil, "", err
		}
		token = strings.TrimSpace(string(data))
		clear(data)
		if len(data) > 4096 {
			return nil, "", errors.New("observe token file exceeds 4096 bytes")
		}
	}
	if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n\x00") {
		return nil, "", errors.New("observe requires one 32-4096 byte bearer token from OCI Vault or a private file")
	}
	if origin != "" {
		urls = []string{origin}
	}
	if len(urls) == 0 {
		return nil, "", fmt.Errorf("admitted management endpoints are unavailable: %w", controlaccess.ErrPending)
	}
	if len(urls) > 64 {
		return nil, "", errors.New("observe endpoint inventory exceeds 64 controllers")
	}
	// Validate every destination before sending a credential to any of them.
	for _, base := range urls {
		if _, err := observeURL(base); err != nil {
			return nil, "", err
		}
	}
	return urls, token, nil
}

func observeURL(base string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("observe endpoint must be an HTTP(S) origin without credentials, path, query or fragment")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip, _ := netip.ParseAddr(host)
		if host != "localhost" && !ip.IsLoopback() && !netip.MustParsePrefix("10.200.0.0/16").Contains(ip) && !strings.HasSuffix(host, ".nb.ts.internal") {
			return nil, errors.New("HTTP observe endpoints require loopback or the encrypted NetBird overlay")
		}
	}
	return u, nil
}

func observeFetch(ctx context.Context, client *http.Client, base, path string, query url.Values, token string) ([]byte, error) {
	u, err := observeURL(base)
	if err != nil {
		return nil, err
	}
	u.Path = path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", base, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%s: authentication denied (HTTP %d); verify the regional Vault credential", base, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("%s: response read failed", base)
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("%s: response exceeds 8 MiB", base)
	}
	if len(data) == 0 || strings.TrimSpace(string(data)) == "null" {
		return nil, fmt.Errorf("%s: API returned empty observation", base)
	}
	if response.StatusCode != http.StatusOK && !observeResourceError(path, response.StatusCode, data) {
		return nil, fmt.Errorf("%s: API returned HTTP %d", base, response.StatusCode)
	}
	return data, nil
}

func writeObserve(out io.Writer, view, format, source, search string, data []byte) (bool, error) {
	var value any
	partial := false
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	switch view {
	case "regions", "region", "nodes", "node", "services", "service", "functions", "function", "volumes", "volume":
		var err error
		value, partial, err = writeObserveResource(table, view, format, data)
		if err != nil {
			return false, err
		}
	case "metrics":
		var result observability.CatalogResult
		if err := json.Unmarshal(data, &result); err != nil {
			return false, errors.New("invalid metric catalog JSON")
		}
		if result.Version != 1 {
			return false, errors.New("unsupported metric catalog version")
		}
		filtered := result.Metrics[:0]
		for _, metric := range result.Metrics {
			if strings.Contains(strings.ToLower(metric.Name+" "+metric.Description+" "+metric.Source), strings.ToLower(search)) {
				filtered = append(filtered, metric)
			}
		}
		result.Metrics = filtered
		partial = result.Truncated || result.State != "available"
		value = result
		if format == "table" {
			fmt.Fprintf(table, "STATE\t%s\tOBSERVED\t%s\tTRUNCATED\t%t\n", result.State, result.ObservedAt.Format(time.RFC3339), result.Truncated)
			fmt.Fprintln(table, "METRIC\tTYPE\tUNIT\tSOURCE\tSTATE\tHISTORY\tTIERS\tRETENTION seconds\tLABELS\tDESCRIPTION")
			for _, metric := range result.Metrics {
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", metric.Name, metric.Type, metric.Unit, metric.Source, metric.State, metric.HistoryState, strings.Join(metric.HistoryTiers, ","), metric.HistoryRetentionSeconds, strings.Join(metric.Labels, ","), metric.Description)
				if len(metric.Unsupported) > 0 {
					fmt.Fprintf(table, "  UNSUPPORTED\t%s\n", strings.Join(metric.Unsupported, ","))
				}
				for _, sample := range metric.Samples {
					fmt.Fprintf(table, "  SAMPLE\t%s\t%s\n", sample.Name, sample.Value)
				}
			}
		}
	case "history":
		var result observability.CatalogHistory
		if err := json.Unmarshal(data, &result); err != nil {
			return false, errors.New("invalid history JSON")
		}
		if result.Version != 1 {
			return false, errors.New("unsupported history version")
		}
		partial = result.Truncated || result.Pending || result.Incomplete || result.State != "available"
		value = result
		if format == "table" {
			fmt.Fprintf(table, "STATE\t%s\tREASON\t%s\nTRUNCATED\t%t\tPENDING\t%t\tINCOMPLETE\t%t\n", result.State, result.Reason, result.Truncated, result.Pending, result.Incomplete)
			fmt.Fprintf(table, "RETENTION START\t%s\tINTERVAL seconds\t%g\tDROPPED SERIES\t%d\n", result.RetentionStart.Format(time.RFC3339), result.IntervalSeconds, result.DroppedSeries)
			fmt.Fprintln(table, "METRIC\tLABELS\tTIER\tTIME\tVALUE\tMIN\tMAX")
			for _, series := range result.Series {
				fmt.Fprintf(table, "SERIES\t%s\tSTALE\t%t\tGAPS\t%t\tLAST OBSERVED\t%s\n", series.Metric, series.Stale, series.Gaps, series.LastObservedAt.Format(time.RFC3339))
				labels, _ := json.Marshal(series.Labels)
				for _, point := range series.Points {
					fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%g\t%g\t%g\n", series.Metric, labels, series.Tier, point.Time.Format(time.RFC3339), point.Value, point.Min, point.Max)
				}
			}
		}
	case "snapshot":
		var result observability.MemberSnapshot
		if err := json.Unmarshal(data, &result); err != nil || result.Member == "" || result.Version != observability.SnapshotVersion {
			return false, errors.New("invalid member snapshot JSON")
		}
		value = result
		partial = len(result.Errors) > 0 || result.MetricsTruncated
		if format == "table" {
			writeObserveMember(table, result)
		}
	case "cluster":
		var result observability.ClusterSnapshot
		if err := json.Unmarshal(data, &result); err != nil || result.Cell == "" {
			return false, errors.New("invalid cluster snapshot JSON")
		}
		value = result
		partial = len(result.Missing) > 0 || len(result.Members) == 0
		if format == "table" {
			fmt.Fprintf(table, "CELL\t%s\tOBSERVED\t%s\nMISSING\t%s\n", result.Cell, result.ObservedAt.Format(time.RFC3339), strings.Join(result.Missing, ","))
		}
		for _, member := range result.Members {
			partial = partial || len(member.Errors) > 0 || member.MetricsTruncated
			if format == "table" {
				writeObserveMember(table, member)
			}
		}
	case "events":
		var result []observability.Event
		if err := json.Unmarshal(data, &result); err != nil {
			return false, errors.New("invalid event JSON")
		}
		value = result
		if format == "table" {
			fmt.Fprintln(table, "SEQUENCE\tTIME\tLEVEL\tCOMPONENT\tMESSAGE\tATTRIBUTES")
			for _, event := range result {
				attrs, _ := json.Marshal(event.Attrs)
				fmt.Fprintf(table, "%d\t%s\t%s\t%s\t%s\t%s\n", event.Sequence, event.Time.Format(time.RFC3339), event.Level, event.Component, event.Message, attrs)
			}
		}
	}
	if format == "json" {
		err := json.MarshalWrite(out, struct {
			Version int    `json:"version"`
			View    string `json:"view"`
			Source  string `json:"source"`
			Partial bool   `json:"partial"`
			Data    any    `json:"data"`
		}{1, view, source, partial, value}, jsontext.WithIndent("  "))
		if err == nil {
			_, err = io.WriteString(out, "\n")
		}
		return partial, err
	}
	return partial, table.Flush()
}

func writeObserveMember(out io.Writer, member observability.MemberSnapshot) {
	fmt.Fprintf(out, "MEMBER\t%s\tCELL\t%s\tROLE\t%s\tREADY\t%t\tOBSERVED\t%s\n", member.Member, member.Cell, member.Role, member.Ready, member.ObservedAt.Format(time.RFC3339))
	for _, check := range member.Checks {
		fmt.Fprintf(out, "CHECK\t%s\tOK\t%t\t%s\n", check.Name, check.OK, check.Detail)
	}
	for _, name := range slices.Sorted(maps.Keys(member.Errors)) {
		fmt.Fprintf(out, "UNAVAILABLE\t%s\t%s\n", name, member.Errors[name])
	}
	fmt.Fprintf(out, "METRICS TRUNCATED\t%t\n", member.MetricsTruncated)
}
