package cli

import (
	"context"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
)

const observeHelp = `Usage: ts-orch observe [metrics|snapshot|cluster|events|releases] [flags]

Read the authenticated node dashboards. Defaults to cluster in every production region.
JSON output is a stream of version 1 documents, one per regional dashboard.
releases prints each region's last ts-orch release: published, discovered,
installed and ready on each host, gate start, gate end and complete.
  --region REGION        Select one runtime region instead of every production region
  --format table|json    Readable output or versioned JSON
  --search TEXT          Filter the metric catalog by name, description or source
  --limit 200            Recent events bound (1..2048); --after SEQUENCE resumes
  --url ORIGIN           Diagnostic endpoint; requires --token-file
  --token-file FILE      Private diagnostic token file; requires --url

Manager addresses resolve through NetBird DNS (ts-<region>-1:9463).
Credentials are read from the runtime Vault secret <region>-1-orch-dashboard-token.
No token is accepted as a command argument. Requests have a fixed 15-second
deadline and 8 MiB limit. Partial results are printed and return an error.
`

func runObserve(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && slices.Contains([]string{"help", "--help", "-h"}, args[0]) {
		_, err := io.WriteString(out, observeHelp)
		return err
	}
	view := "cluster"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		view, args = args[0], args[1:]
	}
	if !slices.Contains([]string{"metrics", "snapshot", "cluster", "events", "releases"}, view) {
		return fmt.Errorf("unknown observe view %q; use ts-orch observe --help", view)
	}
	flags := flag.NewFlagSet("observe "+view, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	region := flags.String("region", "", "region selector")
	format := flags.String("format", "table", "table or json")
	origin := flags.String("url", "", "diagnostic endpoint")
	tokenFile := flags.String("token-file", "", "private diagnostic token file")
	search := flags.String("search", "", "metric search")
	limit := flags.Int("limit", 200, "event limit")
	after := flags.Uint64("after", 0, "event sequence")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, observeHelp)
			return err
		}
		return fmt.Errorf("observe: %w", err)
	}
	if flags.NArg() != 0 || (*format != "table" && *format != "json") {
		return errors.New("observe accepts flags only; --format must be table or json")
	}
	if (*origin == "") != (*tokenFile == "") {
		return errors.New("diagnostic access requires --url and --token-file together")
	}
	if *origin != "" && *region != "" {
		return errors.New("--region does not apply to diagnostic --url access")
	}
	var wrongFlag string
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "search" && view != "metrics" || (f.Name == "limit" || f.Name == "after") && view != "events" {
			wrongFlag = f.Name
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
	case "events":
		if *limit < 1 || *limit > observability.DefaultEventCapacity {
			return errors.New("--limit must be between 1 and 2048")
		}
		query.Set("limit", strconv.Itoa(*limit))
		query.Set("after", strconv.FormatUint(*after, 10))
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, IdleConnTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	selectors := controlaccess.Regions()
	if *region != "" {
		selectors = []string{*region}
	}
	if *origin != "" {
		selectors = []string{*origin}
	}
	type answer struct {
		index  int
		source string
		data   []byte
		err    error
	}
	answers := make(chan answer, len(selectors))
	for i, selector := range selectors {
		go func() {
			access, err := observeAccess(ctx, selector, *origin, *tokenFile)
			if err != nil {
				answers <- answer{index: i, err: err}
				return
			}
			base := access.URLs[0]
			data, err := observeFetch(ctx, client, base, path, query, access.Token)
			answers <- answer{i, base, data, err}
		}()
	}
	results := make([]answer, len(selectors))
	for range selectors {
		result := <-answers
		results[result.index] = result
	}
	var failures []error
	for i, result := range results {
		if result.err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", selectors[i], result.err))
			if *format == "table" {
				if _, err := fmt.Fprintf(out, "REGION %s STATE unavailable\n", selectors[i]); err != nil {
					return errors.Join(append(failures, err)...)
				}
			}
			continue
		}
		var buffer strings.Builder
		partial, err := writeObserve(&buffer, view, *format, result.source, *search, result.data)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", result.source, err))
			continue
		}
		if partial {
			failures = append(failures, fmt.Errorf("%s: partial or truncated observation; inspect the reported gaps", result.source))
		}
		if _, err := io.WriteString(out, buffer.String()); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(failures...)
}

func observeAccess(ctx context.Context, region, origin, tokenFile string) (controlaccess.Access, error) {
	if origin == "" {
		return controlaccess.Resolve(ctx, region)
	}
	if _, err := controlaccess.Origin(origin); err != nil {
		return controlaccess.Access{}, err
	}
	file, err := os.Open(tokenFile)
	if err != nil {
		return controlaccess.Access{}, fmt.Errorf("open observe token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return controlaccess.Access{}, errors.New("observe token file must be a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return controlaccess.Access{}, err
	}
	token := strings.TrimSpace(string(data))
	clear(data)
	if len(data) > 4096 || len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n\x00") {
		return controlaccess.Access{}, errors.New("observe requires one 32-4096 byte bearer token from a private file")
	}
	return controlaccess.Access{URLs: []string{origin}, Token: token}, nil
}

func observeFetch(ctx context.Context, client *http.Client, base, path string, query url.Values, token string) ([]byte, error) {
	u, err := controlaccess.Origin(base)
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: API returned HTTP %d", base, response.StatusCode)
	}
	return data, nil
}

func writeObserve(out io.Writer, view, format, source, search string, data []byte) (bool, error) {
	var value any
	partial := false
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	switch view {
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
	case "releases":
		var result pullrelease.Status
		if err := json.Unmarshal(data, &result); err != nil || result.Region == "" {
			return false, errors.New("invalid release record JSON")
		}
		value = result
		if format == "table" {
			for _, line := range result.Timeline() {
				fmt.Fprintln(table, line)
			}
			if result.Reason != "" {
				fmt.Fprintf(table, "reason\t%s\n", result.Reason)
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
		}{1, view, source, partial, value}, jsontext.WithIndent("  "), jsonv1.FormatDurationAsNano(true))
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
