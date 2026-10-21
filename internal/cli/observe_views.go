package cli

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/logs"
)

type observeFeatureFlags struct {
	since, subjectID, window, minLevel string
}

func (options *observeFeatureFlags) register(flags *flag.FlagSet) {
	flags.StringVar(&options.since, "since", "", "decision start time or duration")
	flags.StringVar(&options.subjectID, "subject-id", "", "exact decision subject identity")
	flags.StringVar(&options.window, "window", "1h", "summary or log window")
	flags.StringVar(&options.minLevel, "min-level", logs.LevelDebug, "minimum log level")
}

func (options observeFeatureFlags) query(view string, limit int, service string) (url.Values, error) {
	query := url.Values{}
	switch view {
	case "decisions":
		if limit < 1 || limit > decisionlog.MaxQueryLimit {
			return nil, errors.New("decision --limit must be between 1 and 1000")
		}
		query.Set("limit", strconv.Itoa(limit))
		query.Set("since", options.since)
		query.Set("subject_id", options.subjectID)
		if _, err := decisionlog.ParseQuery(query, time.Now()); err != nil {
			return nil, err
		}
	case "summary":
		window, err := time.ParseDuration(options.window)
		if err != nil || window < time.Minute || window > 7*24*time.Hour {
			return nil, errors.New("summary --window must be between 1m and 168h")
		}
		query.Set("window", options.window)
	case "logs":
		if limit < 1 {
			return nil, errors.New("log --limit must be between 1 and 500")
		}
		request := logs.Request{Version: 1, Window: options.window, MinLevel: options.minLevel, Service: service, Limit: limit}
		if err := request.Validate(); err != nil {
			return nil, err
		}
		query.Set("window", request.Window)
		query.Set("min_level", request.MinLevel)
		query.Set("service", request.Service)
		query.Set("limit", strconv.Itoa(request.Limit))
	}
	return query, nil
}

func writeObserveFeature(out io.Writer, view, format string, data []byte) (any, bool, error) {
	switch view {
	case "decisions":
		var result decisionlog.Result
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, false, errors.New("invalid decision journal JSON")
		}
		var fields struct {
			Decisions jsontext.Value `json:"decisions"`
		}
		if json.Unmarshal(data, &fields) != nil || len(fields.Decisions) == 0 {
			return nil, false, errors.New("decision journal omitted its observation")
		}
		for _, decision := range result.Decisions {
			if decision.Version != decisionlog.Version || decision.ID == "" || decision.Time.IsZero() {
				return nil, false, errors.New("invalid decision observation")
			}
		}
		partial := result.Partial || result.Truncated
		for _, region := range result.Regions {
			partial = partial || region.State != decisionlog.RegionOK
		}
		if format == "table" {
			fmt.Fprintf(out, "PARTIAL\t%t\tTRUNCATED\t%t\n", partial, result.Truncated)
			for _, region := range result.Regions {
				fmt.Fprintf(out, "REGION\t%s\tSTATE\t%s\tCOUNT\t%d\t%s\n", region.Region, region.State, region.Count, region.Detail)
			}
			fmt.Fprintln(out, "ID\tTIME\tREGION\tKIND\tSTATUS\tSUBJECT\tPARENT\tSUMMARY")
			for _, decision := range result.Decisions {
				fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", decision.ID, decision.Time.Format(time.RFC3339), decision.Region, decision.Kind, decision.Status, decision.Subject.ID, decision.ParentID, decision.Summary)
			}
		}
		return result, partial, nil
	case "insights":
		var result insights.Evaluation
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, false, errors.New("invalid insight evaluation JSON")
		}
		partial := result.At.IsZero() || len(result.Unavailable) > 0
		if format == "table" {
			observed := "unknown"
			if !result.At.IsZero() {
				observed = result.At.Format(time.RFC3339)
			}
			fmt.Fprintf(out, "OBSERVED\t%s\tUNAVAILABLE\t%s\n", observed, strings.Join(result.Unavailable, ","))
			fmt.Fprintln(out, "SEVERITY\tREGION\tENTITY\tTITLE\tWHY\tLAST SEEN")
			for _, insight := range result.Insights {
				fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n", insight.Severity, insight.Region, insight.Entity.ID, insight.Title, insight.Why, insight.LastSeen.Format(time.RFC3339))
			}
		}
		return result, partial, nil
	case "summary":
		var result insights.Summary
		// insights serves encoding/json v1, which writes time.Duration as nanoseconds.
		if err := json.Unmarshal(data, &result, jsonv1.FormatDurationAsNano(true)); err != nil || result.Generated.IsZero() || result.Window <= 0 {
			return nil, false, errors.New("invalid summary JSON")
		}
		if format == "table" {
			fmt.Fprintf(out, "SCOPE\t%s\tGENERATED\t%s\tWINDOW seconds\t%g\tPARTIAL\t%t\n%s\n", result.Scope, result.Generated.Format(time.RFC3339), result.Window.Seconds(), result.Partial, result.Text)
		}
		return result, result.Partial, nil
	case "logs":
		var result logs.Reply
		if err := json.Unmarshal(data, &result); err != nil || result.Version != 1 || result.Region == "" || result.From.IsZero() || result.To.IsZero() {
			return nil, false, errors.New("invalid log summary JSON")
		}
		if format == "table" {
			fmt.Fprintf(out, "REGION\t%s\tFROM\t%s\tTO\t%s\tGAPS\t%d\tTRUNCATED\t%t\n", result.Region, result.From.Format(time.RFC3339), result.To.Format(time.RFC3339), result.Gaps, result.Truncated)
			fmt.Fprintln(out, "SERVICE\tLEVEL\tTOTAL")
			for _, total := range result.Totals {
				fmt.Fprintf(out, "%s\t%s\t%d\n", total.Service, total.Level, total.Count)
			}
			fmt.Fprintln(out, "SERVICE\tLEVEL\tCOMPONENT\tCOUNT\tNODES\tFIRST\tLAST\tMESSAGE")
			for _, class := range result.Classes {
				fmt.Fprintf(out, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", class.Service, class.Level, class.Component, class.Count, strings.Join(class.Nodes, ","), class.First.Format(time.RFC3339), class.Last.Format(time.RFC3339), class.Message)
			}
			fmt.Fprintln(out, "COVERAGE\tnot reported by the log API; classes do not retain operation correlation")
		}
		return result, result.Gaps > 0 || result.Truncated, nil
	}
	return nil, false, errors.New("unsupported feature observation")
}
