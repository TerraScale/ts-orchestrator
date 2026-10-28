// TS-512 runs the same scenarios against a disposable real stack or production.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type environment struct {
	DocumentsKeyIssued                                                       bool
	AuthUnavailable, DashboardUnavailable                                    string
	Target, TerraBaseURL, AdminURL, AuthURL, DashboardURL, StatusURL, Region string
	Credential, UserID, OrganizationID, APIKey                               string
	HTTP                                                                     *http.Client
	ProjectCredential                                                        projectCredential
	Database, UnrelatedDatabase                                              string
	ProductionReady                                                          bool
	OIDCAssertion, OIDCToken                                                 string
}
type result struct {
	Name       string   `json:"name"`
	Components []string `json:"components"`
	Tickets    []string `json:"tickets"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}
type report struct {
	SourceSHA          string              `json:"source_sha,omitempty"`
	ProjectCredential  *projectKeyMetadata `json:"project_credential,omitempty"`
	NegativeReadTarget *negativeReadTarget `json:"negative_read_target,omitempty"`
	LocalPins          json.RawMessage     `json:"local_pins,omitempty"`
	Target             string              `json:"target"`
	Started            time.Time           `json:"started"`
	Results            []result            `json:"scenarios"`
}
type pending struct{ ticket, reason string }

func (p pending) Error() string { return "PENDING(" + p.ticket + "): " + p.reason }

type scenario struct {
	name                string
	components, tickets []string
	run                 func(context.Context, *environment) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Stdout, os.Stderr))
}
func run(ctx context.Context, stdout, stderr io.Writer) int {
	target := envDefault("E2E_TARGET", "local")
	r := report{Target: target, Started: time.Now().UTC(), SourceSHA: os.Getenv("SOURCE_SHA")}
	suite := scenarios()
	if target == "prod" {
		suite = productionScenarios()
	}
	var e *environment
	var closeStack func() error
	var err error
	if target == "local" {
		r.LocalPins = localPinsJSON
		e, closeStack, err = startLocal(ctx)
	} else if target == "prod" {
		e, err = production()
	} else {
		err = fmt.Errorf("E2E_TARGET must be local or prod")
	}
	if e != nil && target == "prod" {
		r.ProjectCredential = &e.ProjectCredential.APIKey
		r.NegativeReadTarget = &negativeReadTarget{
			OrganizationID: e.ProjectCredential.APIKey.OrganizationID,
			ProjectID:      e.ProjectCredential.APIKey.ProjectID, Database: e.UnrelatedDatabase,
			Prerequisite: "Owner must confirm the distinct positive and negative databases already exist in the same approved project, with one document in the negative database and no key for it, before environment preparation and handoff; existence is not verified by this runner.",
		}
	}
	if err != nil {
		r.Results = append(r.Results, result{Name: "stack", Components: []string{"terrabase", "ts-auth", "ts-dashboard"}, Tickets: []string{"TS-512"}, Status: "fail", Detail: redact(err.Error(), e)})
		for _, s := range suite {
			r.Results = append(r.Results, result{Name: s.name, Components: s.components, Tickets: s.tickets, Status: "fail", Detail: "stack setup failed; scenario not executed"})
		}
	} else {
		for _, s := range suite {
			start := time.Now()
			scenarioCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			err := s.run(scenarioCtx, e)
			cancel()
			row := result{Name: s.name, Components: s.components, Tickets: s.tickets, Status: resultStatus(err), DurationMS: time.Since(start).Milliseconds()}
			if err != nil {
				row.Detail = redact(err.Error(), e)
			}
			r.Results = append(r.Results, row)
		}
	}
	if closeStack != nil {
		if err := closeStack(); err != nil {
			r.Results = append(r.Results, result{Name: "stack.cleanup", Components: []string{"stack"}, Tickets: []string{"TS-512"}, Status: "fail", Detail: redact(err.Error(), e)})
		}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.WriteFile(envDefault("E2E_REPORT", "report.json"), append(data, '\n'), 0600)
	}
	code := 0
	for _, row := range r.Results {
		fmt.Fprintf(stdout, "%s %s", strings.ToUpper(row.Status), row.Name)
		if row.Detail != "" {
			fmt.Fprintf(stdout, ": %s", row.Detail)
		}
		fmt.Fprintln(stdout)
		if row.Status == "fail" {
			code = 1
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "write JSON report: %v\n", err)
		code = 1
	}
	return code
}
func envDefault(key, value string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return value
}
func redact(message string, e *environment) string {
	if e != nil {
		for _, secret := range []string{e.Credential, e.APIKey, e.ProjectCredential.Key, e.OIDCAssertion, e.OIDCToken} {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
	}
	for _, name := range []string{"E2E_GITHUB_TOKEN", "TERRABASE_TOKEN", "E2E_MANAGEMENT_CREDENTIAL", "E2E_API_KEY", "E2E_PROJECT_CREDENTIAL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"} {
		if s := os.Getenv(name); s != "" {
			message = strings.ReplaceAll(message, s, "[redacted]")
		}
	}
	return message
}

// Probes have no SDK method. All document and Management calls use ts-go.
func probe(ctx context.Context, e *environment, origin, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(origin, "/")+path, nil)
	if err != nil {
		return err
	}
	res, err := e.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
		if err != nil {
			return err
		}
		if len(body) > 1<<20 {
			return errors.New("probe response exceeds 1 MiB")
		}
		return probeError{path: path, status: res.StatusCode, readinessStatus: decodeReadiness(body)}
	}
	_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	return err
}

type probeError struct {
	path            string
	status          int
	readinessStatus string
}

func (p probeError) Error() string { return fmt.Sprintf("%s: HTTP %d", p.path, p.status) }

func resultStatus(err error) string {
	if err == nil {
		return "pass"
	}
	// A pending feature joined with a cleanup failure must still fail.
	if _, ok := err.(pending); ok {
		return "pending"
	}
	return "fail"
}

func decodeReadiness(body []byte) string {
	var readiness struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &readiness) != nil {
		return ""
	}
	return readiness.Status
}
