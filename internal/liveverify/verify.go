// Package liveverify observes production without provisioning or issuing credentials.
package liveverify

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/commandio"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type row struct {
	Item, Status, Evidence, Tickets string
}

type verifier struct {
	ctx    context.Context
	http   *http.Client
	region string
	cell   string
	rows   []row
}

// Run requires an explicit opt-in; ordinary tests never contact production.
func Run(ctx context.Context, args []string, output io.Writer) (err error) {
	out := commandio.NewWriter(output)
	defer func() { err = errors.Join(err, out.Err()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	f := flag.NewFlagSet("verify", flag.ContinueOnError)
	f.SetOutput(out)
	live := f.Bool("live", os.Getenv("TS_VERIFY_LIVE") == "1", "opt in to read-only production requests")
	region := f.String("region", env("E2E_REGION", "gru-1"), "expected cell/region")
	cell := f.String("cell", env("TS_VERIFY_CELL", "gru"), "expected controller manifest cell (distinct from TerraBase region)")
	tb := f.String("terrabase-url", env("E2E_TERRABASE_URL", "https://gru.api.terrascale.tech"), "TerraBase origin")
	auth := f.String("auth-url", env("E2E_AUTH_URL", "https://gru.auth.terrascale.tech"), "ts-auth origin")
	dash := f.String("dashboard-url", env("E2E_DASHBOARD_URL", "https://dash.terrascale.tech"), "dashboard origin")
	status := f.String("status-url", env("E2E_STATUS_URL", "https://status.terrascale.tech"), "status origin")
	orch := f.String("orchestrator-url", os.Getenv("TS_VERIFY_ORCHESTRATOR_URL"), "controller observability origin (HTTPS or loopback tunnel)")
	timeout := f.Duration("timeout", 10*time.Second, "deadline per GET")
	if err := f.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if f.NArg() != 0 || *timeout <= 0 || *region == "" || *cell == "" {
		return errors.New("verify requires no positional arguments, a region and a positive timeout")
	}
	if !*live {
		return errors.New("verify requires --live or TS_VERIFY_LIVE=1; no requests sent")
	}
	for _, origin := range []string{*tb, *auth, *dash, *status, *orch} {
		if origin != "" && !validOrigin(origin) {
			return errors.New("origins must be HTTPS (HTTP only on loopback), without credentials, query, fragment or path")
		}
	}
	v := verifier{ctx: ctx, region: *region, cell: *cell, http: &http.Client{Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if *orch == "" {
		v.add("1. Orchestrator deployed and working", "UNKNOWN", "controller observability URL/token unavailable; no public controller route is assumed", "TS-484")
	} else {
		v.orchestrator(*orch)
	}
	v.health("TerraBase liveness", *tb, "/healthz", "ok", true, "TS-484, TS-486")
	// Both producer readiness probes write: TerraBase creates a scratch file;
	// ts-auth creates/reads/deletes a document. GET alone is not a read-only guarantee.
	v.add("2. Orchestrator deployed healthy TerraBase", "UNKNOWN", "liveness is reported separately; /readyz skipped (disk write); no current signed host deployment/readiness evidence", "TS-484, TS-485, TS-524")
	v.health("ts-auth liveness", *auth, "/healthz", "ok", false, "TS-487")
	v.add("3. ts-auth persists in TerraBase", "UNKNOWN", "/readyz skipped (creates/deletes storage probe documents); liveness does not establish the active store or durable records", "TS-489, TS-487, TS-525")
	v.health("Dashboard liveness", *dash, "/health/live", "ok", false, "TS-472")
	v.health("Dashboard readiness", *dash, "/health/ready", "ok", false, "TS-472")
	v.add("4. Dashboard persists in TerraBase", "UNKNOWN", "readiness only checks for a non-nil store; no evidence tying current service state to TerraBase documents", "TS-472, TS-492, TS-526")
	v.oidc(*auth)
	body, code, _, evidence := v.get(*status, "/api/v1/status", "")
	var publicStatus struct {
		Status      string    `json:"status"`
		GeneratedAt time.Time `json:"generatedAt"`
		Groups      []struct {
			Components []struct{ ID, Status string } `json:"components"`
		} `json:"groups"`
	}
	state := "PASS"
	if code != http.StatusOK || json.Unmarshal(body, &publicStatus) != nil || len(publicStatus.Groups) == 0 || publicStatus.GeneratedAt.IsZero() || publicStatus.Status == "" {
		state = "FAIL"
		evidence += "; expected timestamped status JSON with groups"
	} else {
		evidence += "; status=" + publicStatus.Status + ", generatedAt=" + publicStatus.GeneratedAt.UTC().Format(time.RFC3339) + " (observations only, not deployment/persistence proof)"
	}
	v.add("Status API response", state, evidence, "TS-497, TS-471")
	fmt.Fprintf(out, "Read-only production verification: cell=%s, region=%s, observed_at=%s\n\n", clean(*cell), clean(*region), time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(out, "| Item | Result | Evidence | Gap tickets |\n| --- | --- | --- | --- |")
	complete := true
	for _, r := range v.rows {
		fmt.Fprintf(out, "| %s | %s | %s | %s |\n", clean(r.Item), r.Status, clean(r.Evidence), r.Tickets)
		complete = complete && r.Status == "PASS"
	}
	if !complete {
		return errors.Join(ctx.Err(), errors.New("production verification incomplete: FAIL/UNKNOWN items require gap follow-up"))
	}
	return ctx.Err()
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
}

func clean(value string) string {
	for _, name := range []string{"TS_VERIFY_ORCHESTRATOR_TOKEN", "TS_VERIFY_OIDC_JWT", "E2E_MANAGEMENT_CREDENTIAL", "E2E_API_KEY"} {
		if secret := os.Getenv(name); secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)
	return strings.ReplaceAll(value, "|", "\\|")
}

func (v *verifier) add(item, status, evidence, tickets string) {
	v.rows = append(v.rows, row{item, status, evidence, tickets})
}

// get only requests reviewed paths, refuses redirects and never prints bodies,
// cookies, credentials, or raw upstream/network error messages.
func (v *verifier) get(origin, path, token string) ([]byte, int, http.Header, string) {
	target := strings.TrimRight(origin, "/") + path
	evidence := "GET " + target
	req, err := http.NewRequestWithContext(v.ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, nil, evidence + ": invalid request"
	}
	req.Header.Set("Cache-Control", "no-cache")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := v.http.Do(req)
	if err != nil {
		kind := "connection/TLS/DNS error"
		if v.ctx.Err() != nil {
			kind = "canceled"
		} else {
			var dns *net.DNSError
			if errors.As(err, &dns) {
				kind = "DNS lookup failed"
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				kind = "timeout"
			}
		}
		return nil, 0, nil, evidence + ": " + kind
	}
	defer res.Body.Close()
	evidence += fmt.Sprintf(": HTTP %d", res.StatusCode)
	for _, name := range []string{"X-TerraBase-Region", "X-TerraBase-Version", "X-Version", "CF-Ray"} {
		if value := res.Header.Get(name); value != "" && len(value) <= 128 {
			evidence += "; " + name + "=" + value
		}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, res.StatusCode, res.Header, evidence + "; unreadable/oversized body"
	}
	return body, res.StatusCode, res.Header, evidence
}

func (v *verifier) health(item, origin, path, expected string, regional bool, tickets string) {
	body, code, headers, evidence := v.get(origin, path, "")
	var payload struct{ Status, Version, Region string }
	state := "PASS"
	if code != http.StatusOK || json.Unmarshal(body, &payload) != nil || payload.Status != expected || payload.Version == "" {
		state = "FAIL"
		evidence += "; expected versioned health JSON, status=" + expected
	} else {
		evidence += "; version=" + payload.Version
		if regional && (payload.Region != v.region || headers.Get("X-TerraBase-Region") != v.region) {
			state = "FAIL"
			evidence += "; body/header region mismatch (want " + v.region + ")"
		}
	}
	v.add(item, state, evidence, tickets)
}

func (v *verifier) orchestrator(origin string) {
	_, health, _, he := v.get(origin, "/healthz", "")
	_, ready, _, re := v.get(origin, "/readyz", "")
	body, code, _, se := v.get(origin, "/v1/snapshot", os.Getenv("TS_VERIFY_ORCHESTRATOR_TOKEN"))
	var snapshot observability.MemberSnapshot
	state := "PASS"
	if health != 200 || ready != 200 {
		state = "FAIL"
	}
	if code == 401 || code == 403 {
		if state != "FAIL" {
			state = "UNKNOWN"
		}
	} else if code != 200 || json.Unmarshal(body, &snapshot) != nil || snapshot.Version != observability.SnapshotVersion || snapshot.Cell != v.cell || snapshot.Role != "controller" || !snapshot.Ready || snapshot.BuildVersion == "" || snapshot.Member == "" || time.Since(snapshot.ObservedAt) > 30*time.Second || time.Until(snapshot.ObservedAt) > 5*time.Second {
		state = "FAIL"
		se += "; expected current ready controller snapshot with cell/build identity"
	} else {
		se += "; cell=" + snapshot.Cell + ", member=" + snapshot.Member + ", build=" + snapshot.BuildVersion
	}
	v.add("1. Orchestrator deployed and working", state, he+"; "+re+"; "+se, "TS-484")
}
