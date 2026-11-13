package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// Verifier checks that a region serves: what TS-640 lacked when it was
// marked done.
type Verifier struct {
	HTTP           *http.Client
	Cell           string
	API, Auth      string
	LB             lb.API
	LoadBalancerID string
	BackendSets    []string
}

// Check is one verification result.
type Check struct {
	Name, Evidence string
	OK             bool
}

// Checks runs every check once.
func (v Verifier) Checks(ctx context.Context) []Check {
	var api struct {
		Status string `json:"status"`
		Region string `json:"region"`
	}
	code, err := v.get(ctx, v.API+"/healthz", &api)
	checks := []Check{{"api", fmt.Sprintf("GET %s/healthz: %s; status=%q region=%q", v.API, outcome(code, err), api.Status, api.Region),
		err == nil && code == http.StatusOK && api.Status == "ok" && api.Region == v.Cell}}

	pingURL := v.API + "/healthz"
	dashboard := "https://dashboard.terrascale.tech"
	code, headers, _, err := v.fetch(ctx, pingURL, dashboard)
	missing := pingHeaderGaps(code, headers)
	gaps := "all ping headers present"
	if len(missing) > 0 {
		gaps = strings.Join(missing, ", ")
	}
	checks = append(checks, Check{"api ping", fmt.Sprintf("GET %s with Origin: %s: %s; %s", pingURL, dashboard, outcome(code, err), gaps),
		err == nil && len(missing) == 0})

	var discovery struct {
		Issuer string `json:"issuer"`
	}
	issuer := v.Auth + "/terrascale"
	code, err = v.get(ctx, issuer+"/.well-known/openid-configuration", &discovery)
	checks = append(checks, Check{"auth", fmt.Sprintf("GET %s/.well-known/openid-configuration: %s; issuer=%q", issuer, outcome(code, err), discovery.Issuer),
		err == nil && code == http.StatusOK && discovery.Issuer == issuer})

	checks = append(checks, v.balancer(ctx))
	return checks
}

// balancer requires every backend set to hold backends, all healthy.
func (v Verifier) balancer(ctx context.Context) Check {
	if v.LB == nil || v.LoadBalancerID == "" {
		return Check{"load balancer", "the bound plan records no load balancer", false}
	}
	var evidence []string
	ok := true
	for _, set := range v.BackendSets {
		backends, err := v.LB.ListBackends(ctx, v.LoadBalancerID, set)
		if err != nil {
			return Check{"load balancer", set + ": " + err.Error(), false}
		}
		unhealthy, err := v.LB.UnhealthyBackends(ctx, v.LoadBalancerID, set)
		if err != nil {
			return Check{"load balancer", set + ": " + err.Error(), false}
		}
		evidence = append(evidence, fmt.Sprintf("%s %d/%d healthy", set, len(backends)-len(unhealthy), len(backends)))
		ok = ok && len(backends) > 0 && len(unhealthy) == 0
	}
	return Check{"load balancer", strings.Join(evidence, ", "), ok}
}

func outcome(code int, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("HTTP %d", code)
}

// get decodes a bounded JSON GET without following redirects.
func (v Verifier) get(ctx context.Context, url string, into any) (int, error) {
	code, _, body, err := v.fetch(ctx, url, "")
	if err != nil || code != http.StatusOK {
		return code, err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return code, errors.New("unexpected JSON")
	}
	return code, nil
}

func (v Verifier) fetch(ctx context.Context, url, origin string) (int, http.Header, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	} else {
		request.Header.Set("Cache-Control", "no-cache")
	}
	response, err := v.HTTP.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, response.Header, body, err
}

func pingHeaderGaps(code int, headers http.Header) []string {
	var missing []string
	if code != http.StatusOK {
		missing = append(missing, fmt.Sprintf("status is %d, want 200", code))
	}
	if got := headers.Get("Access-Control-Allow-Origin"); got != "*" {
		missing = append(missing, fmt.Sprintf("Access-Control-Allow-Origin is %q, want *", got))
	}
	if got := headers.Get("Timing-Allow-Origin"); got != "*" {
		missing = append(missing, fmt.Sprintf("Timing-Allow-Origin is %q, want *", got))
	}
	if !strings.Contains(headers.Get("Cache-Control"), "no-store") {
		missing = append(missing, fmt.Sprintf("Cache-Control is %q, want no-store", headers.Get("Cache-Control")))
	}
	return missing
}

// Until runs the checks every interval until all pass or wait ends, and
// returns the last results.
func (v Verifier) Until(ctx context.Context, wait, interval time.Duration) ([]Check, error) {
	deadline := time.Now().Add(wait)
	for {
		checks := v.Checks(ctx)
		failed := 0
		for _, check := range checks {
			if !check.OK {
				failed++
			}
		}
		if failed == 0 {
			return checks, nil
		}
		if !time.Now().Add(interval).Before(deadline) {
			return checks, fmt.Errorf("%d of %d region checks fail", failed, len(checks))
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return checks, ctx.Err()
		case <-timer.C:
		}
	}
}

// Print writes the checks as a Markdown table.
func Print(out io.Writer, checks []Check) error {
	if _, err := fmt.Fprintln(out, "| Check | Result | Evidence |\n| --- | --- | --- |"); err != nil {
		return err
	}
	for _, check := range checks {
		result := "PASS"
		if !check.OK {
			result = "FAIL"
		}
		if _, err := fmt.Fprintf(out, "| %s | %s | %s |\n", check.Name, result, strings.ReplaceAll(check.Evidence, "|", "\\|")); err != nil {
			return err
		}
	}
	return nil
}
