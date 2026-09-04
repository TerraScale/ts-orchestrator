package vmqual

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

type Scenario string

const (
	ScenarioBootstrap      Scenario = "bootstrap"
	ScenarioAddRegion      Scenario = "add-region"
	ScenarioR3             Scenario = "control-r3"
	ScenarioReconcile      Scenario = "reconcile"
	ScenarioSignedDelivery Scenario = "signed-delivery"
	ScenarioRollback       Scenario = "rollback"
	ScenarioEdge           Scenario = "edge-promotion"
	ScenarioEstate         Scenario = "estate-publication"
	ScenarioSelfHeal       Scenario = "self-heal"
	ScenarioKeyRotation    Scenario = "key-rotation"
	ScenarioRestore        Scenario = "restore"
	ScenarioDegraded       Scenario = "degraded"
	ScenarioPartition      Scenario = "partition-heal"
	ScenarioPlacement      Scenario = "placement"
	ScenarioCleanup        Scenario = "cleanup"
)

var RequiredScenarios = []Scenario{ScenarioBootstrap, ScenarioAddRegion, ScenarioR3, ScenarioReconcile, ScenarioSignedDelivery, ScenarioRollback, ScenarioEdge, ScenarioEstate, ScenarioSelfHeal, ScenarioKeyRotation, ScenarioRestore, ScenarioDegraded, ScenarioPartition, ScenarioPlacement, ScenarioCleanup}

type ScenarioDriver interface {
	Run(context.Context, Scenario) error
}
type HTTPScenarioDriver struct {
	BaseURL string
	Client  *http.Client
	Timeout time.Duration
}

func (d HTTPScenarioDriver) Run(c context.Context, s Scenario) error {
	u, e := url.Parse(d.BaseURL)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return errors.New("vmqual: scenario endpoint must be an HTTP URL")
	}
	u.Path = path.Join(u.Path, "qualification", string(s))
	cc := d.Client
	if cc == nil {
		cc = &http.Client{}
	}
	t := d.Timeout
	if t <= 0 {
		t = 2 * time.Minute
	}
	x, cancel := context.WithTimeout(c, t)
	defer cancel()
	q, e := http.NewRequestWithContext(x, http.MethodPost, u.String(), bytes.NewBufferString(`{"qualification":"firecracker"}`))
	if e != nil {
		return e
	}
	q.Header.Set("Content-Type", "application/json")
	r, e := cc.Do(q)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
	if r.StatusCode < 200 || r.StatusCode > 299 {
		return fmt.Errorf("scenario %s returned %s", s, r.Status)
	}
	return nil
}

type ScenarioResult struct {
	Scenario Scenario      `json:"scenario"`
	Passed   bool          `json:"passed"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}
type SuiteReport struct {
	StartedAt, FinishedAt time.Time
	Scenarios             []ScenarioResult `json:"scenarios"`
}

func (r SuiteReport) OK() bool {
	if len(r.Scenarios) != len(RequiredScenarios) {
		return false
	}
	for _, s := range r.Scenarios {
		if !s.Passed {
			return false
		}
	}
	return true
}
func WriteSuiteReport(w io.Writer, r SuiteReport) error { return json.NewEncoder(w).Encode(r) }
func RunSuite(c context.Context, s *Stack, d ScenarioDriver) (r SuiteReport, e error) {
	if s == nil || d == nil {
		return r, errors.New("vmqual: stack and provider-contract driver are required")
	}
	r.StartedAt = time.Now().UTC()
	if e = s.Start(c); e != nil {
		return r, e
	}
	defer func() { r.FinishedAt = time.Now().UTC(); e = errors.Join(e, s.Cleanup(context.Background())) }()
	for _, x := range RequiredScenarios {
		st := time.Now()
		z := ScenarioResult{Scenario: x}
		z.Error = ""
		if zerr := d.Run(c, x); zerr != nil {
			z.Error = zerr.Error()
			e = zerr
		}
		z.Passed = z.Error == ""
		z.Duration = time.Since(st)
		r.Scenarios = append(r.Scenarios, z)
		if e != nil {
			break
		}
	}
	if e == nil && !r.OK() {
		e = errors.New("vmqual: suite incomplete")
	}
	return r, e
}
