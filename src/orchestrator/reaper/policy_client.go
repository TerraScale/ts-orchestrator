package reaper

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrLifecyclePolicy contains no service credentials, owner addresses or remote
// response text. Unavailable or unrecognized policy must never permit an effect.
var ErrLifecyclePolicy = errors.New("reaper: lifecycle policy unavailable or invalid")

// LifecyclePolicyClientConfig pins the selected dashboard endpoint and supplies
// its service credential in memory. Transport is an explicit qualification seam.
type LifecyclePolicyClientConfig struct {
	Endpoint, ServiceKey string
	Transport            http.RoundTripper
	CheckEffectAuthority func(context.Context) error
	Clock                Clock
}

type LifecyclePolicyClient struct {
	endpoint, key string
	client        *http.Client
	check         func(context.Context) error
	clock         Clock
}

type LifecyclePolicyScope struct {
	OrganizationID   string `json:"organizationId"`
	ProjectID        string `json:"projectId"`
	DatabaseID       string `json:"databaseId"`
	ExpectedRevision string `json:"expectedRevision,omitempty"`
}

// LifecyclePolicyFacts are an authoritative policy observation for one admitted
// inventory entry, not a database catalog or inferred customer activity.
type LifecycleBillingGrace struct {
	StartedAt time.Time `json:"startedAt"`
	Deadline  time.Time `json:"deadline"`
}
type LifecycleBillingCoverage struct {
	PaidThrough           *time.Time                       `json:"paidThrough"`
	CardLoss              *LifecycleBillingGrace           `json:"cardLoss"`
	UncoveredStorage      *LifecycleBillingGrace           `json:"uncoveredStorage"`
	UnpaidStorageInvoices map[string]LifecycleBillingGrace `json:"unpaidStorageInvoices"`
}

type LifecyclePolicyFacts struct {
	Coverage                LifecycleBillingCoverage `json:"coverage"`
	SchemaVersion           int                      `json:"schemaVersion"`
	OrganizationID          string                   `json:"organizationId"`
	ProjectID               string                   `json:"projectId"`
	DatabaseID              string                   `json:"databaseId"`
	Revision                string                   `json:"revision"`
	ObservedAt              time.Time                `json:"observedAt"`
	Plan                    string                   `json:"plan"`
	LastAuthorizedRequestAt *time.Time               `json:"lastAuthorizedRequestAt"`
	DeletionProtection      bool                     `json:"deletionProtection"`
	OwnerEmails             []string                 `json:"ownerEmails"`
	PauseEligible           bool                     `json:"pauseEligible"`
	DeletionEligible        bool                     `json:"deletionEligible"`
	DeletionReasons         []string                 `json:"deletionReasons"`
	AccessRevoked           bool                     `json:"accessRevoked"`
	UsageStoppedAt          *time.Time               `json:"usageStoppedAt"`
	RetainUntil             *time.Time               `json:"retainUntil"`
	BillingGraceDeadline    *time.Time               `json:"billingGraceDeadline"`
	BillingDeletionEligible bool                     `json:"billingDeletionEligible"`
	IdleNoticeAccepted      bool                     `json:"idleNoticeAccepted"`
}

func NewLifecyclePolicyClient(c LifecyclePolicyClientConfig) (*LifecyclePolicyClient, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Path != "/api/internal/lifecycle/evaluate" || u.RawPath != "" || len(c.ServiceKey) < 32 || len(c.ServiceKey) > 4096 || strings.TrimSpace(c.ServiceKey) != c.ServiceKey || strings.ContainsAny(c.ServiceKey, "\r\n") || c.CheckEffectAuthority == nil {
		return nil, ErrLifecyclePolicy
	}
	if rt, ok := c.Transport.(*http.Transport); ok && rt.TLSClientConfig != nil && rt.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrLifecyclePolicy
	}
	clock := c.Clock
	if clock == nil {
		clock = systemClock{}
	} else if isNil(clock) {
		return nil, ErrLifecyclePolicy
	}
	return &LifecyclePolicyClient{endpoint: c.Endpoint, key: c.ServiceKey, check: c.CheckEffectAuthority, clock: clock, client: &http.Client{Transport: c.Transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func policyToken(s string) bool {
	if s == "" || strings.TrimSpace(s) != s || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (c *LifecyclePolicyClient) Evaluate(ctx context.Context, scope LifecyclePolicyScope) (LifecyclePolicyFacts, error) {
	if c == nil || c.client == nil || c.clock == nil || c.check == nil || ctx == nil || !policyToken(scope.OrganizationID) || !policyToken(scope.ProjectID) || !policyToken(scope.DatabaseID) || (scope.ExpectedRevision != "" && !policyToken(scope.ExpectedRevision)) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, err := json.Marshal(struct {
		SchemaVersion int `json:"schemaVersion"`
		LifecyclePolicyScope
	}{SchemaVersion: 1, LifecyclePolicyScope: scope})
	if err != nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-terrascale-lifecycle-service-key", c.key)
	if err := checkReaperEffect(ctx, c.check); err != nil {
		return LifecyclePolicyFacts{}, err
	}
	response, err := c.client.Do(req)
	if err != nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	facts, err := decodeLifecyclePolicy(raw)
	if err != nil {
		return LifecyclePolicyFacts{}, err
	}
	now := c.clock.Now()
	if facts.SchemaVersion != 1 || facts.OrganizationID != scope.OrganizationID || facts.ProjectID != scope.ProjectID || facts.DatabaseID != scope.DatabaseID || !policyToken(facts.Revision) || (scope.ExpectedRevision != "" && facts.Revision != scope.ExpectedRevision) || facts.ObservedAt.IsZero() || now.Sub(facts.ObservedAt) > time.Minute || facts.ObservedAt.Sub(now) > 5*time.Second {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if facts.Coverage.PaidThrough != nil && facts.Coverage.PaidThrough.IsZero() {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	validGrace := func(g LifecycleBillingGrace) bool {
		return !g.StartedAt.IsZero() && !g.Deadline.IsZero() && !g.Deadline.Before(g.StartedAt) &&
			g.Deadline.Sub(g.StartedAt) >= 30*24*time.Hour
	}
	if facts.Coverage.CardLoss != nil && !validGrace(*facts.Coverage.CardLoss) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if facts.Coverage.UncoveredStorage != nil && !validGrace(*facts.Coverage.UncoveredStorage) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if len(facts.Coverage.UnpaidStorageInvoices) > 1000 {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	for id, grace := range facts.Coverage.UnpaidStorageInvoices {
		if !policyToken(id) || !validGrace(grace) {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	if facts.BillingDeletionEligible {
		if _, err := selectedBillingGrace(facts, now); err != nil {
			return LifecyclePolicyFacts{}, err
		}
	}
	return facts, nil
}

func decodeLifecyclePolicy(raw []byte) (LifecyclePolicyFacts, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(raw, &fields); err != nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	// Every field is required; only the three explicitly nullable timestamps may
	// be null. Missing booleans must not silently become permission-granting false.
	for _, name := range []string{"coverage", "schemaVersion", "organizationId", "projectId", "databaseId", "revision", "observedAt", "plan", "lastAuthorizedRequestAt", "deletionProtection", "ownerEmails", "pauseEligible", "deletionEligible", "deletionReasons", "accessRevoked", "usageStoppedAt", "retainUntil", "billingGraceDeadline", "billingDeletionEligible", "idleNoticeAccepted"} {
		value, ok := fields[name]
		if !ok {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && name != "lastAuthorizedRequestAt" && name != "usageStoppedAt" && name != "retainUntil" && name != "billingGraceDeadline" {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	var coverage map[string]jsontext.Value
	if err := json.Unmarshal(fields["coverage"], &coverage); err != nil || len(coverage) != 4 {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	for _, name := range []string{"paidThrough", "cardLoss", "unpaidStorageInvoices", "uncoveredStorage"} {
		if _, ok := coverage[name]; !ok {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	if bytes.Equal(bytes.TrimSpace(coverage["unpaidStorageInvoices"]), []byte("null")) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	var facts LifecyclePolicyFacts
	if err := json.Unmarshal(raw, &facts, json.RejectUnknownMembers(true)); err != nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if (facts.Plan != "free" && facts.Plan != "starter" && facts.Plan != "pro" && facts.Plan != "scale") || len(facts.OwnerEmails) == 0 || len(facts.OwnerEmails) > 1000 || len(facts.DeletionReasons) > 100 {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	for _, address := range facts.OwnerEmails {
		if !ociMailbox(address) {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	for _, reason := range facts.DeletionReasons {
		if !policyToken(reason) {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	for _, timestamp := range []*time.Time{facts.LastAuthorizedRequestAt, facts.UsageStoppedAt, facts.RetainUntil} {
		if timestamp != nil && timestamp.IsZero() {
			return LifecyclePolicyFacts{}, ErrLifecyclePolicy
		}
	}
	if facts.LastAuthorizedRequestAt != nil && facts.LastAuthorizedRequestAt.After(facts.ObservedAt) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if facts.AccessRevoked != (facts.UsageStoppedAt != nil) {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if facts.BillingGraceDeadline != nil && facts.BillingGraceDeadline.IsZero() {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	if facts.BillingDeletionEligible && facts.BillingGraceDeadline == nil {
		return LifecyclePolicyFacts{}, ErrLifecyclePolicy
	}
	return facts, nil
}
