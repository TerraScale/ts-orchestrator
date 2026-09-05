package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	cloudflareapi "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

const (
	reconcileContractDesiredName = "reconcile-contract.terrascale.tech"
	reconcileContractForeignName = "operator-owned.terrascale.tech"
	reconcileContractOwner       = "vmqual-reconcile-contract"
)

// ReconcileContractResult is provider-backed proof of the reconciliation
// behavior exercised by RunReconcileContract. The plans came from Loop.Pass,
// the records came from a final provider read, and both call sets are counted
// at their respective real boundaries.
type ReconcileContractResult struct {
	DesiredRecord        ReconcileContractDNSRecord `json:"desiredRecord"`
	UnownedRecord        ReconcileContractDNSRecord `json:"unownedRecord"`
	InitialPlan          ReconcileContractPlan      `json:"initialPlan"`
	EventualPlan         ReconcileContractPlan      `json:"eventualPlan"`
	MutableDriftPlan     ReconcileContractPlan      `json:"mutableDriftPlan"`
	FinalPlan            ReconcileContractPlan      `json:"finalPlan"`
	ProviderCalls        ReconcileContractCalls     `json:"providerCalls"`
	HTTPCalls            ReconcileContractHTTPCalls `json:"httpCalls"`
	SkippedUnownedDelete int                        `json:"skippedUnownedDelete"`
}

// ReconcileContractDNSRecord is the non-secret portion of a record observed
// from the local Cloudflare endpoint. Provider-generated identifiers are
// deliberately omitted from qualification evidence.
type ReconcileContractDNSRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// ReconcileContractPlan summarizes one actual Loop.Pass result.
type ReconcileContractPlan struct {
	Creates    int      `json:"creates"`
	Updates    int      `json:"updates"`
	Deletes    int      `json:"deletes"`
	References []string `json:"references,omitempty"`
}

// ReconcileContractCalls counts the exported reconcile provider contract.
type ReconcileContractCalls struct {
	Observes             int `json:"observes"`
	ApplyAttempts        int `json:"applyAttempts"`
	RetryableFailures    int `json:"retryableFailures"`
	Creates              int `json:"creates"`
	Updates              int `json:"updates"`
	Deletes              int `json:"deletes"`
	DeleteAuthorizations int `json:"deleteAuthorizations"`
}

// ReconcileContractHTTPCalls counts requests that actually reached the
// production Cloudflare client's transport. It includes the two deliberate
// out-of-band mutations used to introduce foreign state and mutable drift.
type ReconcileContractHTTPCalls struct {
	Lists   int `json:"lists"`
	Creates int `json:"creates"`
	Updates int `json:"updates"`
	Deletes int `json:"deletes"`
}

// RunReconcileContract exercises reconcile.NewLoop and Loop.Pass against the
// production Cloudflare HTTP client and the bounded local provider endpoint.
// It returns only after provider readback proves creation, drift repair,
// eventual observation, retry, and fail-closed handling of an unowned record.
func RunReconcileContract(ctx context.Context, endpoints *LocalProviderEndpoints, httpClient *http.Client) (ReconcileContractResult, error) {
	var result ReconcileContractResult
	if ctx == nil {
		return result, errors.New("vmqual: reconcile contract context is nil")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if endpoints == nil || endpoints.Cloudflare == nil || strings.TrimSpace(endpoints.CloudflareURL) == "" || endpoints.ZoneID == "" || endpoints.AccountID == "" {
		return result, errors.New("vmqual: reconcile contract requires a complete local Cloudflare endpoint")
	}

	transport := http.DefaultTransport
	if httpClient != nil && httpClient.Transport != nil {
		transport = httpClient.Transport
	}
	httpCalls := &reconcileContractTransport{next: transport}
	client := cloudflareapi.NewClient("vmqual-local", endpoints.ZoneID, endpoints.AccountID)
	client.BaseURL = strings.TrimRight(endpoints.CloudflareURL, "/")
	client.HTTP = httpCalls

	desired := cloudflareapi.DNSRecord{
		Name: reconcileContractDesiredName, Type: "A", Content: "192.0.2.44", TTL: 60, Proxied: true,
	}
	foreign := cloudflareapi.DNSRecord{
		Name: reconcileContractForeignName, Type: "A", Content: "198.51.100.77", TTL: 300, Proxied: false,
	}
	before, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract initial observation: %w", err)
	}
	if _, ok := reconcileContractRecordNamed(before, desired.Name); ok {
		return result, fmt.Errorf("vmqual: reconcile contract reserved record %q already exists", desired.Name)
	}
	if _, ok := reconcileContractRecordNamed(before, foreign.Name); ok {
		return result, fmt.Errorf("vmqual: reconcile contract reserved record %q already exists", foreign.Name)
	}
	if err := client.CreateDNSRecord(ctx, foreign); err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract seed unowned record: %w", err)
	}
	seeded, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract read seeded state: %w", err)
	}
	seededForeign, ok := reconcileContractRecordNamed(seeded, foreign.Name)
	if !ok || !reconcileContractSameDNS(seededForeign, foreign) {
		return result, errors.New("vmqual: reconcile contract provider did not retain the unowned seed record")
	}

	adapter := &reconcileContractDNSAdapter{
		client:             client,
		owned:              make(map[string]reconcileContractOwnedRecord),
		settling:           make(map[string]int),
		retryableRemaining: 1,
	}
	audit := &reconcileContractAudit{}
	spec := estate.Default()
	spec.Cloudflare.DNSRecords = []estate.DNSRecord{{
		Name: desired.Name, Type: desired.Type, Content: desired.Content,
		Proxied: desired.Proxied, TTL: uint32(desired.TTL),
	}}
	loop, err := reconcile.NewLoop(reconcile.LoopConfig{
		Spec:                spec,
		Providers:           []reconcile.Reconciler{adapter},
		Interval:            time.Hour,
		AllowDeletes:        true,
		RetryMaxAttempts:    3,
		RetryInitialBackoff: time.Millisecond,
		RetryMaxBackoff:     time.Millisecond,
		Progress:            reconcile.NewMemoryProgressStore(),
		Audit:               audit,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract loop: %w", err)
	}

	initial, err := loop.Pass(ctx)
	result.InitialPlan = reconcileContractSummarizePlan(initial)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract initial pass: %w", err)
	}
	if !reconcileContractHasAction(initial, reconcile.ActionCreate, desired.Name) {
		return result, errors.New("vmqual: reconcile contract initial pass did not plan the missing record")
	}
	if !reconcileContractHasAction(initial, reconcile.ActionDelete, foreign.Name) {
		return result, errors.New("vmqual: reconcile contract initial pass did not report unowned drift")
	}
	createdState, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract creation readback: %w", err)
	}
	created, ok := reconcileContractRecordNamed(createdState, desired.Name)
	if !ok || !reconcileContractSameDNS(created, desired) {
		return result, errors.New("vmqual: reconcile contract missing record was not created with declared attributes")
	}
	foreignAfterCreate, ok := reconcileContractRecordNamed(createdState, foreign.Name)
	if !ok || foreignAfterCreate.ID != seededForeign.ID || !reconcileContractSameDNS(foreignAfterCreate, foreign) {
		return result, errors.New("vmqual: reconcile contract changed the unowned record during creation")
	}
	initialCalls := adapter.callSnapshot()
	if initialCalls.ApplyAttempts != 2 || initialCalls.RetryableFailures != 1 || initialCalls.Creates != 1 {
		return result, fmt.Errorf("vmqual: reconcile contract retry/create calls = %+v", initialCalls)
	}

	// The provider reports a successful asynchronous mutation as creating for
	// one observation. The loop must wait for that observation to settle and
	// must not submit a duplicate create.
	eventual, err := loop.Pass(ctx)
	result.EventualPlan = reconcileContractSummarizePlan(eventual)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract eventual pass: %w", err)
	}
	if reconcileContractHasReference(eventual, desired.Name) || adapter.callSnapshot().Creates != 1 {
		return result, errors.New("vmqual: reconcile contract resubmitted a record while the provider reported it creating")
	}
	steady, err := loop.Pass(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract steady pass: %w", err)
	}
	if err := reconcileContractRequireOnlyDeletes(steady, foreign.Name); err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract did not settle after create: %w", err)
	}

	// Introduce mutable drift through the provider API, not through adapter
	// memory, then require Loop.Pass to observe and repair it.
	drifted := desired
	drifted.ID = created.ID
	drifted.Content = "203.0.113.99"
	if err := client.UpdateDNSRecord(ctx, drifted); err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract introduce mutable drift: %w", err)
	}
	driftedState, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract drift readback: %w", err)
	}
	observedDrift, ok := reconcileContractRecordNamed(driftedState, desired.Name)
	if !ok || !reconcileContractSameDNS(observedDrift, drifted) {
		return result, errors.New("vmqual: reconcile contract provider did not retain mutable drift")
	}

	driftPlan, err := loop.Pass(ctx)
	result.MutableDriftPlan = reconcileContractSummarizePlan(driftPlan)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract drift pass: %w", err)
	}
	if !reconcileContractHasAction(driftPlan, reconcile.ActionUpdate, desired.Name) || !reconcileContractHasChangedAttribute(driftPlan, desired.Name, "dns.content") {
		return result, errors.New("vmqual: reconcile contract mutable drift did not produce the expected content update")
	}
	repairedState, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract repair readback: %w", err)
	}
	repaired, ok := reconcileContractRecordNamed(repairedState, desired.Name)
	if !ok || !reconcileContractSameDNS(repaired, desired) {
		return result, errors.New("vmqual: reconcile contract provider state did not converge after mutable drift")
	}

	// Consume the update's bounded creating observation and then capture the
	// stable plan. Unowned drift remains visible but cannot reach Apply.
	if postUpdate, passErr := loop.Pass(ctx); passErr != nil {
		return result, fmt.Errorf("vmqual: reconcile contract post-update eventual pass: %w", passErr)
	} else if reconcileContractHasReference(postUpdate, desired.Name) {
		return result, errors.New("vmqual: reconcile contract resubmitted an update while the provider reported it creating")
	}
	final, err := loop.Pass(ctx)
	result.FinalPlan = reconcileContractSummarizePlan(final)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract final pass: %w", err)
	}
	if err := reconcileContractRequireOnlyDeletes(final, foreign.Name); err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract final plan: %w", err)
	}

	finalState, err := client.ListDNSRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: reconcile contract final provider observation: %w", err)
	}
	finalDesired, desiredPresent := reconcileContractRecordNamed(finalState, desired.Name)
	finalForeign, foreignPresent := reconcileContractRecordNamed(finalState, foreign.Name)
	if !desiredPresent || !reconcileContractSameDNS(finalDesired, desired) {
		return result, errors.New("vmqual: reconcile contract declared record is not converged in final provider state")
	}
	if !foreignPresent || finalForeign.ID != seededForeign.ID || !reconcileContractSameDNS(finalForeign, foreign) {
		return result, errors.New("vmqual: reconcile contract did not preserve the original unowned record")
	}

	result.DesiredRecord = reconcileContractPublicDNS(finalDesired)
	result.UnownedRecord = reconcileContractPublicDNS(finalForeign)
	result.ProviderCalls = adapter.callSnapshot()
	result.HTTPCalls = httpCalls.snapshot()
	result.SkippedUnownedDelete = audit.skippedDeleteCount(foreign.Name)
	if result.ProviderCalls.Updates != 1 || result.ProviderCalls.Deletes != 0 || result.ProviderCalls.DeleteAuthorizations != 0 {
		return result, fmt.Errorf("vmqual: reconcile contract mutation boundary calls = %+v", result.ProviderCalls)
	}
	if result.HTTPCalls.Creates != 2 || result.HTTPCalls.Updates != 2 || result.HTTPCalls.Deletes != 0 {
		return result, fmt.Errorf("vmqual: reconcile contract HTTP mutation calls = %+v", result.HTTPCalls)
	}
	if result.SkippedUnownedDelete == 0 {
		return result, errors.New("vmqual: reconcile contract did not audit the refused unowned deletion")
	}
	return result, nil
}

type reconcileContractOwnedRecord struct {
	name  string
	token string
}

type reconcileContractDNSAdapter struct {
	client *cloudflareapi.Client

	mu                 sync.Mutex
	owned              map[string]reconcileContractOwnedRecord
	settling           map[string]int
	retryableRemaining int
	calls              ReconcileContractCalls
}

var (
	_ reconcile.Reconciler       = (*reconcileContractDNSAdapter)(nil)
	_ reconcile.DeleteAuthorizer = (*reconcileContractDNSAdapter)(nil)
)

func (*reconcileContractDNSAdapter) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{estate.ResourceDNS}
}

func (a *reconcileContractDNSAdapter) Observe(ctx context.Context) (reconcile.State, error) {
	a.mu.Lock()
	a.calls.Observes++
	a.mu.Unlock()
	records, err := a.client.ListDNSRecords(ctx)
	if err != nil {
		return reconcile.State{}, err
	}
	state := reconcile.State{Resources: make([]reconcile.Resource, 0, len(records))}
	for _, record := range records {
		resource := reconcile.Resource{
			Ref:        estate.ResourceRef{Kind: estate.ResourceDNS, Name: record.Name},
			Attributes: reconcileContractAttributes(record),
			Status:     reconcile.ResourceHealthy,
		}
		a.mu.Lock()
		if owned, ok := a.owned[record.ID]; ok && owned.name == record.Name {
			resource.Ownership = reconcile.OwnershipProof{
				Owner: reconcileContractOwner, Token: owned.token, Verified: true, DeletionAllowed: true,
			}
			if a.settling[record.ID] > 0 {
				resource.Status = reconcile.ResourceCreating
				a.settling[record.ID]--
			}
		}
		a.mu.Unlock()
		state.Resources = append(state.Resources, resource)
	}
	return state, nil
}

func (a *reconcileContractDNSAdapter) Apply(ctx context.Context, plan reconcile.Plan) error {
	a.mu.Lock()
	a.calls.ApplyAttempts++
	if a.retryableRemaining > 0 {
		a.retryableRemaining--
		a.calls.RetryableFailures++
		a.mu.Unlock()
		return reconcileContractRetryableError{}
	}
	a.mu.Unlock()

	for _, action := range plan.Actions {
		record, err := reconcileContractRecordFromAction(action)
		if err != nil {
			return err
		}
		switch action.Kind {
		case reconcile.ActionCreate:
			if err := a.client.CreateDNSRecord(ctx, record); err != nil {
				return err
			}
			created, err := a.findUnique(ctx, record.Name)
			if err != nil {
				return err
			}
			a.mu.Lock()
			a.owned[created.ID] = reconcileContractOwnedRecord{name: created.Name, token: reconcileContractOwnershipToken(created.ID)}
			a.settling[created.ID] = 1
			a.calls.Creates++
			a.mu.Unlock()
		case reconcile.ActionUpdate:
			current, err := a.findUnique(ctx, action.Ref.Name)
			if err != nil {
				return err
			}
			record.ID = current.ID
			if err := a.client.UpdateDNSRecord(ctx, record); err != nil {
				return err
			}
			a.mu.Lock()
			a.settling[current.ID] = 1
			a.calls.Updates++
			a.mu.Unlock()
		case reconcile.ActionDelete:
			current, err := a.findUnique(ctx, action.Ref.Name)
			if err != nil {
				return err
			}
			a.mu.Lock()
			owned, ownedNow := a.owned[current.ID]
			a.mu.Unlock()
			if !ownedNow || owned.name != action.Ref.Name || owned.token != action.Ownership.Token {
				return errors.New("vmqual: reconcile contract refusing stale or unowned DNS deletion")
			}
			if err := a.client.DeleteDNSRecord(ctx, current.ID); err != nil {
				return err
			}
			a.mu.Lock()
			delete(a.owned, current.ID)
			delete(a.settling, current.ID)
			a.calls.Deletes++
			a.mu.Unlock()
		default:
			return fmt.Errorf("vmqual: reconcile contract unsupported action %q", action.Kind)
		}
	}
	return nil
}

func (a *reconcileContractDNSAdapter) AuthorizeDelete(ctx context.Context, action reconcile.Action) error {
	a.mu.Lock()
	a.calls.DeleteAuthorizations++
	a.mu.Unlock()
	if action.Ref.Kind != estate.ResourceDNS || action.Ownership.Owner != reconcileContractOwner || !action.Ownership.Verified || !action.Ownership.DeletionAllowed {
		return errors.New("vmqual: reconcile contract deletion ownership is invalid")
	}
	record, err := a.findUnique(ctx, action.Ref.Name)
	if err != nil {
		return err
	}
	a.mu.Lock()
	owned, ok := a.owned[record.ID]
	a.mu.Unlock()
	if !ok || owned.name != action.Ref.Name || owned.token != action.Ownership.Token {
		return errors.New("vmqual: reconcile contract deletion ownership changed")
	}
	return nil
}

func (a *reconcileContractDNSAdapter) findUnique(ctx context.Context, name string) (cloudflareapi.DNSRecord, error) {
	records, err := a.client.ListDNSRecords(ctx)
	if err != nil {
		return cloudflareapi.DNSRecord{}, err
	}
	var found cloudflareapi.DNSRecord
	count := 0
	for _, record := range records {
		if record.Name == name {
			found = record
			count++
		}
	}
	if count != 1 {
		return cloudflareapi.DNSRecord{}, fmt.Errorf("vmqual: reconcile contract found %d DNS records named %q", count, name)
	}
	return found, nil
}

func (a *reconcileContractDNSAdapter) callSnapshot() ReconcileContractCalls {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type reconcileContractRetryableError struct{}

func (reconcileContractRetryableError) Error() string {
	return "vmqual: reconcile contract provider is not ready"
}
func (reconcileContractRetryableError) Retryable() bool { return true }

type reconcileContractTransport struct {
	next  http.RoundTripper
	mu    sync.Mutex
	calls ReconcileContractHTTPCalls
}

func (t *reconcileContractTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.Contains(request.URL.Path, "/dns_records") {
		t.mu.Lock()
		switch request.Method {
		case http.MethodGet:
			t.calls.Lists++
		case http.MethodPost:
			t.calls.Creates++
		case http.MethodPatch, http.MethodPut:
			t.calls.Updates++
		case http.MethodDelete:
			t.calls.Deletes++
		}
		t.mu.Unlock()
	}
	return t.next.RoundTrip(request)
}

func (t *reconcileContractTransport) snapshot() ReconcileContractHTTPCalls {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

type reconcileContractAudit struct {
	mu      sync.Mutex
	entries []reconcile.AuditEntry
}

func (a *reconcileContractAudit) Append(_ context.Context, entry reconcile.AuditEntry) error {
	a.mu.Lock()
	a.entries = append(a.entries, entry)
	a.mu.Unlock()
	return nil
}

func (a *reconcileContractAudit) skippedDeleteCount(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := 0
	for _, entry := range a.entries {
		if entry.Ref.Kind == estate.ResourceDNS && entry.Ref.Name == name && entry.Action == reconcile.ActionDelete && entry.Result == "skipped" {
			count++
		}
	}
	return count
}

func reconcileContractRecordFromAction(action reconcile.Action) (cloudflareapi.DNSRecord, error) {
	if action.Ref.Kind != estate.ResourceDNS || action.Ref.Region != "" || action.Ref.Name == "" {
		return cloudflareapi.DNSRecord{}, errors.New("vmqual: reconcile contract received an invalid DNS reference")
	}
	values := make(map[string]string, len(action.Attributes))
	for _, attribute := range action.Attributes {
		if _, exists := values[attribute.Name]; exists {
			return cloudflareapi.DNSRecord{}, fmt.Errorf("vmqual: reconcile contract duplicate DNS attribute %q", attribute.Name)
		}
		values[attribute.Name] = attribute.Value
	}
	if len(values) != 4 {
		return cloudflareapi.DNSRecord{}, errors.New("vmqual: reconcile contract DNS action has an incomplete attribute set")
	}
	ttl, err := strconv.Atoi(values["dns.ttl"])
	if err != nil || ttl <= 0 {
		return cloudflareapi.DNSRecord{}, errors.New("vmqual: reconcile contract DNS TTL is invalid")
	}
	proxied, err := strconv.ParseBool(values["dns.proxied"])
	if err != nil {
		return cloudflareapi.DNSRecord{}, errors.New("vmqual: reconcile contract DNS proxy flag is invalid")
	}
	record := cloudflareapi.DNSRecord{
		Name: action.Ref.Name, Type: values["dns.type"], Content: values["dns.content"], TTL: ttl, Proxied: proxied,
		Tags: []string{cloudflareapi.DNSOwnershipTag},
	}
	if record.Type == "" || record.Content == "" {
		return cloudflareapi.DNSRecord{}, errors.New("vmqual: reconcile contract DNS type or content is empty")
	}
	return record, nil
}

func reconcileContractAttributes(record cloudflareapi.DNSRecord) []reconcile.Attribute {
	return []reconcile.Attribute{
		{Name: "dns.type", Value: record.Type},
		{Name: "dns.content", Value: record.Content},
		{Name: "dns.proxied", Value: strconv.FormatBool(record.Proxied)},
		{Name: "dns.ttl", Value: strconv.Itoa(record.TTL)},
	}
}

func reconcileContractOwnershipToken(id string) string {
	return "dns/" + id
}

func reconcileContractRecordNamed(records []cloudflareapi.DNSRecord, name string) (cloudflareapi.DNSRecord, bool) {
	var found cloudflareapi.DNSRecord
	count := 0
	for _, record := range records {
		if record.Name == name {
			found = record
			count++
		}
	}
	return found, count == 1
}

func reconcileContractSameDNS(left, right cloudflareapi.DNSRecord) bool {
	return left.Name == right.Name && left.Type == right.Type && left.Content == right.Content && left.TTL == right.TTL && left.Proxied == right.Proxied
}

func reconcileContractPublicDNS(record cloudflareapi.DNSRecord) ReconcileContractDNSRecord {
	return ReconcileContractDNSRecord{Name: record.Name, Type: record.Type, Content: record.Content, TTL: record.TTL, Proxied: record.Proxied}
}

func reconcileContractSummarizePlan(plan reconcile.Plan) ReconcileContractPlan {
	summary := ReconcileContractPlan{References: make([]string, 0, len(plan.Actions))}
	for _, action := range plan.Actions {
		switch action.Kind {
		case reconcile.ActionCreate:
			summary.Creates++
		case reconcile.ActionUpdate:
			summary.Updates++
		case reconcile.ActionDelete:
			summary.Deletes++
		}
		summary.References = append(summary.References, reconcile.RefKey(action.Ref))
	}
	return summary
}

func reconcileContractHasAction(plan reconcile.Plan, kind reconcile.ActionKind, name string) bool {
	for _, action := range plan.Actions {
		if action.Kind == kind && action.Ref.Kind == estate.ResourceDNS && action.Ref.Name == name {
			return true
		}
	}
	return false
}

func reconcileContractHasReference(plan reconcile.Plan, name string) bool {
	for _, action := range plan.Actions {
		if action.Ref.Kind == estate.ResourceDNS && action.Ref.Name == name {
			return true
		}
	}
	return false
}

func reconcileContractHasChangedAttribute(plan reconcile.Plan, name, attribute string) bool {
	for _, action := range plan.Actions {
		if action.Kind != reconcile.ActionUpdate || action.Ref.Kind != estate.ResourceDNS || action.Ref.Name != name {
			continue
		}
		for _, change := range action.Changes {
			if change.Name == attribute {
				return true
			}
		}
	}
	return false
}

func reconcileContractRequireOnlyDeletes(plan reconcile.Plan, requiredName string) error {
	found := false
	for _, action := range plan.Actions {
		if action.Kind != reconcile.ActionDelete {
			return fmt.Errorf("unexpected %s action for %s", action.Kind, reconcile.RefKey(action.Ref))
		}
		if action.Ref.Kind == estate.ResourceDNS && action.Ref.Name == requiredName {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("missing protected delete plan for %q", requiredName)
	}
	return nil
}
