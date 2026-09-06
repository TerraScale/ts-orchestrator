package vmqualsuite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmqual"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/estatepublisher"
)

const (
	providerOperationsToken    = "vmqual-estate-public-token"
	providerOperationsDatabase = "control"
	providerTickLowerBound     = 9 * time.Second
	providerTickUpperBound     = 15 * time.Second
)

// ProviderOperationsContract qualifies criteria 9 and 10 through the live
// Stack, Cloudflare REST client, production loops, and the public TerraBase
// document client. The old deterministic operations contract remains in use
// for restore and placement tests only.
type ProviderOperationsContract struct {
	endpoints *LocalProviderEndpoints
	stack     *vmqual.Stack
	client    *http.Client
	objects   *localOperationsObjectStore
	stateRoot string
}

func (d *LocalScenarioDriver) providerOperationsContract() (*ProviderOperationsContract, error) {
	d.mu.Lock()
	if d.state.providerOps != nil {
		contract := d.state.providerOps
		d.mu.Unlock()
		return contract, nil
	}
	stack := d.stack
	d.mu.Unlock()
	contract, err := NewProviderOperationsContract(d.Endpoints, stack)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.state.providerOps == nil {
		d.state.providerOps = contract
	} else {
		contract = d.state.providerOps
	}
	d.mu.Unlock()
	return contract, nil
}

func NewProviderOperationsContract(endpoints *LocalProviderEndpoints, stack *vmqual.Stack) (*ProviderOperationsContract, error) {
	if endpoints == nil || endpoints.Cloudflare == nil || endpoints.CloudflareURL == "" || endpoints.Edge == nil || stack == nil {
		return nil, errors.New("vmqual: provider operations require live stack, Cloudflare, and edge endpoints")
	}
	stateRoot := filepath.Join(stack.Config().StateRoot, "provider-operations")
	if !filepath.IsAbs(stateRoot) {
		return nil, errors.New("vmqual: provider operations state root must be absolute")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return &ProviderOperationsContract{
		endpoints: endpoints, stack: stack, client: client, stateRoot: stateRoot,
		objects: &localOperationsObjectStore{endpoints: endpoints, client: client},
	}, nil
}

func (c *ProviderOperationsContract) cloudflareClient() *cf.Client {
	client := cf.NewClient("vmqual-provider-operations", c.endpoints.ZoneID, c.endpoints.AccountID)
	client.BaseURL = c.endpoints.CloudflareURL
	if c.client.Transport != nil {
		client.HTTP = c.client.Transport
	}
	return client
}

type providerKVSource struct {
	mu                    sync.Mutex
	observedPlacementPath string
	stack                 *vmqual.Stack
	registryPath          string
	placementPath         string
}

// selectRevision admits an already persisted pair without filesystem work while
// the real health ticker is running. Each observation pass pins the pair so a
// notification cannot mix an old health catalog with a new placement revision.
func (s *providerKVSource) selectRevision(registryPath, placementPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registryPath, s.placementPath = registryPath, placementPath
}

func (s *providerKVSource) ObserveRegionHealth(ctx context.Context) (map[string]cf.RegionHealth, error) {
	s.mu.Lock()
	registryPath := s.registryPath
	s.observedPlacementPath = s.placementPath
	s.mu.Unlock()
	var registry struct {
		Regions []string `json:"regions"`
	}
	if err := readStrictProviderJSON(registryPath, &registry); err != nil {
		return nil, fmt.Errorf("vmqual: read registered Regions: %w", err)
	}
	if len(registry.Regions) == 0 || len(registry.Regions) > 20 {
		return nil, errors.New("vmqual: registered Region catalog is invalid")
	}
	live, err := observeProviderGuests(ctx, s.stack)
	if err != nil {
		return nil, err
	}
	result := make(map[string]cf.RegionHealth, len(registry.Regions))
	seen := make(map[string]struct{}, len(registry.Regions))
	for _, region := range registry.Regions {
		region = strings.ToLower(strings.TrimSpace(region))
		if region == "" {
			return nil, errors.New("vmqual: registered Region code is empty")
		}
		if _, duplicate := seen[region]; duplicate {
			return nil, errors.New("vmqual: registered Region code is duplicated")
		}
		seen[region] = struct{}{}
		members := append([]string(nil), live[region]...)
		sort.Strings(members)
		result[region] = cf.RegionHealth{Region: region, Healthy: len(members) == 2, Members: members}
	}
	return result, nil
}

func (s *providerKVSource) ObserveDBPlacement(ctx context.Context) (map[string]cf.DBPlacement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	placementPath := s.observedPlacementPath
	s.mu.Unlock()
	if placementPath == "" {
		return nil, errors.New("vmqual: placement observation requires a pinned health revision")
	}
	result := map[string]cf.DBPlacement{}
	if err := readStrictProviderJSON(placementPath, &result); err != nil {
		return nil, fmt.Errorf("vmqual: read durable placement projection: %w", err)
	}
	if len(result) == 0 || len(result) > 4096 {
		return nil, errors.New("vmqual: durable placement projection is invalid")
	}
	return result, nil
}

func observeProviderGuests(ctx context.Context, stack *vmqual.Stack) (map[string][]string, error) {
	if stack == nil {
		return nil, errors.New("vmqual: live guest observation requires a stack")
	}
	snapshot := stack.Snapshot()
	vms, guests := snapshot.VMs, snapshot.Guests
	result := make(map[string][]string)
	for _, guest := range guests {
		vm := vms[guest.ID]
		if vm == nil {
			continue
		}
		observed, err := vm.Inspect(ctx)
		if err != nil {
			return nil, fmt.Errorf("vmqual: observe provider guest %s: %w", guest.ID, err)
		}
		if observed.ID != guest.ID || observed.Region != guest.Region {
			return nil, fmt.Errorf("vmqual: provider guest %s returned mismatched identity", guest.ID)
		}
		if observed.Running && observed.Ready {
			result[strings.ToLower(string(guest.Region))] = append(result[strings.ToLower(string(guest.Region))], guest.ID)
		}
	}
	return result, nil
}

type providerKVEvent struct {
	at   time.Time
	kind string
	key  string
}

type providerKVStore struct {
	delegate *cf.Client
	mu       sync.Mutex
	events   []providerKVEvent
	changed  chan struct{}
}

func (s *providerKVStore) SetWorkerHealth(ctx context.Context, value cf.WorkerHealthDoc) error {
	if err := s.delegate.SetWorkerHealth(ctx, value); err != nil {
		return err
	}
	s.record("set-health", "regions")
	return nil
}
func (s *providerKVStore) SetWorkerPlacements(ctx context.Context, values map[string]cf.WorkerPlacement) error {
	if err := s.delegate.SetWorkerPlacements(ctx, values); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s.record("set-placement", key)
	}
	return nil
}
func (s *providerKVStore) DeleteWorkerPlacements(ctx context.Context, keys []string) error {
	if err := s.delegate.DeleteWorkerPlacements(ctx, keys); err != nil {
		return err
	}
	for _, key := range keys {
		s.record("delete-placement", key)
	}
	return nil
}

func (s *providerKVStore) record(kind, key string) {
	s.mu.Lock()
	s.events = append(s.events, providerKVEvent{at: time.Now(), kind: kind, key: key})
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *providerKVStore) snapshot() []providerKVEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]providerKVEvent(nil), s.events...)
}

func (c *ProviderOperationsContract) QualifyKV(ctx context.Context) (KVOperationsResult, error) {
	var result KVOperationsResult
	if ctx == nil {
		return result, errors.New("vmqual: provider KV context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := os.MkdirAll(c.stateRoot, 0o700); err != nil {
		return result, fmt.Errorf("vmqual: create provider operations state: %w", err)
	}
	registryPath := filepath.Join(c.stateRoot, "regions.json")
	placementPath := filepath.Join(c.stateRoot, "placement.json")
	if err := writeProviderJSON(registryPath, map[string]any{"regions": []string{"fra", "gru", "iad", "sfo"}}); err != nil {
		return result, err
	}
	if err := writeProviderJSON(placementPath, map[string]cf.DBPlacement{
		"qualification-live":  {Regions: []string{"gru", "fra"}, PlacementLock: "explicit", Generation: 1},
		"qualification-stale": {Regions: []string{"sfo"}, PlacementLock: "explicit", Generation: 1},
	}); err != nil {
		return result, err
	}
	client := c.cloudflareClient()
	if err := ensureKVNamespaces(ctx, client); err != nil {
		return result, err
	}
	// Prepare immutable source revisions before starting the real ticker. Disk
	// synchronization is setup work, not part of notification latency or cadence.
	nextRegistryPath := filepath.Join(c.stateRoot, "regions-next.json")
	nextPlacementPath := filepath.Join(c.stateRoot, "placement-next.json")
	if err := writeProviderJSON(nextRegistryPath, map[string]any{"regions": []string{"fra", "gru", "sfo"}}); err != nil {
		return result, err
	}
	if err := writeProviderJSON(nextPlacementPath, map[string]cf.DBPlacement{
		"qualification-live": {Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 2},
	}); err != nil {
		return result, err
	}
	source := &providerKVSource{stack: c.stack, registryPath: registryPath, placementPath: placementPath}
	store := &providerKVStore{delegate: client, changed: make(chan struct{}, 1)}
	var budgetMu sync.Mutex
	var budget []int
	writer, err := cf.NewKVWriter(cf.KVWriterConfig{
		Store: store, Health: source, Placement: source,
		MaxWritesPerTick: 2,
		OnBudgetExceeded: func(writes int) {
			budgetMu.Lock()
			budget = append(budget, writes)
			budgetMu.Unlock()
		},
	})
	if err != nil {
		return result, err
	}
	result.Interval = writer.Interval()
	if cf.DefaultKVWriterHealthInterval != 10*time.Second || result.Interval != cf.DefaultKVWriterHealthInterval {
		return result, fmt.Errorf("vmqual: production KV interval is %s, want 10s", result.Interval)
	}
	if err := writer.Start(ctx); err != nil {
		return result, err
	}
	defer writer.Close()
	if err := awaitProviderKVEvents(ctx, store, 3, 3*time.Second); err != nil {
		return result, fmt.Errorf("vmqual: initial provider KV pass: %w", err)
	}
	initial := store.snapshot()
	result.InitialWrites = len(initial)
	if err := awaitProviderKVEvents(ctx, store, 4, providerTickUpperBound); err != nil {
		return result, fmt.Errorf("vmqual: periodic provider KV pass: %w", err)
	}
	periodic := store.snapshot()
	result.RefreshWrites = len(periodic) - result.InitialWrites
	elapsed := periodic[result.InitialWrites].at.Sub(initial[0].at)
	if elapsed < providerTickLowerBound || elapsed > providerTickUpperBound {
		return result, fmt.Errorf("vmqual: observed KV refresh after %s, want one real 10s tick", elapsed)
	}
	source.selectRevision(nextRegistryPath, nextPlacementPath)
	writer.NotifyChange()
	if err := awaitProviderKVEvents(ctx, store, 7, 3*time.Second); err != nil {
		return result, fmt.Errorf("vmqual: notified provider KV pass: %w", err)
	}
	if err := awaitProviderKVWriteCount(ctx, writer, 7, 3*time.Second); err != nil {
		return result, fmt.Errorf("vmqual: notified provider KV accounting: %w", err)
	}
	allEvents := store.snapshot()
	result.TransitionWrites = len(allEvents) - len(periodic)
	for _, event := range allEvents[len(periodic):] {
		result.TransitionOrder = append(result.TransitionOrder, event.kind+":"+event.key)
	}
	wantOrder := []string{
		"set-health:regions", "set-placement:qualification-live", "delete-placement:qualification-stale",
	}
	if !equalStrings(result.TransitionOrder, wantOrder) {
		return result, fmt.Errorf("vmqual: provider KV transition order is %v", result.TransitionOrder)
	}
	placement, err := client.WorkerPlacement(ctx, "qualification-live")
	if err != nil {
		return result, err
	}
	healthValue, healthErr := client.WorkerHealth(ctx)
	if healthErr != nil {
		return result, healthErr
	}
	_, staleHealth := healthValue.Regions["IAD"]
	_, stalePlacementErr := client.WorkerPlacement(ctx, "qualification-stale")
	result.StaleHealthRemoved = !staleHealth
	result.StalePlacementRemoved = errors.Is(stalePlacementErr, cf.ErrNotFound)
	result.PlacementRegions = append([]string(nil), placement.R...)
	result.PlacementGeneration = placement.G
	result.TotalWrites = writer.WriteCount()
	budgetMu.Lock()
	result.BudgetObservations = append([]int(nil), budget...)
	budgetMu.Unlock()
	if writer.LastError() != nil || !result.StaleHealthRemoved || !result.StalePlacementRemoved ||
		!equalStrings(result.PlacementRegions, []string{"GRU"}) || result.PlacementGeneration != 2 ||
		result.InitialWrites != 3 || result.RefreshWrites != 1 || result.TransitionWrites != 3 || result.TotalWrites != 7 ||
		!equalInts(result.BudgetObservations, []int{3, 3}) {
		return result, fmt.Errorf("vmqual: provider KV proof is incomplete: %+v lastError=%v", result, writer.LastError())
	}
	return result, nil
}

func awaitProviderKVEvents(ctx context.Context, store *providerKVStore, count int, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(store.snapshot()) < count {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-store.changed:
		case <-timer.C:
			return errors.New("provider KV event observation timed out")
		}
	}
	return nil
}

func awaitProviderKVWriteCount(ctx context.Context, writer *cf.KVWriter, count int, timeout time.Duration) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for writer.WriteCount() < count {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-timer.C:
			return errors.New("provider KV write accounting timed out")
		}
	}
	return nil
}

type providerEstateEvent struct {
	at     time.Time
	result estatepublisher.PublishResult
}

type providerEstateSource struct {
	stack     *vmqual.Stack
	endpoints *LocalProviderEndpoints
	cloud     *cf.Client
}

func (s *providerEstateSource) snapshot(ctx context.Context) (estate.Snapshot, error) {
	live, err := observeProviderGuests(ctx, s.stack)
	if err != nil {
		return estate.Snapshot{}, err
	}
	regions := make([]map[string]any, 0, len(live))
	hosts := make([]map[string]any, 0, 6)
	regionNames := make([]string, 0, len(live))
	for region := range live {
		regionNames = append(regionNames, region)
	}
	sort.Strings(regionNames)
	for _, region := range regionNames {
		members := append([]string(nil), live[region]...)
		sort.Strings(members)
		regions = append(regions, map[string]any{"code": region, "members": len(members), "serving": len(members) == 2})
		for _, member := range members {
			hosts = append(hosts, map[string]any{"id": member, "region": region, "ready": true})
		}
	}
	placement, err := s.cloud.WorkerPlacement(ctx, "qualification-live")
	if err != nil {
		return estate.Snapshot{}, err
	}
	deployments, err := s.cloud.ListWorkerDeployments(ctx, "ts-dashboard")
	if err != nil {
		return estate.Snapshot{}, err
	}
	routes, err := s.cloud.ListWorkerRoutes(ctx)
	if err != nil {
		return estate.Snapshot{}, err
	}
	snippets, err := s.cloud.ListSnippets(ctx)
	if err != nil {
		return estate.Snapshot{}, err
	}
	metrics := s.endpoints.Edge.Metrics()
	return estate.Snapshot{
		Regions:   map[string]any{"regions": regions},
		Hosts:     map[string]any{"hosts": hosts},
		Databases: map[string]any{"databases": []any{placement}},
		Rollouts:  map[string]any{"workerDeployments": len(deployments)},
		SLO: map[string]any{
			"cacheHits": metrics.CacheHits, "cacheableResponses": metrics.CacheableResponses,
			"labels": map[string]string{"region": "gru", "subsystem": "orchestrator"},
		},
		Reconcile: map[string]any{
			"workerRoutes": len(routes), "snippets": len(snippets),
			"api_token": "vmqual-never-publish-this-secret",
		},
	}, nil
}

type localControlPlaneEndpoint struct {
	objects *localOperationsObjectStore

	mu         sync.Mutex
	writes     int
	idempotent map[string]string
}

func (h *localControlPlaneEndpoint) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPut || request.Header.Get("Authorization") != "Bearer "+providerOperationsToken {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	prefix := "/api/v1/databases/" + providerOperationsDatabase + "/collections/" + estate.EstateCollection + "/documents/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	docID := strings.TrimPrefix(request.URL.Path, prefix)
	if !containsString(estatepublisher.EstateDocIDs(), docID) || strings.Contains(docID, "/") {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, estatepublisher.DefaultMaxDocumentBytes+1))
	if err != nil || len(body) == 0 || len(body) > estatepublisher.DefaultMaxDocumentBytes || !json.Valid(body) {
		http.Error(response, "invalid document", http.StatusBadRequest)
		return
	}
	fingerprint := request.URL.Path + "\x00" + string(body)
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if idempotencyKey == "" || len(idempotencyKey) > 128 {
		http.Error(response, "idempotency key required", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	if prior, ok := h.idempotent[idempotencyKey]; ok {
		h.mu.Unlock()
		if prior != fingerprint {
			http.Error(response, "idempotency conflict", http.StatusConflict)
			return
		}
		h.writeReceipt(response, body)
		return
	}
	h.mu.Unlock()
	key := "control-plane/estate/" + docID + ".json"
	if err := h.objects.put(request.Context(), operationsControlRegion, operationsControlBucket, key, body); err != nil {
		http.Error(response, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	h.mu.Lock()
	h.idempotent[idempotencyKey] = fingerprint
	h.writes++
	h.mu.Unlock()
	h.writeReceipt(response, body)
}

func (h *localControlPlaneEndpoint) writeReceipt(response http.ResponseWriter, body []byte) {
	digest := sha256.Sum256(body)
	revision := hex.EncodeToString(digest[:])
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("ETag", `"`+revision+`"`)
	_ = json.NewEncoder(response).Encode(map[string]string{"revision": revision})
}

func (h *localControlPlaneEndpoint) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.writes
}

func (c *ProviderOperationsContract) QualifyEstate(ctx context.Context) (EstateOperationsResult, error) {
	var result EstateOperationsResult
	if ctx == nil {
		return result, errors.New("vmqual: provider estate context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := c.objects.ensureBucket(ctx, operationsControlRegion, operationsControlBucket); err != nil {
		return result, err
	}
	handler := &localControlPlaneEndpoint{objects: c.objects, idempotent: make(map[string]string)}
	server := httptest.NewServer(handler)
	defer server.Close()
	publicClient, err := estate.NewControlPlaneClient(estate.ControlPlaneClientConfig{
		BaseURL: server.URL, Database: providerOperationsDatabase,
		Token: estate.StaticToken(providerOperationsToken), HTTP: c.client,
	})
	if err != nil {
		return result, err
	}
	source := &providerEstateSource{stack: c.stack, endpoints: c.endpoints, cloud: c.cloudflareClient()}
	events := make(chan providerEstateEvent, 8)
	publisher, err := estatepublisher.NewProductionPublisher(estatepublisher.Config{
		Client: publicClient, Snapshot: source.snapshot, Generation: 7,
		OnSuccess: func(published estatepublisher.PublishResult) {
			events <- providerEstateEvent{at: time.Now(), result: published}
		},
		RetryMaxAttempts: 1,
	})
	if err != nil {
		return result, err
	}
	result.Interval = publisher.Interval()
	if estatepublisher.DefaultPublisherInterval != 10*time.Second || result.Interval != estatepublisher.DefaultPublisherInterval {
		return result, fmt.Errorf("vmqual: production estate interval is %s, want 10s", result.Interval)
	}
	if err := publisher.Start(ctx); err != nil {
		return result, err
	}
	defer publisher.Close()
	initial, err := awaitProviderEstateEvent(ctx, events, 3*time.Second)
	if err != nil {
		return result, fmt.Errorf("vmqual: initial public estate pass: %w", err)
	}
	result.InitialWrites = initial.result.Writes
	if result.InitialWrites != len(estatepublisher.DocumentIDs) {
		return result, fmt.Errorf("vmqual: initial public estate writes = %d", result.InitialWrites)
	}
	if _, err := probeDeliveryReactivePath(ctx, c.endpoints, c.client); err != nil {
		return result, fmt.Errorf("vmqual: mutate observed edge state for estate publication: %w", err)
	}
	publisher.NotifyChange()
	changed, err := awaitProviderEstateEvent(ctx, events, 3*time.Second)
	if err != nil {
		return result, fmt.Errorf("vmqual: changed public estate pass: %w", err)
	}
	result.OnChangeWrites = changed.result.Writes
	if result.OnChangeWrites != 1 {
		return result, fmt.Errorf("vmqual: notified public estate writes = %d, want 1", result.OnChangeWrites)
	}
	periodic, err := awaitProviderEstateEvent(ctx, events, providerTickUpperBound)
	if err != nil {
		return result, fmt.Errorf("vmqual: periodic public estate pass: %w", err)
	}
	result.UnchangedWrites = periodic.result.Writes
	elapsed := periodic.at.Sub(initial.at)
	if elapsed < providerTickLowerBound || elapsed > providerTickUpperBound || result.UnchangedWrites != 0 {
		return result, fmt.Errorf("vmqual: periodic estate pass after %s wrote %d documents", elapsed, result.UnchangedWrites)
	}
	result.Documents = estatepublisher.EstateDocIDs()
	secretAbsent := true
	for _, docID := range result.Documents {
		raw, found, readErr := c.objects.get(ctx, operationsControlRegion, operationsControlBucket, "control-plane/estate/"+docID+".json")
		if readErr != nil || !found || !json.Valid(raw) {
			return result, fmt.Errorf("vmqual: public estate readback %s failed: %w", docID, readErr)
		}
		if bytes.Contains(raw, []byte("vmqual-never-publish-this-secret")) {
			secretAbsent = false
		}
	}
	result.PersistentReadback = true
	result.SecretRejected = secretAbsent
	writesBeforeUnsafe := handler.count()
	unsafePublisher, err := estatepublisher.NewProductionPublisher(estatepublisher.Config{
		Client: publicClient, Generation: 7, RetryMaxAttempts: 1,
		Snapshot: func(context.Context) (estate.Snapshot, error) {
			value := map[string]any{"labels": map[string]string{"tenant_id": "customer-1"}}
			return estate.Snapshot{Regions: value, Hosts: value, Databases: value, Rollouts: value, SLO: value, Reconcile: value}, nil
		},
	})
	if err != nil {
		return result, err
	}
	_, unsafeErr := unsafePublisher.Publish(ctx)
	result.UnboundedLabelRejected = errors.Is(unsafeErr, estatepublisher.ErrLabelPolicy) && handler.count() == writesBeforeUnsafe
	if publisher.LastError() != nil || !result.PersistentReadback || !result.SecretRejected || !result.UnboundedLabelRejected {
		return result, fmt.Errorf("vmqual: provider estate safety proof is incomplete: %+v lastError=%v", result, publisher.LastError())
	}
	return result, nil
}

func awaitProviderEstateEvent(ctx context.Context, events <-chan providerEstateEvent, timeout time.Duration) (providerEstateEvent, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event := <-events:
		return event, nil
	case <-ctx.Done():
		return providerEstateEvent{}, ctx.Err()
	case <-timer.C:
		return providerEstateEvent{}, errors.New("public estate event observation timed out")
	}
}

func readStrictProviderJSON(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > 16<<20 {
		return errors.New("state file is unavailable or unsafe")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return errors.New("state file is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("state file is malformed")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("state file has trailing data")
	}
	return nil
}

func writeProviderJSON(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("vmqual: encode provider state: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("vmqual: create provider state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("vmqual: create provider state staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	return errors.Join(err, closeErr)
}

var _ cf.KVRegionHealthSource = (*providerKVSource)(nil)
var _ cf.KVDBPlacementSource = (*providerKVSource)(nil)
var _ cf.KVWriterDeleteStore = (*providerKVStore)(nil)
var _ http.Handler = (*localControlPlaneEndpoint)(nil)
