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
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/control/placement"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/observability"
	"terrascale.tech/orchestrator/src/orchestrator/residency"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const (
	operationsControlRegion = "gru"
	operationsControlBucket = "control-snapshots"
	operationsBackupBucket  = "backups"
)

var operationsRegions = []string{"gru", "sfo", "fra"}

// LocalOperationsContract executes the stateful operations portions of the
// Firecracker journey through exported production contracts and the same
// disk-backed provider endpoints as LocalScenarioDriver. It returns measured
// results; callers decide how those results are represented as suite evidence.
type LocalOperationsContract struct {
	endpoints *LocalProviderEndpoints
	client    *http.Client
	now       func() time.Time
	objects   *localOperationsObjectStore
}

// NewLocalOperationsContract binds operational qualification to one complete
// local provider fixture. The fixture remains owned by LocalScenarioDriver.
func NewLocalOperationsContract(endpoints *LocalProviderEndpoints) (*LocalOperationsContract, error) {
	if endpoints == nil || endpoints.Cloudflare == nil || endpoints.CloudflareURL == "" || len(endpoints.Object) != len(operationsRegions) {
		return nil, errors.New("vmqual: operations contract requires complete local providers")
	}
	for _, region := range operationsRegions {
		code, err := operationsRegionCode(region)
		if err != nil || endpoints.Object[code] == nil || endpoints.ObjectURL[code] == "" {
			return nil, fmt.Errorf("vmqual: operations contract object store %s is missing", region)
		}
		if root := endpoints.Object[code].Root(); root == "" || !filepath.IsAbs(root) {
			return nil, fmt.Errorf("vmqual: operations contract object store %s is not persistent", region)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return &LocalOperationsContract{
		endpoints: endpoints,
		client:    client,
		now:       time.Now,
		objects:   &localOperationsObjectStore{endpoints: endpoints, client: client},
	}, nil
}

// KVOperationsResult is state-derived proof of GOAL criterion 9.
type KVOperationsResult struct {
	Interval              time.Duration `json:"interval"`
	InitialWrites         int           `json:"initialWrites"`
	RefreshWrites         int           `json:"refreshWrites"`
	TransitionWrites      int           `json:"transitionWrites"`
	TotalWrites           int           `json:"totalWrites"`
	BudgetObservations    []int         `json:"budgetObservations"`
	TransitionOrder       []string      `json:"transitionOrder"`
	PlacementRegions      []string      `json:"placementRegions"`
	PlacementGeneration   uint64        `json:"placementGeneration"`
	StaleHealthRemoved    bool          `json:"staleHealthRemoved"`
	StalePlacementRemoved bool          `json:"stalePlacementRemoved"`
}

type operationsKVSource struct {
	health    map[string]cf.RegionHealth
	placement map[string]cf.DBPlacement
}

func (s *operationsKVSource) ObserveRegionHealth(context.Context) (map[string]cf.RegionHealth, error) {
	result := make(map[string]cf.RegionHealth, len(s.health))
	for key, value := range s.health {
		value.Members = append([]string(nil), value.Members...)
		result[key] = value
	}
	return result, nil
}

func (s *operationsKVSource) ObserveDBPlacement(context.Context) (map[string]cf.DBPlacement, error) {
	result := make(map[string]cf.DBPlacement, len(s.placement))
	for key, value := range s.placement {
		value.Regions = append([]string(nil), value.Regions...)
		result[key] = value
	}
	return result, nil
}

type recordingKVStore struct {
	delegate *cf.Client
	events   []string
}

func (s *recordingKVStore) SetWorkerHealth(ctx context.Context, value cf.WorkerHealthDoc) error {
	if err := s.delegate.SetWorkerHealth(ctx, value); err != nil {
		return err
	}
	s.events = append(s.events, "set-health:"+"regions")
	return nil
}
func (s *recordingKVStore) SetWorkerPlacements(ctx context.Context, values map[string]cf.WorkerPlacement) error {
	if err := s.delegate.SetWorkerPlacements(ctx, values); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s.events = append(s.events, "set-placement:"+key)
	}
	return nil
}
func (s *recordingKVStore) DeleteWorkerPlacements(ctx context.Context, keys []string) error {
	if err := s.delegate.DeleteWorkerPlacements(ctx, keys); err != nil {
		return err
	}
	for _, key := range keys {
		s.events = append(s.events, "delete-placement:"+key)
	}
	return nil
}

// QualifyKV executes health refreshes, an unchanged tick, a safe placement
// narrowing, and stale-key removal against the local Cloudflare HTTP API.
func (c *LocalOperationsContract) QualifyKV(ctx context.Context) (KVOperationsResult, error) {
	var result KVOperationsResult
	if err := c.ready(ctx); err != nil {
		return result, err
	}
	client := cf.NewClient("vmqual-local", c.endpoints.ZoneID, c.endpoints.AccountID)
	client.BaseURL = c.endpoints.CloudflareURL
	client.HTTP = c.client.Transport
	if client.HTTP == nil {
		client.HTTP = http.DefaultTransport
	}
	if err := ensureKVNamespaces(ctx, client); err != nil {
		return result, err
	}
	source := &operationsKVSource{
		health: map[string]cf.RegionHealth{
			"fra": {Healthy: true, Members: []string{"10.77.2.10", "10.77.2.11"}},
			"gru": {Healthy: true, Members: []string{"10.77.0.10", "10.77.0.11"}},
			"sfo": {Healthy: true, Members: []string{"10.77.1.10", "10.77.1.11"}},
		},
		placement: map[string]cf.DBPlacement{
			"qualification-live":  {Regions: []string{"gru", "fra"}, PlacementLock: "explicit", Generation: 1},
			"qualification-stale": {Regions: []string{"sfo"}, PlacementLock: "explicit", Generation: 1},
		},
	}
	store := &recordingKVStore{delegate: client}
	var budget []int
	now := c.now().UTC()
	writer, err := cf.NewKVWriter(cf.KVWriterConfig{
		Store:            store,
		Health:           source,
		Placement:        source,
		MaxWritesPerTick: 2,
		OnBudgetExceeded: func(writes int) { budget = append(budget, writes) },
		Now:              func() time.Time { return now },
	})
	if err != nil {
		return result, err
	}
	result.Interval = writer.Interval()
	if cf.DefaultKVWriterHealthInterval != 10*time.Second || result.Interval != cf.DefaultKVWriterHealthInterval {
		return result, fmt.Errorf("vmqual: KV cadence is %s, want 10s", result.Interval)
	}
	if result.InitialWrites, err = writer.Step(ctx); err != nil {
		return result, err
	}
	if result.RefreshWrites, err = writer.Step(ctx); err != nil {
		return result, err
	}
	if result.InitialWrites != 3 || result.RefreshWrites != 1 {
		return result, fmt.Errorf("vmqual: KV refresh writes are initial=%d refresh=%d", result.InitialWrites, result.RefreshWrites)
	}
	store.events = nil
	delete(source.health, "sfo")
	delete(source.placement, "qualification-stale")
	source.placement["qualification-live"] = cf.DBPlacement{
		Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 2,
	}
	if result.TransitionWrites, err = writer.Step(ctx); err != nil {
		return result, err
	}
	result.TransitionOrder = append([]string(nil), store.events...)
	wantOrder := []string{
		"set-health:regions", "set-placement:qualification-live", "delete-placement:qualification-stale",
	}
	if !equalStrings(result.TransitionOrder, wantOrder) {
		return result, fmt.Errorf("vmqual: unsafe KV transition order %v", result.TransitionOrder)
	}
	placementValue, err := client.WorkerPlacement(ctx, "qualification-live")
	if err != nil {
		return result, err
	}
	if !equalStrings(placementValue.Res.Codes, []string{"GRU"}) || placementValue.G != 2 || !equalStrings(placementValue.R, []string{"GRU"}) {
		return result, fmt.Errorf("vmqual: KV placement readback is %+v", placementValue)
	}
	healthValue, err := client.WorkerHealth(ctx)
	if err != nil || !healthValue.Regions["GRU"].OK || healthValue.Updated != now.Unix() {
		return result, fmt.Errorf("vmqual: KV health readback is %+v: %w", healthValue, err)
	}
	_, staleHealth := healthValue.Regions["SFO"]
	_, placementErr := client.WorkerPlacement(ctx, "qualification-stale")
	result.StaleHealthRemoved = !staleHealth
	result.StalePlacementRemoved = errors.Is(placementErr, cf.ErrNotFound)
	if !result.StaleHealthRemoved || !result.StalePlacementRemoved {
		return result, errors.New("vmqual: stale KV keys remain visible")
	}
	result.TotalWrites = writer.WriteCount()
	result.BudgetObservations = append([]int(nil), budget...)
	result.PlacementRegions = append([]string(nil), placementValue.R...)
	result.PlacementGeneration = placementValue.G
	if result.TransitionWrites != 3 || result.TotalWrites != 7 || !equalInts(result.BudgetObservations, []int{3, 3}) {
		return result, fmt.Errorf("vmqual: KV budget accounting writes=%d alerts=%v", result.TotalWrites, result.BudgetObservations)
	}
	return result, nil
}

func ensureKVNamespaces(ctx context.Context, client *cf.Client) error {
	namespaces, err := client.ListKVNamespaces(ctx)
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(namespaces))
	for _, namespace := range namespaces {
		present[namespace.Title] = true
	}
	for _, title := range []string{cf.RegionHealthNamespace, cf.DBPlacementNamespace} {
		if !present[title] {
			if err := client.CreateKVNamespace(ctx, title); err != nil {
				return err
			}
		}
	}
	return nil
}

// EstateOperationsResult is state-derived proof of GOAL criterion 10.
type EstateOperationsResult struct {
	Interval               time.Duration `json:"interval"`
	InitialWrites          int           `json:"initialWrites"`
	UnchangedWrites        int           `json:"unchangedWrites"`
	OnChangeWrites         int           `json:"onChangeWrites"`
	Documents              []string      `json:"documents"`
	SecretRejected         bool          `json:"secretRejected"`
	UnboundedLabelRejected bool          `json:"unboundedLabelRejected"`
	PersistentReadback     bool          `json:"persistentReadback"`
}

type operationsEstateSource struct {
	snapshot estate.Snapshot
}

func (s *operationsEstateSource) observe(context.Context) (estate.Snapshot, error) {
	return s.snapshot, nil
}

type localEstateWriter struct {
	objects *localOperationsObjectStore
}

func (w *localEstateWriter) PutDocument(ctx context.Context, collection, docID string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return errors.New("vmqual: estate document is not JSON")
	}
	_, err = w.PutPublicDocument(ctx, collection, docID, raw, estate.DocumentWriteOptions{})
	return err
}

func (w *localEstateWriter) PutPublicDocument(ctx context.Context, collection, docID string, raw json.RawMessage, _ estate.DocumentWriteOptions) (estate.DocumentWriteReceipt, error) {
	if collection != estate.EstateCollection || !containsString(estate.EstateDocIDs(), docID) {
		return estate.DocumentWriteReceipt{}, errors.New("vmqual: estate document identity is invalid")
	}
	if err := validateOperationsEstatePayload(raw); err != nil {
		return estate.DocumentWriteReceipt{}, err
	}
	key := "control-plane/estate/" + docID + ".json"
	if err := w.objects.put(ctx, operationsControlRegion, operationsControlBucket, key, raw); err != nil {
		return estate.DocumentWriteReceipt{}, err
	}
	sum := sha256.Sum256(raw)
	revision := hex.EncodeToString(sum[:])
	return estate.DocumentWriteReceipt{Revision: revision, ETag: revision}, nil
}

// QualifyEstate executes initial, unchanged, and notified change publishes.
// Its persistent writer rejects secret-bearing payloads and labels outside the
// repository's closed observability vocabulary before any object mutation.
func (c *LocalOperationsContract) QualifyEstate(ctx context.Context) (EstateOperationsResult, error) {
	var result EstateOperationsResult
	if err := c.ready(ctx); err != nil {
		return result, err
	}
	if err := c.objects.ensureBucket(ctx, operationsControlRegion, operationsControlBucket); err != nil {
		return result, err
	}
	regions, err := estate.RegionsPayload(estate.Default())
	if err != nil {
		return result, err
	}
	source := &operationsEstateSource{snapshot: estate.Snapshot{
		Regions:   regions,
		Hosts:     map[string]any{"hosts": []any{map[string]any{"id": "gru-1", "healthy": true}}},
		Databases: map[string]any{"databases": []any{map[string]any{"id": "control", "regions": []string{"gru", "sfo", "fra"}}}},
		Rollouts:  map[string]any{"rollouts": []any{}},
		SLO:       map[string]any{"state": "healthy", "labels": map[string]string{"region": "gru", "subsystem": "orchestrator"}},
		Reconcile: map[string]any{"converged": true, "generation": 1},
	}}
	writer := &localEstateWriter{objects: c.objects}
	published := make(chan int, 8)
	publisher, err := estate.NewPublisher(estate.PublisherConfig{
		Writer: writer, Snapshot: source.observe, OnPublish: func(writes int) { published <- writes },
	})
	if err != nil {
		return result, err
	}
	result.Interval = publisher.Interval()
	if estate.DefaultPublisherInterval != 10*time.Second || result.Interval != estate.DefaultPublisherInterval {
		return result, fmt.Errorf("vmqual: estate cadence is %s, want 10s", result.Interval)
	}
	if result.InitialWrites, err = publisher.Publish(ctx); err != nil {
		return result, err
	}
	if observed, err := awaitOperationsPublish(ctx, published); err != nil || observed != result.InitialWrites {
		return result, fmt.Errorf("vmqual: estate initial publish observation: writes=%d: %w", observed, err)
	}
	if result.UnchangedWrites, err = publisher.Publish(ctx); err != nil {
		return result, err
	}
	if observed, err := awaitOperationsPublish(ctx, published); err != nil || observed != 0 {
		return result, fmt.Errorf("vmqual: estate unchanged publish observation: writes=%d: %w", observed, err)
	}
	if err := publisher.Start(ctx); err != nil {
		return result, err
	}
	defer publisher.Close()
	if observed, err := awaitOperationsPublish(ctx, published); err != nil || observed != 0 {
		return result, fmt.Errorf("vmqual: estate loop initial observation: writes=%d: %w", observed, err)
	}
	source.snapshot.Reconcile = map[string]any{"converged": true, "generation": 2}
	publisher.NotifyChange()
	if result.OnChangeWrites, err = awaitOperationsPublish(ctx, published); err != nil {
		return result, err
	}
	if result.InitialWrites != len(estate.EstateDocIDs()) || result.UnchangedWrites != 0 || result.OnChangeWrites != 1 {
		return result, fmt.Errorf("vmqual: estate change accounting is initial=%d unchanged=%d changed=%d", result.InitialWrites, result.UnchangedWrites, result.OnChangeWrites)
	}
	result.Documents = estate.EstateDocIDs()
	for _, docID := range result.Documents {
		raw, found, err := c.objects.get(ctx, operationsControlRegion, operationsControlBucket, "control-plane/estate/"+docID+".json")
		if err != nil || !found || !json.Valid(raw) {
			return result, fmt.Errorf("vmqual: estate document %s readback failed: %w", docID, err)
		}
	}
	result.PersistentReadback = true
	result.SecretRejected = rejectsEstateSnapshot(ctx, writer, estate.Snapshot{
		Regions: map[string]any{"api_key": "qualification-secret"},
	})
	result.UnboundedLabelRejected = rejectsEstateSnapshot(ctx, writer, estate.Snapshot{
		Regions: map[string]any{"labels": map[string]string{"tenant_id": "customer-1"}},
	})
	if !result.SecretRejected || !result.UnboundedLabelRejected {
		return result, errors.New("vmqual: unsafe estate payload was not rejected")
	}
	return result, nil
}

func rejectsEstateSnapshot(ctx context.Context, writer estate.DocumentWriter, snapshot estate.Snapshot) bool {
	publisher, err := estate.NewPublisher(estate.PublisherConfig{
		Writer: writer,
		Snapshot: func(context.Context) (estate.Snapshot, error) {
			return snapshot, nil
		},
		RetryMaxAttempts: 1,
	})
	if err != nil {
		return false
	}
	writes, err := publisher.Publish(ctx)
	return err != nil && writes == 0
}

func awaitOperationsPublish(ctx context.Context, values <-chan int) (int, error) {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case value := <-values:
		return value, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return 0, errors.New("vmqual: estate publish observation timed out")
	}
}

func validateOperationsEstatePayload(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || !json.Valid(raw) {
		return errors.New("vmqual: estate payload is invalid or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("vmqual: estate payload is invalid")
	}
	count := 0
	return validateOperationsEstateValue(value, 0, &count)
}

func validateOperationsEstateValue(value any, depth int, count *int) error {
	*count++
	if depth > 32 || *count > 4096 {
		return errors.New("vmqual: estate payload structure is unbounded")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
			switch normalized {
			case "token", "access_token", "password", "passwd", "secret", "api_key", "apikey", "authorization", "cookie", "credential", "credentials":
				return errors.New("vmqual: estate payload contains secret-bearing data")
			case "labels":
				labels, ok := child.(map[string]any)
				if !ok {
					return errors.New("vmqual: estate labels are malformed")
				}
				candidate := make(map[string]string, len(labels))
				for label, rawValue := range labels {
					text, ok := rawValue.(string)
					if !ok {
						return errors.New("vmqual: estate labels must be bounded strings")
					}
					candidate[label] = text
				}
				if err := observability.DefaultLabelAllowList.ValidateLabels(candidate); err != nil {
					return errors.New("vmqual: estate labels are outside the bounded vocabulary")
				}
			}
			if err := validateOperationsEstateValue(child, depth+1, count); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateOperationsEstateValue(child, depth+1, count); err != nil {
				return err
			}
		}
	case string:
		if len(typed) > 16<<10 {
			return errors.New("vmqual: estate string is unbounded")
		}
		if observability.RedactText(typed) != typed {
			return errors.New("vmqual: estate payload contains secret-bearing data")
		}
	}
	return nil
}

// RestoreOperationsResult is state-derived proof of GOAL criterion 14.
type RestoreOperationsResult struct {
	DailyInterval        time.Duration `json:"dailyInterval"`
	SchedulerCallbackRan bool          `json:"schedulerCallbackRan"`
	RunID                string        `json:"runID"`
	RestoredDatabases    []string      `json:"restoredDatabases"`
	ScratchBranchesClean bool          `json:"scratchBranchesClean"`
	SnapshotObject       string        `json:"snapshotObject"`
	SnapshotRegions      []string      `json:"snapshotRegions"`
	ArtifactObject       string        `json:"artifactObject"`
	ArtifactRegions      []string      `json:"artifactRegions"`
	PersistentReadback   bool          `json:"persistentReadback"`
}

// QualifyRestoreAndMirrors runs the exported daily Drill and ArtifactMirror
// contracts against the fixture's disk-backed regional object stores.
func (c *LocalOperationsContract) QualifyRestoreAndMirrors(ctx context.Context) (RestoreOperationsResult, error) {
	var result RestoreOperationsResult
	if err := c.ready(ctx); err != nil {
		return result, err
	}
	if err := c.ensureDeclaredBuckets(ctx); err != nil {
		return result, err
	}
	seed := map[string][]byte{
		"control":       []byte(`{"rows":[{"id":"estate.regions"},{"id":"estate.hosts"}]}`),
		"qualification": []byte(`{"rows":[{"id":"document-1"},{"id":"document-2"},{"id":"document-3"}]}`),
	}
	facts := make(map[string]restoredrill.JournalFacts, len(seed))
	for database, body := range seed {
		key := localRestoreSourceKey(database)
		if err := c.objects.put(ctx, operationsControlRegion, operationsBackupBucket, key, body); err != nil {
			return result, err
		}
		facts[database] = restoredrill.JournalFacts{
			JournalCut: "cut-" + database,
			Checksum:   delivery.SHA256Digest(body),
			RowCount:   restoreRowCount(body),
		}
	}
	journal, err := newLocalDrillJournal(ctx, c.objects)
	if err != nil {
		return result, err
	}
	if err := journal.setFacts(ctx, facts); err != nil {
		return result, err
	}
	branches := &localScratchBranches{objects: c.objects}
	backup := &localRestoreBackup{objects: c.objects, facts: facts}
	scheduler := &localDailyScheduler{at: c.now().UTC()}
	pager := &localRestorePager{}
	snapshotter, controlJetStream, err := newLocalControlJetStreamSnapshotter(ctx, c.objects, c.now)
	if err != nil {
		return result, err
	}
	defer controlJetStream.Close()
	snapshots := &localControlSnapshots{objects: c.objects}
	mirror, err := delivery.NewArtifactMirror(estate.Default(), c.objects)
	if err != nil {
		return result, err
	}
	composition, err := restoredrill.NewProductionComposition(restoredrill.ProductionConfig{
		Backup: backup, Branches: branches, Journal: journal, Scheduler: scheduler, Pager: pager,
		Drill: restoredrill.Config{
			ControlPlaneID: "control", SampleSize: 1, Seed: 71, Now: c.now, AcceptedControlEpoch: 3,
		},
		Snapshotter: snapshotter, SnapshotMirror: snapshots,
		SnapshotRegions: append([]string(nil), operationsRegions...), ArtifactMirror: mirror,
	})
	if err != nil {
		return result, err
	}
	if err := composition.Drill.Start(ctx); err != nil {
		return result, err
	}
	result.DailyInterval = scheduler.interval
	result.SchedulerCallbackRan = scheduler.callbackRan
	if result.DailyInterval != 24*time.Hour {
		return result, fmt.Errorf("vmqual: restore drill cadence is %s, want 24h", result.DailyInterval)
	}
	if !result.SchedulerCallbackRan {
		return result, errors.New("vmqual: daily restore scheduler did not invoke its callback")
	}
	run, found, err := journal.LoadRun(ctx, "restore-drill-"+c.now().UTC().Format("2006-01-02"))
	if err != nil || !found || run.Status != restoredrill.RunSucceeded {
		return result, fmt.Errorf("vmqual: restore drill status %s: %w", run.Status, err)
	}
	if pager.count() != 0 || len(run.DatabaseIDs) != 2 || run.DatabaseIDs[0] != "control" {
		return result, fmt.Errorf("vmqual: restore drill outcome is incomplete: databases=%v pages=%d", run.DatabaseIDs, pager.count())
	}
	result.RunID = run.ID
	result.RestoredDatabases = append([]string(nil), run.DatabaseIDs...)
	result.SnapshotObject = run.Snapshot.ObjectKey
	result.SnapshotRegions = append([]string(nil), run.SnapshotRegions...)
	sort.Strings(result.SnapshotRegions)
	wantRegions := append([]string(nil), operationsRegions...)
	sort.Strings(wantRegions)
	if !equalStrings(result.SnapshotRegions, wantRegions) || run.Snapshot.Checksum == "" || run.Snapshot.Size <= 0 {
		return result, fmt.Errorf("vmqual: control snapshot mirrors are incomplete: %+v", run.SnapshotRegions)
	}
	for _, region := range operationsRegions {
		identity, found, err := c.objects.head(ctx, region, operationsControlBucket, run.Snapshot.ObjectKey)
		if err != nil || !found || !delivery.SameDigest(identity.Digest, run.Snapshot.Checksum) || identity.Size != run.Snapshot.Size {
			return result, fmt.Errorf("vmqual: control snapshot readback failed in %s: %w", region, err)
		}
	}
	result.ScratchBranchesClean = true
	for _, item := range run.Items {
		if item.Status != restoredrill.ItemSucceeded || item.Expected.Checksum != item.Observed.Checksum || item.Expected.RowCount != item.Observed.RowCount {
			return result, fmt.Errorf("vmqual: restore item did not prove equality: %+v", item)
		}
		for _, object := range []string{localScratchDataKey(item.BranchID), localScratchMarkerKey(item.BranchID)} {
			_, found, err := c.objects.head(ctx, operationsControlRegion, operationsBackupBucket, object)
			if err != nil || found {
				result.ScratchBranchesClean = false
				return result, fmt.Errorf("vmqual: restore scratch object %s remains: %w", object, err)
			}
		}
	}
	reloaded, err := newLocalDrillJournal(ctx, c.objects)
	if err != nil {
		return result, err
	}
	persistedRun, found, err := reloaded.LoadRun(ctx, run.ID)
	if err != nil || !found || persistedRun.Status != restoredrill.RunSucceeded || persistedRun.Snapshot.Checksum != run.Snapshot.Checksum {
		return result, fmt.Errorf("vmqual: restore journal did not survive reload: %w", err)
	}
	artifactBody := []byte("vmqual-signed-release-artifact-linux-native")
	artifact := &delivery.ReleaseArtifact{
		Service: "terrabase", Digest: delivery.SHA256Digest(artifactBody), Architecture: "linux/amd64",
		Body: artifactBody, SignatureKey: "vmqual-release-key",
	}
	if err := composition.ArtifactMirror.MirrorAll(ctx, artifact); err != nil {
		return result, err
	}
	result.ArtifactObject = delivery.MirrorObject(artifact.Service, artifact.Digest)
	for _, region := range operationsRegions {
		identity, found, err := c.objects.head(ctx, region, "releases", result.ArtifactObject)
		if err != nil || !found || !delivery.SameDigest(identity.Digest, artifact.Digest) || identity.Size != int64(len(artifactBody)) {
			return result, fmt.Errorf("vmqual: release artifact readback failed in %s: %w", region, err)
		}
		result.ArtifactRegions = append(result.ArtifactRegions, region)
	}
	sort.Strings(result.ArtifactRegions)
	result.PersistentReadback = true
	return result, nil
}

type localDailyScheduler struct {
	interval    time.Duration
	callbackRan bool
	at          time.Time
}

func (s *localDailyScheduler) Every(ctx context.Context, interval time.Duration, callback func(context.Context, time.Time) error) error {
	if interval <= 0 || callback == nil {
		return restoredrill.ErrInvalidConfig
	}
	s.interval = interval
	s.callbackRan = true
	return callback(ctx, s.at)
}

type localRestorePager struct {
	mu    sync.Mutex
	pages []restoredrill.Page
}

func (p *localRestorePager) Page(_ context.Context, page restoredrill.Page) error {
	p.mu.Lock()
	p.pages = append(p.pages, page)
	p.mu.Unlock()
	return nil
}

func (p *localRestorePager) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pages)
}

type localRestoreBackup struct {
	objects *localOperationsObjectStore
	facts   map[string]restoredrill.JournalFacts
}

func (b *localRestoreBackup) ListDatabases(context.Context) ([]restoredrill.Database, error) {
	return []restoredrill.Database{{ID: "control", ControlPlane: true}, {ID: "qualification"}}, nil
}

func (b *localRestoreBackup) Restore(ctx context.Context, request restoredrill.RestoreRequest) error {
	facts, ok := b.facts[request.SourceDatabaseID]
	if !ok || request.JournalCut != facts.JournalCut || request.RestoreEpoch == 0 || request.IdempotencyKey == "" || request.BranchID == "" {
		return errors.New("vmqual: restore request is incomplete or does not name its journal cut")
	}
	body, found, err := b.objects.get(ctx, operationsControlRegion, operationsBackupBucket, localRestoreSourceKey(request.SourceDatabaseID))
	if err != nil || !found {
		return fmt.Errorf("vmqual: restore source is missing: %w", err)
	}
	if !delivery.SameDigest(delivery.SHA256Digest(body), facts.Checksum) {
		return restoredrill.ErrChecksumMismatch
	}
	return b.objects.put(ctx, operationsControlRegion, operationsBackupBucket, localScratchDataKey(request.BranchID), body)
}

type localScratchBranches struct {
	objects *localOperationsObjectStore
}

func (b *localScratchBranches) CreateScratch(ctx context.Context, request restoredrill.ScratchBranchRequest) (restoredrill.ScratchBranch, error) {
	if request.SourceDatabaseID == "" || request.IdempotencyKey == "" || request.RestoreEpoch == 0 {
		return restoredrill.ScratchBranch{}, errors.New("vmqual: scratch branch request is incomplete")
	}
	sum := sha256.Sum256([]byte(request.IdempotencyKey))
	branch := restoredrill.ScratchBranch{ID: "scratch-" + hex.EncodeToString(sum[:8])}
	body, _ := json.Marshal(request)
	if err := b.objects.put(ctx, operationsControlRegion, operationsBackupBucket, localScratchMarkerKey(branch.ID), body); err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	return branch, nil
}

func (b *localScratchBranches) Stats(ctx context.Context, branch restoredrill.ScratchBranch) (restoredrill.RestoreStats, error) {
	body, found, err := b.objects.get(ctx, operationsControlRegion, operationsBackupBucket, localScratchDataKey(branch.ID))
	if err != nil || !found {
		return restoredrill.RestoreStats{}, fmt.Errorf("vmqual: scratch branch data is missing: %w", err)
	}
	return restoredrill.RestoreStats{Checksum: delivery.SHA256Digest(body), RowCount: restoreRowCount(body)}, nil
}

func (b *localScratchBranches) Delete(ctx context.Context, branch restoredrill.ScratchBranch) error {
	return errors.Join(
		b.objects.delete(ctx, operationsControlRegion, operationsBackupBucket, localScratchDataKey(branch.ID)),
		b.objects.delete(ctx, operationsControlRegion, operationsBackupBucket, localScratchMarkerKey(branch.ID)),
	)
}

func localRestoreSourceKey(database string) string {
	return "vmqual/restore/source/" + database + ".json"
}
func localScratchDataKey(branch string) string {
	return "vmqual/restore/scratch/" + branch + "/data.json"
}
func localScratchMarkerKey(branch string) string {
	return "vmqual/restore/scratch/" + branch + "/branch.json"
}

func restoreRowCount(body []byte) int64 {
	var value struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if json.Unmarshal(body, &value) != nil {
		return -1
	}
	return int64(len(value.Rows))
}

const localDrillJournalKey = "vmqual/restore/journal.json"

type localDrillJournalState struct {
	Facts  map[string]restoredrill.JournalFacts `json:"facts"`
	Runs   map[string]restoredrill.RunRecord    `json:"runs"`
	Items  map[string]restoredrill.ItemRecord   `json:"items"`
	Epochs map[string]uint64                    `json:"epochs"`
	Claims map[string]uint64                    `json:"claims"`
}

type localDrillJournal struct {
	mu      sync.Mutex
	objects *localOperationsObjectStore
	state   localDrillJournalState
}

func newLocalDrillJournal(ctx context.Context, objects *localOperationsObjectStore) (*localDrillJournal, error) {
	journal := &localDrillJournal{objects: objects, state: localDrillJournalState{
		Facts: map[string]restoredrill.JournalFacts{}, Runs: map[string]restoredrill.RunRecord{},
		Items: map[string]restoredrill.ItemRecord{}, Epochs: map[string]uint64{}, Claims: map[string]uint64{},
	}}
	raw, found, err := objects.get(ctx, operationsControlRegion, operationsControlBucket, localDrillJournalKey)
	if err != nil {
		return nil, err
	}
	if found {
		if err := json.Unmarshal(raw, &journal.state); err != nil {
			return nil, errors.New("vmqual: persistent restore journal is malformed")
		}
		journal.initializeMaps()
	}
	return journal, nil
}

func (j *localDrillJournal) initializeMaps() {
	if j.state.Facts == nil {
		j.state.Facts = map[string]restoredrill.JournalFacts{}
	}
	if j.state.Runs == nil {
		j.state.Runs = map[string]restoredrill.RunRecord{}
	}
	if j.state.Items == nil {
		j.state.Items = map[string]restoredrill.ItemRecord{}
	}
	if j.state.Epochs == nil {
		j.state.Epochs = map[string]uint64{}
	}
	if j.state.Claims == nil {
		j.state.Claims = map[string]uint64{}
	}
}

func (j *localDrillJournal) persistLocked(ctx context.Context) error {
	body, err := json.Marshal(j.state)
	if err != nil {
		return err
	}
	return j.objects.put(ctx, operationsControlRegion, operationsControlBucket, localDrillJournalKey, body)
}

func (j *localDrillJournal) setFacts(ctx context.Context, facts map[string]restoredrill.JournalFacts) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for database, value := range facts {
		j.state.Facts[database] = value
	}
	return j.persistLocked(ctx)
}

func (j *localDrillJournal) Facts(_ context.Context, database, _ string) (restoredrill.JournalFacts, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	facts, ok := j.state.Facts[database]
	if !ok {
		return restoredrill.JournalFacts{}, errors.New("vmqual: restore journal facts are missing")
	}
	return facts, nil
}

func (j *localDrillJournal) LoadRun(_ context.Context, id string) (restoredrill.RunRecord, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	run, found := j.state.Runs[id]
	return copyOperationsRun(run), found, nil
}

func (j *localDrillJournal) ActiveRuns(_ context.Context) ([]restoredrill.RunRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	runs := make([]restoredrill.RunRecord, 0)
	for _, run := range j.state.Runs {
		if run.Status == restoredrill.RunRunning {
			runs = append(runs, copyOperationsRun(run))
		}
	}
	return runs, nil
}

func (j *localDrillJournal) SaveRun(ctx context.Context, run restoredrill.RunRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.state.Runs[run.ID] = copyOperationsRun(run)
	return j.persistLocked(ctx)
}

func (j *localDrillJournal) LoadItem(_ context.Context, key string) (restoredrill.ItemRecord, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	item, found := j.state.Items[key]
	return item, found, nil
}

func (j *localDrillJournal) SaveItem(ctx context.Context, item restoredrill.ItemRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if item.RestoreEpoch != 0 && j.state.Epochs[item.DatabaseID] != item.RestoreEpoch {
		return restoredrill.ErrRestoreEpochFenced
	}
	j.state.Items[item.Key] = item
	return j.persistLocked(ctx)
}

func (j *localDrillJournal) ClaimRestoreEpoch(ctx context.Context, database, key string) (uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if epoch := j.state.Claims[key]; epoch != 0 {
		return epoch, nil
	}
	j.state.Epochs[database]++
	j.state.Claims[key] = j.state.Epochs[database]
	if err := j.persistLocked(ctx); err != nil {
		return 0, err
	}
	return j.state.Claims[key], nil
}

func (j *localDrillJournal) RestoreEpochCurrent(_ context.Context, database string, epoch uint64) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return epoch != 0 && j.state.Epochs[database] == epoch, nil
}

func copyOperationsRun(run restoredrill.RunRecord) restoredrill.RunRecord {
	run.DatabaseIDs = append([]string(nil), run.DatabaseIDs...)
	run.Items = append([]restoredrill.ItemRecord(nil), run.Items...)
	run.SnapshotRegions = append([]string(nil), run.SnapshotRegions...)
	return run
}

type localControlSnapshots struct {
	objects *localOperationsObjectStore
}

func (s *localControlSnapshots) Mirror(ctx context.Context, snapshot restoredrill.ControlStateSnapshot, region string) error {
	body, found, err := s.objects.get(ctx, operationsControlRegion, operationsControlBucket, snapshot.ObjectKey)
	if err != nil || !found {
		return fmt.Errorf("vmqual: source control snapshot is missing: %w", err)
	}
	if int64(len(body)) != snapshot.Size || !delivery.SameDigest(delivery.SHA256Digest(body), snapshot.Checksum) {
		return errors.New("vmqual: source control snapshot identity changed")
	}
	return s.objects.put(ctx, region, operationsControlBucket, snapshot.ObjectKey, body)
}

// PlacementOperationsResult is state-derived proof of GOAL criterion 15.
type PlacementOperationsResult struct {
	Kind             string                    `json:"kind"`
	Regions          []string                  `json:"regions"`
	Generation       uint64                    `json:"generation"`
	Bootstrap        residency.MutationReceipt `json:"bootstrap"`
	Repair           residency.MutationReceipt `json:"repair"`
	Backup           residency.MutationReceipt `json:"backup"`
	Restore          residency.MutationReceipt `json:"restore"`
	Export           residency.MutationReceipt `json:"export"`
	Branch           residency.MutationReceipt `json:"branch"`
	RegionChange     residency.MutationReceipt `json:"regionChange"`
	WideningRejected bool                      `json:"wideningRejected"`
	Persistent       bool                      `json:"persistent"`
}

type persistedPlacementLock struct {
	Kind       string   `json:"kind"`
	Regions    []string `json:"regions"`
	Generation uint64   `json:"generation"`
}

// QualifyPlacementLocks runs every typed byte-at-rest mutation through the
// production residency coordinator.
func (c *LocalOperationsContract) QualifyPlacementLocks(ctx context.Context) (PlacementOperationsResult, error) {
	return c.qualifyPlacementMutations(ctx)
}

func operationsPlacementCatalog() *placement.RegionCatalog {
	return placement.NewRegionCatalog([]*placement.RegionCatalogEntry{
		{Region: placement.RegionCodeGru, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "br", MemberHosts: 2},
		{Region: placement.RegionCodeSfo, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "us", MemberHosts: 2},
		{Region: placement.RegionCodeFra, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "eu", MemberHosts: 2},
	})
}

func operationsPlacementRequest(lock *placement.PlacementLock) *placement.DatabasePlacementRequest {
	partitionID := placement.PartitionId{Value: "qualification-partition"}
	seats := []*placement.ActiveMemberSeat{
		{Member: placement.MemberId{Value: "gru-member-1"}, Region: placement.RegionCodeGru, Partition: partitionID, FailureDomain: placement.FailureDomainId{Value: "AD-1"}, IsActive: true},
		{Member: placement.MemberId{Value: "gru-member-2"}, Region: placement.RegionCodeGru, Partition: partitionID, FailureDomain: placement.FailureDomainId{Value: "AD-2"}, IsActive: true},
	}
	regional := placement.NewPartitionRegionPlacement(placement.RegionCodeGru, seats)
	logical := placement.NewLogicalPartitionPlacement(partitionID, []*placement.PartitionRegionPlacement{&regional})
	backup := &placement.BackupPlacement{
		Backup: placement.BackupId{Value: "qualification-backup"}, Region: placement.RegionCodeFra,
		IsReadOnly: true, IsImmutable: true, PromotionPolicy: placement.BackupPromotionPolicyNeverPromote,
	}
	return placement.NewDatabasePlacementRequest(
		[]placement.RegionCode{placement.RegionCodeGru}, []*placement.LogicalPartitionPlacement{&logical}, backup, lock,
	)
}

func encodePlacementLock(lock *placement.PlacementLock) ([]byte, error) {
	value := persistedPlacementLock{Kind: string(lock.Kind), Generation: lock.Generation}
	if value.Generation == 0 {
		value.Generation = lock.PlacementGeneration
	}
	for _, region := range lock.Regions {
		value.Regions = append(value.Regions, region.Value())
	}
	sort.Strings(value.Regions)
	return json.Marshal(value)
}

func decodePlacementLock(raw []byte) (*placement.PlacementLock, error) {
	var value persistedPlacementLock
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("vmqual: persisted placement lock is malformed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("vmqual: persisted placement lock has trailing data")
	}
	regions := make([]placement.RegionCode, 0, len(value.Regions))
	for _, rawRegion := range value.Regions {
		region, err := placement.RegionCodeFromValue(rawRegion)
		if err != nil {
			return nil, err
		}
		regions = append(regions, region)
	}
	return placement.NewPlacementLock(placement.PlacementLockKind(value.Kind), regions, value.Generation)
}

func samePlacementLock(left, right *placement.PlacementLock) bool {
	if left == nil || right == nil || left.Kind != right.Kind || left.Generation != right.Generation || len(left.Regions) != len(right.Regions) {
		return false
	}
	want, got := make([]string, 0, len(left.Regions)), make([]string, 0, len(right.Regions))
	for _, region := range left.Regions {
		want = append(want, region.Value())
	}
	for _, region := range right.Regions {
		got = append(got, region.Value())
	}
	sort.Strings(want)
	sort.Strings(got)
	return equalStrings(want, got)
}

func placementLockContains(lock *placement.PlacementLock, region string) bool {
	for _, allowed := range lock.Regions {
		if allowed.Value() == region {
			return true
		}
	}
	return false
}

func (c *LocalOperationsContract) ready(ctx context.Context) error {
	if c == nil || c.endpoints == nil || c.objects == nil {
		return errors.New("vmqual: local operations contract is unavailable")
	}
	if ctx == nil {
		return errors.New("vmqual: local operations context is required")
	}
	return ctx.Err()
}

func (c *LocalOperationsContract) ensureDeclaredBuckets(ctx context.Context) error {
	for _, region := range operationsRegions {
		for _, bucket := range []string{operationsBackupBucket, operationsControlBucket, "releases"} {
			if err := c.objects.ensureBucket(ctx, region, bucket); err != nil {
				return err
			}
		}
	}
	return nil
}

type localOperationsObjectStore struct {
	endpoints *LocalProviderEndpoints
	client    *http.Client
}

func (s *localOperationsObjectStore) GetSnapshot(ctx context.Context, region, bucket, object string) ([]byte, bool, error) {
	return s.get(ctx, region, bucket, object)
}

func (s *localOperationsObjectStore) Put(ctx context.Context, region, bucket, object string, body []byte) error {
	return s.put(ctx, region, bucket, object, body)
}

func (s *localOperationsObjectStore) put(ctx context.Context, region, bucket, object string, body []byte) error {
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	request.Header.Set("opc-meta-terrascale-sha256", hex.EncodeToString(sum[:]))
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return localObjectStatusError("put", region, bucket, object, response)
	}
	return nil
}

func (s *localOperationsObjectStore) Head(ctx context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	return s.head(ctx, region, bucket, object)
}

func (s *localOperationsObjectStore) head(ctx context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return delivery.ObjectIdentity{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return delivery.ObjectIdentity{}, false, localObjectStatusError("head", region, bucket, object, response)
	}
	size, err := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 {
		return delivery.ObjectIdentity{}, false, errors.New("vmqual: object store returned invalid size")
	}
	digest := strings.TrimSpace(response.Header.Get("opc-meta-terrascale-sha256"))
	if len(digest) != sha256.Size*2 {
		return delivery.ObjectIdentity{}, false, errors.New("vmqual: object store returned invalid digest")
	}
	return delivery.ObjectIdentity{
		Digest: "sha256:" + digest, Size: size, ETag: response.Header.Get("ETag"),
		Version: response.Header.Get("opc-version-id"),
	}, true, nil
}

func (s *localOperationsObjectStore) get(ctx context.Context, region, bucket, object string) ([]byte, bool, error) {
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return nil, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, localObjectStatusError("get", region, bucket, object, response)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20+1))
	if err != nil || len(body) > 16<<20 {
		return nil, false, errors.New("vmqual: object read is invalid or unbounded")
	}
	sum := sha256.Sum256(body)
	if !strings.EqualFold(response.Header.Get("opc-meta-terrascale-sha256"), hex.EncodeToString(sum[:])) {
		return nil, false, errors.New("vmqual: object read digest mismatch")
	}
	return body, true, nil
}

func (s *localOperationsObjectStore) delete(ctx context.Context, region, bucket, object string) error {
	identity, found, err := s.head(ctx, region, bucket, object)
	if err != nil || !found {
		return err
	}
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("If-Match", identity.ETag)
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return localObjectStatusError("delete", region, bucket, object, response)
	}
	return nil
}

func (s *localOperationsObjectStore) ensureBucket(ctx context.Context, region, bucket string) error {
	code, err := operationsRegionCode(region)
	if err != nil {
		return err
	}
	store := s.endpoints.Object[code]
	target := s.endpoints.ObjectURL[code] + "/n/" + url.PathEscape(store.Namespace()) + "/b/"
	body, _ := json.Marshal(map[string]string{"name": bucket, "versioning": "Enabled"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusConflict {
		return fmt.Errorf("vmqual: create object bucket %s/%s returned %s", region, bucket, response.Status)
	}
	verify, err := http.NewRequestWithContext(ctx, http.MethodGet, target+url.PathEscape(bucket), nil)
	if err != nil {
		return err
	}
	verified, err := s.client.Do(verify)
	if err != nil {
		return err
	}
	defer verified.Body.Close()
	if verified.StatusCode != http.StatusOK {
		return fmt.Errorf("vmqual: object bucket %s/%s is not readable", region, bucket)
	}
	return nil
}

func (s *localOperationsObjectStore) objectURL(region, bucket, object string) (string, error) {
	code, err := operationsRegionCode(region)
	if err != nil {
		return "", err
	}
	if bucket == "" || object == "" || strings.ContainsAny(bucket+object, "\x00\r\n") {
		return "", errors.New("vmqual: object identity is invalid")
	}
	store := s.endpoints.Object[code]
	if store == nil || s.endpoints.ObjectURL[code] == "" {
		return "", fmt.Errorf("vmqual: object store %s is missing", region)
	}
	return s.endpoints.ObjectURL[code] + "/n/" + url.PathEscape(store.Namespace()) + "/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(object), nil
}

func localObjectStatusError(operation, region, bucket, object string, response *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return fmt.Errorf("vmqual: object %s %s/%s/%s returned %s", operation, region, bucket, object, response.Status)
}

func operationsRegionCode(region string) (vmnet.RegionCode, error) {
	switch strings.ToUpper(strings.TrimSpace(region)) {
	case string(vmnet.GRU):
		return vmnet.GRU, nil
	case string(vmnet.SFO):
		return vmnet.SFO, nil
	case string(vmnet.FRA):
		return vmnet.FRA, nil
	default:
		return "", fmt.Errorf("vmqual: unsupported operations Region %q", region)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
