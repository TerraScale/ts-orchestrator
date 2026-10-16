package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type fixedSnapshots struct {
	snapshot observability.MemberSnapshot
	err      error
}

func (source fixedSnapshots) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.snapshot, source.err
}

type fixedCluster struct {
	snapshot observability.ClusterSnapshot
	err      error
	calls    *int
}

func (source fixedCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	if source.calls != nil {
		*source.calls++
	}
	return source.snapshot, source.err
}

func memberSnapshot() observability.MemberSnapshot {
	return observability.MemberSnapshot{Version: observability.SnapshotVersion, Cell: "fra", Member: "ctl-1",
		Role: "controller", BuildVersion: "abc123def456", StartedAt: testNow.Add(-3 * time.Hour),
		ObservedAt: testNow, Ready: true,
		Authority: &observability.AuthorityView{Leader: true, Ready: true, CanMutate: true, OwnerID: "00000000009DQWP5T1WY4KP1TS",
			Epoch: 7, Revision: 42},
		NATS: &observability.NATSView{ServerName: "ctl-1", Connections: 5, Routes: 2, ClusterPeers: 3,
			MetaLeader: "ctl-1", IsMetaLeader: true, MetaClusterSize: 3, StoreUsedBytes: 512 << 20,
			StoreLimitBytes: 1 << 30,
			MetaPeers: []observability.PeerView{{Name: "ctl-2", Current: true}, {Name: "ctl-3", Offline: true,
				Lag: 9}},
			Streams:   []observability.StreamView{{Name: "TS_DELIVERY", Messages: 12, Bytes: 4096, Replicas: 3, Leader: "ctl-1"}},
			Consumers: []observability.ConsumerView{{Stream: "TS_DELIVERY", Name: "placement", NumPending: 4}}},
		Placement: &observability.PlacementView{StageCounts: map[string]int{"serving": 2, "joining": 1},
			Databases: []observability.DatabaseView{{DatabaseID: "00000000000DMQEY0YD7RZ04RR", PartitionID: "00000000003K6TBW31R91GBDRD", Generation: 3,
				DesiredSeats: 3, Serving: 2, Stages: map[string]int{"serving": 2, "joining": 1},
				Members: []observability.MemberView{
					{SeatID: "0000000000DNKA8DBDEPN1J9XM", Stage: "serving", HostNode: "host-a", FailureDomain: "FD-1"},
					{SeatID: "0000000000K6ST06WNWDFCTSJY", Stage: "serving", HostNode: "host-b", FailureDomain: "FD-2"},
					{SeatID: "000000000036XR713YE93E9M0S", Stage: "joining", HostNode: "host-a", FailureDomain: "FD-1"}},
				Rollout: &observability.RolloutView{OperationID: "0000000000HAAS49GS9KYXGSQT", ArtifactDigest: "sha256:feedface",
					Seats: 3, Completed: 1, Phases: map[string]int{"done": 1, "pending": 2}}}}},
		Delivery: &observability.DeliveryView{Acknowledged: 10, Deferred: 1, TransportRetries: 2},
		OCI: &observability.OCIView{Operations: []observability.OCIOperationView{{Service: "compute",
			Operation: "GET /instances/{id}", Calls: 4, Errors: 1, Throttled: 1, TotalSeconds: 2, MaxSeconds: 1,
			LastStatus: 200, LastErrorCode: 429}}},
		System: &observability.SystemView{CPUCount: 4, Load1: 0.5, MemTotalBytes: 8 << 30, MemAvailBytes: 2 << 30,
			Pressure: map[string]observability.PSI{"memory": {SomeAvg10: 1.25}},
			Filesystems: []observability.FilesystemView{{Role: "nats", Path: "/var/lib/ts/nats",
				SizeBytes: 100 << 30, AvailBytes: 5 << 30, Files: 1000, FilesFree: 900}}},
		Errors: map[string]string{"placement": "timeout"},
	}
}

func readyHealth(ok bool) *observability.Health {
	health := new(observability.Health)
	health.Add(observability.Check{Name: "nats", Run: func(context.Context) (bool, string) {
		if ok {
			return true, ""
		}
		return false, "regional broker is not connected"
	}})
	return health
}

func newTestDashboard(options Options) *Dashboard {
	options.Now = func() time.Time { return testNow }
	if options.Interval == 0 {
		options.Interval = 20 * time.Millisecond
	}
	return New(options)
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestEveryPageRendersProviderData(t *testing.T) {
	t.Parallel()
	bus := observability.NewEventBus(16)
	bus.Publish(observability.Event{Level: "WARN", Component: "placement", Message: "placement held",
		Attrs: map[string]string{"reason": "capacity"}})
	snapshot := memberSnapshot()
	other := memberSnapshot()
	other.Member, other.Authority.Leader, other.NATS.IsMetaLeader = "ctl-2", false, false
	dashboard := newTestDashboard(Options{Health: readyHealth(true), Events: bus,
		Snapshots: fixedSnapshots{snapshot: snapshot},
		Cluster: fixedCluster{snapshot: observability.ClusterSnapshot{Cell: "fra",
			Members: []observability.MemberSnapshot{snapshot, other}, Missing: []string{"ctl-3"}}}})
	handler := dashboard.Handler()
	for path, wants := range map[string][]string{
		"/region":    {"Region FRA", "ctl-1", "epoch 7", "placement held", "1 missing", "ctl-1: placement timeout"},
		"/":          {"All regions", "appears once this controller"},
		"/members":   {"ctl-2", "ctl-3", "did not answer", "host-a", "FD-1", "leader", "75.0%"},
		"/nats":      {"TS_DELIVERY", "placement", "this server", "ctl-3", "512.0 MiB / 1.0 GiB"},
		"/oci":       {"GET /instances/{id}", "429", "500ms", "OCI inventory provider is attached"},
		"/storage":   {"No filesystem was reported", "50.0%"},
		"/terrabase": {"00000000000DMQEY0YD7RZ04RR", "00000000003K6TBW31R91GBDRD", "joining 1, serving 2", "000000000036XR713YE93E9M0S: joining on host-a"},
		"/rollouts":  {"0000000000HAAS49GS9KYXGSQT", "sha256:feedface", "1 / 3", "done 1, pending 2", "33.3%"},
		"/events":    {"placement held", "reason=capacity", `<option value="placement"`},
	} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.Code)
		}
		body := response.Body.String()
		if !strings.Contains(body, `id="content"`) || !strings.Contains(body, `data-init="@get(&#39;`) {
			t.Errorf("GET %s lacks the streamed content root", path)
		}
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
		if csp := response.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("GET %s CSP = %q", path, csp)
		}
		if response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s lacks hardening headers", path)
		}
	}
}

func TestPagesRenderWithoutProviders(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{}).Handler()
	for _, page := range pages {
		response := get(t, handler, page.href())
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", page.href(), response.Code)
		}
		if body := response.Body.String(); !strings.Contains(body, "still starting") {
			t.Errorf("GET %s does not explain the missing providers", page.href())
		}
	}
}

func TestPagesExplainFailingProviders(t *testing.T) {
	t.Parallel()
	dashboard := newTestDashboard(Options{Health: readyHealth(false),
		Snapshots: fixedSnapshots{err: errors.New("boom")},
		Cluster:   fixedCluster{err: errors.New("no responders")}})
	body := get(t, dashboard.Handler(), "/").Body.String()
	for _, want := range []string{"snapshot is unavailable", "cell-wide view is unavailable",
		"nats: regional broker is not connected", "not ready"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(body, "boom") || strings.Contains(body, "no responders") {
		t.Error("overview leaked raw provider error text")
	}
}

func TestLateAttachedProvidersAndSharedClusterCache(t *testing.T) {
	t.Parallel()
	dashboard := newTestDashboard(Options{})
	handler := dashboard.Handler()
	if body := get(t, handler, "/members").Body.String(); strings.Contains(body, "ctl-1") {
		t.Fatal("member listed before its provider was attached")
	}
	calls := 0
	dashboard.SetSnapshots(fixedSnapshots{snapshot: memberSnapshot()})
	dashboard.SetCluster(fixedCluster{snapshot: observability.ClusterSnapshot{Cell: "fra",
		Members: []observability.MemberSnapshot{memberSnapshot()}}, calls: &calls})
	for range 3 {
		if body := get(t, handler, "/members").Body.String(); !strings.Contains(body, "ctl-1") {
			t.Fatal("member missing after attaching providers")
		}
	}
	if calls != 1 {
		t.Fatalf("cluster provider called %d times, want one shared call per cache period", calls)
	}
}

func TestEventFilterFromQuery(t *testing.T) {
	t.Parallel()
	bus := observability.NewEventBus(16)
	bus.Publish(observability.Event{Level: "INFO", Component: "controller", Message: "controller ready"})
	bus.Publish(observability.Event{Level: "WARN", Component: "placement", Message: "placement held"})
	bus.Publish(observability.Event{Level: "ERROR", Component: "delivery", Message: "delivery failed"})
	handler := newTestDashboard(Options{Events: bus}).Handler()
	body := get(t, handler, "/events?level=warn").Body.String()
	if strings.Contains(body, "controller ready") || !strings.Contains(body, "placement held") ||
		!strings.Contains(body, "delivery failed") || !strings.Contains(body, "/events/stream?level=warn") {
		t.Fatalf("level filter not applied")
	}
	body = get(t, handler, "/events?component=delivery").Body.String()
	if strings.Contains(body, "placement held") || !strings.Contains(body, "delivery failed") {
		t.Fatalf("component filter not applied")
	}
	body = get(t, handler, "/events?component=%3Cscript%3E&level=trace").Body.String()
	if !strings.Contains(body, "controller ready") || strings.Contains(body, "<script>") {
		t.Fatalf("invalid filter was not ignored")
	}
}

func TestLoginPageKeepsRedirectLocal(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{}).Handler()
	body := get(t, handler, "/login?failed=1&next=https://evil.example/").Body.String()
	if !strings.Contains(body, "not accepted") || !strings.Contains(body, `name="next" value="/"`) {
		t.Fatalf("login page = %q", body)
	}
	body = get(t, handler, "/login?next=/nats").Body.String()
	if !strings.Contains(body, `name="next" value="/nats"`) || strings.Contains(body, "not accepted") {
		t.Fatalf("login page = %q", body)
	}
}

func TestAssetsAreContentAddressed(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{}).Handler()
	for _, name := range []string{"pico.min.css", "dashboard.css", "datastar.js"} {
		url := assetURL(name)
		response := get(t, handler, url)
		if response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("GET %s = %d", url, response.Code)
		}
		if !strings.Contains(response.Header().Get("Cache-Control"), "immutable") ||
			response.Header().Get("ETag") == "" {
			t.Errorf("GET %s headers = %v", url, response.Header())
		}
		wantType := "text/css"
		if strings.HasSuffix(name, ".js") {
			wantType = "text/javascript"
		}
		if !strings.HasPrefix(response.Header().Get("Content-Type"), wantType) {
			t.Errorf("GET %s Content-Type = %q", url, response.Header().Get("Content-Type"))
		}
		request := httptest.NewRequest(http.MethodGet, url, nil)
		request.Header.Set("If-None-Match", response.Header().Get("ETag"))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
			t.Errorf("conditional GET %s = %d", url, recorder.Code)
		}
	}
	if response := get(t, handler, "/assets/000000000000/datastar.js"); response.Code != http.StatusNotFound {
		t.Fatalf("stale asset hash = %d", response.Code)
	}
	if response := get(t, handler, "/assets/x/missing.js"); response.Code != http.StatusNotFound {
		t.Fatalf("unknown asset = %d", response.Code)
	}
}

func TestLiteralHostGuard(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{RequireLiteralHost: true}).Handler()
	for host, want := range map[string]int{
		"127.0.0.1:9464": http.StatusOK, "[::1]:9464": http.StatusOK, "localhost:9464": http.StatusOK,
		"10.0.0.4:9464": http.StatusOK, "rebound.example:9464": http.StatusMisdirectedRequest,
		"rebound.example": http.StatusMisdirectedRequest,
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Host = host
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Errorf("Host %q = %d, want %d", host, recorder.Code, want)
		}
	}
}

// newStreamServer serves the dashboard until the test ends. Its cleanup is
// registered before any stream's, so streams are cancelled before Close
// waits for their handlers.
func newStreamServer(t *testing.T, dashboard *Dashboard) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(dashboard.Handler())
	t.Cleanup(server.Close)
	return server
}

// sseReader reads Datastar events from a live stream.
type sseReader struct {
	t       *testing.T
	scanner *bufio.Scanner
}

func openStream(t *testing.T, server *httptest.Server, path string) (*sseReader, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Datastar-Request", "true")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return &sseReader{t: t, scanner: bufio.NewScanner(response.Body)}, response
}

// next returns the type and joined data lines of the next event.
func (reader *sseReader) next() (string, string) {
	reader.t.Helper()
	var eventType string
	var data []string
	for reader.scanner.Scan() {
		line := reader.scanner.Text()
		switch {
		case line == "" && eventType != "":
			return eventType, strings.Join(data, "\n")
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		}
	}
	reader.t.Fatalf("stream ended: %v", reader.scanner.Err())
	return "", ""
}

func TestContentStreamPatchesOnlyChanges(t *testing.T) {
	t.Parallel()
	source := &switchingSnapshots{}
	source.set(memberSnapshot())
	// Every page's stream stays open below, plus members: the listener's cap must cover them all.
	dashboard := newTestDashboard(Options{Snapshots: source, MaxStreams: len(pages) + 1})
	server := newStreamServer(t, dashboard)
	for _, page := range pages {
		if page.slug == "events" {
			continue
		}
		reader, response := openStream(t, server, page.streamPath())
		if response.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatalf("%s Content-Type = %q", page.streamPath(), response.Header.Get("Content-Type"))
		}
		eventType, data := reader.next()
		if eventType != "datastar-patch-elements" || !strings.Contains(data, `elements <div id="content">`) {
			t.Fatalf("%s first event = %s %q", page.streamPath(), eventType, data)
		}
	}
	reader, _ := openStream(t, server, "/members/stream")
	if _, data := reader.next(); !strings.Contains(data, "ctl-1") {
		t.Fatalf("initial members patch = %q", data)
	}
	// Several ticks pass with identical content and send nothing; a change
	// is patched on the next tick.
	time.Sleep(5 * dashboard.options.Interval)
	changed := memberSnapshot()
	changed.Member = "ctl-renamed"
	source.set(changed)
	if _, data := reader.next(); !strings.Contains(data, "ctl-renamed") {
		t.Fatalf("changed members patch = %q", data)
	}
}

type switchingSnapshots struct {
	mu      sync.Mutex
	current observability.MemberSnapshot
}

func (source *switchingSnapshots) set(snapshot observability.MemberSnapshot) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.current = snapshot
}

func (source *switchingSnapshots) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.current, nil
}

func TestEventsStreamPrependsLiveEvents(t *testing.T) {
	t.Parallel()
	bus := observability.NewEventBus(16)
	dashboard := newTestDashboard(Options{Events: bus})
	server := newStreamServer(t, dashboard)
	reader, _ := openStream(t, server, "/events/stream?level=warn")
	eventType, data := reader.next()
	if eventType != "datastar-patch-elements" || !strings.Contains(data, `<tbody id="events-rows">`) ||
		!strings.Contains(data, "events-rows-empty") {
		t.Fatalf("initial events patch = %s %q", eventType, data)
	}
	// The events stream keeps the top bar current like every page stream.
	if _, data = reader.next(); !strings.Contains(data, "region-switcher") || !strings.Contains(data, "attention-badge") {
		t.Fatalf("chrome patch = %q", data)
	}
	bus.Publish(observability.Event{Level: "INFO", Message: "filtered out"})
	bus.Publish(observability.Event{Level: "WARN", Component: "placement", Message: "placement held"})
	_, data = reader.next()
	if !strings.Contains(data, "selector #events-rows") || !strings.Contains(data, "mode prepend") ||
		!strings.Contains(data, "placement held") || strings.Contains(data, "filtered out") {
		t.Fatalf("live event patch = %q", data)
	}
	_, data = reader.next()
	if !strings.Contains(data, "selector #events-rows-empty") || !strings.Contains(data, "mode remove") {
		t.Fatalf("empty placeholder removal = %q", data)
	}
	bus.Publish(observability.Event{Level: "ERROR", Message: "second"})
	if _, data = reader.next(); !strings.Contains(data, "second") {
		t.Fatalf("second live event patch = %q", data)
	}
}

func TestStreamsAreCapped(t *testing.T) {
	t.Parallel()
	dashboard := newTestDashboard(Options{MaxStreams: 1, Interval: time.Hour})
	server := newStreamServer(t, dashboard)
	reader, _ := openStream(t, server, "/global/stream")
	reader.next()
	response, err := server.Client().Get(server.URL + "/nats/stream")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "" {
		t.Fatalf("second stream = %d", response.StatusCode)
	}
}

func TestEventFilterMatches(t *testing.T) {
	t.Parallel()
	filter := eventFilter{Level: "warn", Component: "placement"}
	for _, test := range []struct {
		level, component string
		want             bool
	}{
		{"WARN", "placement", true},
		{"ERROR", "placement", true},
		{"WARN+2", "placement", true},
		{"INFO", "placement", false},
		{"ERROR", "delivery", false},
	} {
		event := observability.Event{Level: test.level, Component: test.component}
		if got := filter.matches(event); got != test.want {
			t.Errorf("matches(%+v) = %v", event, got)
		}
	}
}

// lossyEvents keeps events in its ring but never delivers them live, as a
// bus whose full subscription dropped them.
type lossyEvents struct {
	mu     sync.Mutex
	events []observability.Event
}

func (source *lossyEvents) add(event observability.Event) {
	source.mu.Lock()
	defer source.mu.Unlock()
	event.Sequence = uint64(len(source.events) + 1)
	source.events = append([]observability.Event{event}, source.events...)
}

func (source *lossyEvents) Recent(int) []observability.Event {
	source.mu.Lock()
	defer source.mu.Unlock()
	return slices.Clone(source.events)
}

func (source *lossyEvents) Since(uint64, int) []observability.Event { return nil }

func (source *lossyEvents) Subscribe(ctx context.Context, _ int) <-chan observability.Event {
	channel := make(chan observability.Event)
	context.AfterFunc(ctx, func() { close(channel) })
	return channel
}

// A matching event the bus dropped from the stream's subscription is still
// listed: every tick reconciles the rows with the event ring.
func TestEventsStreamRecoversDroppedEvents(t *testing.T) {
	t.Parallel()
	source := &lossyEvents{}
	dashboard := newTestDashboard(Options{Events: source})
	server := newStreamServer(t, dashboard)
	reader, _ := openStream(t, server, "/events/stream?level=warn")
	reader.next()
	source.add(observability.Event{Level: "WARN", Component: "placement", Message: "dropped warning"})
	for range 20 {
		if _, data := reader.next(); strings.Contains(data, "dropped warning") {
			return
		}
	}
	t.Fatal("a dropped matching event never appeared")
}

// A toast opens its insight under the insight's own region on the
// all-regions list, like an insight card does.
func TestToastLinksTheRegionScopedInsight(t *testing.T) {
	t.Parallel()
	insight := testInsight("oci:x", "OCI errors", insights.SeverityWarning, "sfo")
	var body bytes.Buffer
	if err := insightToast(parseState(url.Values{"r": {"fra"}}), insights.Change{Type: insights.ChangeOpened,
		Insight: insight}).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), "id="+insight.Key) || !strings.Contains(body.String(), "region=all") ||
		!strings.Contains(body.String(), "#insight-"+insight.Key) {
		t.Fatalf("toast = %s", body.String())
	}
}
