package estate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type publisherWriterFake struct {
	mutex sync.Mutex
	puts  []publisherPut
	fail  error
}

type publisherPut struct {
	collection string
	docID      string
	body       any
}

func (f *publisherWriterFake) PutDocument(_ context.Context, collection, docID string, body any) error {
	if f.fail != nil {
		return f.fail
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.puts = append(f.puts, publisherPut{collection: collection, docID: docID, body: body})
	return nil
}

func (f *publisherWriterFake) ids() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	ids := make([]string, 0, len(f.puts))
	for _, put := range f.puts {
		ids = append(ids, put.docID)
	}
	return ids
}

func publisherTestSnapshot(regions any) func(context.Context) (Snapshot, error) {
	return func(context.Context) (Snapshot, error) {
		return Snapshot{
			Regions:   regions,
			Hosts:     map[string]any{"hosts": []any{}},
			Databases: map[string]any{"databases": []any{}},
			Rollouts:  map[string]any{"rollouts": []any{}},
			SLO:       map[string]any{"slo": "ok"},
			Reconcile: map[string]any{"converged": true},
		}, nil
	}
}

func TestPublisherDefaultsToTenSecondTick(t *testing.T) {
	writer := &publisherWriterFake{}
	publisher, err := NewPublisher(PublisherConfig{
		Writer:   writer,
		Snapshot: publisherTestSnapshot(map[string]any{"v": 1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if publisher.Interval() != DefaultPublisherInterval || DefaultPublisherInterval != 10*time.Second {
		t.Fatalf("interval = %v, want 10s", publisher.Interval())
	}
	if got := len(EstateDocIDs()); got != 6 {
		t.Fatalf("estate documents = %d, want 6", got)
	}
	for _, want := range []string{"regions", "hosts", "databases", "rollouts", "slo", "reconcile"} {
		found := false
		for _, id := range EstateDocIDs() {
			if id == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("estate document %q is missing", want)
		}
		if QualifiedName(want) != "estate."+want {
			t.Fatalf("qualified name = %q, want estate.%s", QualifiedName(want), want)
		}
	}
}

func TestPublisherRejectsMissingDependencies(t *testing.T) {
	base := PublisherConfig{
		Writer:   &publisherWriterFake{},
		Snapshot: publisherTestSnapshot(nil),
	}
	for _, mutate := range []func(*PublisherConfig){
		func(c *PublisherConfig) { c.Writer = nil },
		func(c *PublisherConfig) { c.Snapshot = nil },
		func(c *PublisherConfig) { c.Interval = -time.Second },
		func(c *PublisherConfig) { c.Collection = " bad " },
	} {
		config := base
		mutate(&config)
		if _, err := NewPublisher(config); err == nil {
			t.Fatal("invalid config was accepted")
		}
	}
}

func TestPublisherWritesChangedDocumentsOnly(t *testing.T) {
	writer := &publisherWriterFake{}
	regions := map[string]any{"gru": "healthy"}
	publisher, err := NewPublisher(PublisherConfig{
		Writer:   writer,
		Snapshot: publisherTestSnapshot(regions),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := publisher.Publish(ctx)
	if err != nil || first != 6 {
		t.Fatalf("first publish writes=%d err=%v, want 6", first, err)
	}
	second, err := publisher.Publish(ctx)
	if err != nil || second != 0 {
		t.Fatalf("second publish writes=%d err=%v, want 0 (change only)", second, err)
	}
	if got := publisher.WriteCount(); got != 6 {
		t.Fatalf("write count=%d, want 6", got)
	}
	regions["gru"] = "degraded"
	third, err := publisher.Publish(ctx)
	if err != nil || third != 1 {
		t.Fatalf("changed publish writes=%d err=%v, want 1", third, err)
	}
	ids := writer.ids()
	if len(ids) != 7 {
		t.Fatalf("total puts=%d, want 7", len(ids))
	}
	if ids[len(ids)-1] != DocRegions {
		t.Fatalf("changed put doc=%q, want %q", ids[len(ids)-1], DocRegions)
	}
	for _, put := range writer.puts {
		if put.collection != EstateCollection {
			t.Fatalf("put collection=%q, want %q", put.collection, EstateCollection)
		}
	}
}

func TestPublisherFailsClosed(t *testing.T) {
	writer := &publisherWriterFake{}
	publisher, err := NewPublisher(PublisherConfig{
		Writer:   writer,
		Snapshot: publisherTestSnapshot(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(nil); err == nil {
		t.Fatal("nil context was accepted")
	}
	failing := &publisherWriterFake{fail: errors.New("control-plane unavailable")}
	publisherFail, err := NewPublisher(PublisherConfig{
		Writer:   failing,
		Snapshot: publisherTestSnapshot(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisherFail.Publish(context.Background()); err == nil {
		t.Fatal("writer failure was accepted")
	}
	if publisherFail.LastError() == nil {
		t.Fatal("LastError should retain the tick failure")
	}
	broken, err := NewPublisher(PublisherConfig{
		Writer:   writer,
		Snapshot: func(context.Context) (Snapshot, error) { return Snapshot{}, errors.New("observation failed") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Publish(context.Background()); err == nil {
		t.Fatal("snapshot failure was accepted")
	}
}

func TestRegionsPayloadIsDeterministic(t *testing.T) {
	spec := Default()
	first, err := RegionsPayload(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RegionsPayload(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first.EstateVersion != SchemaVersion || first.HomeRegion != "gru" || len(first.Regions) != 3 {
		t.Fatalf("regions payload = %+v, want 3 launch regions", first)
	}
	rawFirst, err := marshalCanonical(first)
	if err != nil {
		t.Fatal(err)
	}
	rawSecond, err := marshalCanonical(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(rawFirst) != string(rawSecond) {
		t.Fatal("regions payload is not deterministic")
	}
	if _, err := RegionsPayload(Spec{}); err == nil {
		t.Fatal("invalid spec was accepted")
	}
}

func TestControlPlaneClientPutDocument(t *testing.T) {
	var mutex sync.Mutex
	var method, path, auth, contentType string
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		method, path = request.Method, request.URL.EscapedPath()
		auth, contentType = request.Header.Get("Authorization"), request.Header.Get("Content-Type")
		body, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"revision":"1-1"}`))
	}))
	defer server.Close()

	client, err := NewControlPlaneClient(ControlPlaneClientConfig{
		BaseURL:  server.URL,
		Database: "control",
		Token:    StaticToken("secret-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.PutDocument(context.Background(), EstateCollection, DocRegions, map[string]any{"gru": "healthy"}); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if method != http.MethodPut {
		t.Fatalf("method = %s, want PUT", method)
	}
	wantPath := "/api/v1/databases/control/collections/estate/documents/regions"
	if path != wantPath {
		t.Fatalf("path = %s, want %s", path, wantPath)
	}
	if auth != "Bearer secret-key" {
		t.Fatalf("authorization = %q, want bearer token", auth)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type = %q, want application/json", contentType)
	}
	if strings.Contains(string(body), "secret-key") {
		t.Fatal("request body must never carry the token")
	}
	if !strings.Contains(string(body), `"gru"`) {
		t.Fatalf("body = %s, want the raw document value", body)
	}
}

func TestControlPlaneClientFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"code":"forbidden"}`))
	}))
	defer server.Close()

	client, err := NewControlPlaneClient(ControlPlaneClientConfig{
		BaseURL:  server.URL,
		Database: "control",
		Token:    StaticToken("secret-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.PutDocument(context.Background(), EstateCollection, DocRegions, map[string]any{}); err == nil {
		t.Fatal("non-2xx was accepted")
	}
	if err := client.PutDocument(nil, EstateCollection, DocRegions, map[string]any{}); err == nil {
		t.Fatal("nil context was accepted")
	}
	if err := client.PutDocument(context.Background(), "", DocRegions, map[string]any{}); err == nil {
		t.Fatal("empty collection was accepted")
	}
	if _, err := NewControlPlaneClient(ControlPlaneClientConfig{Database: "control", Token: StaticToken("k")}); err == nil {
		t.Fatal("missing base URL was accepted")
	}
	if _, err := NewControlPlaneClient(ControlPlaneClientConfig{BaseURL: server.URL, Token: StaticToken("k")}); err == nil {
		t.Fatal("missing database was accepted")
	}
	if _, err := NewControlPlaneClient(ControlPlaneClientConfig{BaseURL: server.URL, Database: "control"}); err == nil {
		t.Fatal("missing token source was accepted")
	}
	emptyToken, err := NewControlPlaneClient(ControlPlaneClientConfig{BaseURL: server.URL, Database: "control", Token: func() string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if err := emptyToken.PutDocument(context.Background(), EstateCollection, DocRegions, map[string]any{}); err == nil {
		t.Fatal("empty token was accepted")
	}
}
