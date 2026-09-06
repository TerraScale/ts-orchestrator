package cloudflare

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// workerMapFake is a KV fake for the two namespaces the Worker reads: it
// answers namespace listing, raw value get/put, and the bulk endpoints.
type workerMapFake struct {
	mu       sync.Mutex
	values   map[string]map[string]string // namespace id -> key -> value
	bulkPuts [][]string                   // keys per bulk PUT call
}

func newWorkerMapFake() *workerMapFake {
	return &workerMapFake{values: map[string]map[string]string{
		"ns-health": {},
		"ns-place":  {},
	}}
}

func (f *workerMapFake) handle(t *testing.T) func(fakeCall) (int, string, http.Header) {
	return func(call fakeCall) (int, string, http.Header) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/namespaces?per_page=100"):
			return okEnvelope(`[{"id":"ns-health","title":"` + RegionHealthNamespace + `"},{"id":"ns-place","title":"` + DBPlacementNamespace + `"}]`)
		case call.Method == http.MethodPut && strings.Contains(call.Path, "/values/"):
			ns := nsID(call.Path)
			f.values[ns][lastSegment(call.Path)] = call.Body
			return okEnvelope("null")
		case call.Method == http.MethodGet && strings.Contains(call.Path, "/values/"):
			ns := nsID(call.Path)
			value, ok := f.values[ns][lastSegment(call.Path)]
			if !ok {
				return failEnvelope(http.StatusNotFound, 10004, "not found")
			}
			return http.StatusOK, value, nil // raw value, not an envelope
		case call.Method == http.MethodDelete && strings.Contains(call.Path, "/values/"):
			delete(f.values[nsID(call.Path)], lastSegment(call.Path))
			return okEnvelope("null")
		case call.Method == http.MethodPut && strings.HasSuffix(call.Path, "/bulk"):
			ns := nsID(call.Path)
			var batch []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}
			if err := json.Unmarshal([]byte(call.Body), &batch); err != nil {
				t.Fatalf("bulk put body is not a key/value array: %v", err)
			}
			keys := make([]string, 0, len(batch))
			for _, entry := range batch {
				f.values[ns][entry.Key] = entry.Value
				keys = append(keys, entry.Key)
			}
			f.bulkPuts = append(f.bulkPuts, keys)
			return okEnvelope("[]")
		case call.Method == http.MethodDelete && strings.HasSuffix(call.Path, "/bulk"):
			ns := nsID(call.Path)
			var keys []string
			if err := json.Unmarshal([]byte(call.Body), &keys); err != nil {
				t.Fatalf("bulk delete body is not a key array: %v", err)
			}
			for _, key := range keys {
				delete(f.values[ns], key)
			}
			return okEnvelope("[]")
		}
		return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
	}
}

func nsID(path string) string {
	const marker = "/namespaces/"
	rest := path[strings.Index(path, marker)+len(marker):]
	return rest[:strings.IndexByte(rest, '/')]
}

func lastSegment(path string) string {
	return path[strings.LastIndexByte(path, '/')+1:]
}

func TestWorkerResidencyWireShapes(t *testing.T) {
	cases := []struct {
		name string
		in   WorkerResidency
		want string
	}{
		{name: "null when unconstrained", in: WorkerResidency{}, want: `null`},
		{name: "label", in: WorkerResidency{Label: "eu-only"}, want: `"eu-only"`},
		{name: "region list", in: WorkerResidency{Codes: []string{"gru", "FRA"}}, want: `["gru","FRA"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("wire = %s, want %s", got, tc.want)
			}
			var back WorkerResidency
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if !reflect.DeepEqual(back, tc.in) {
				t.Fatalf("round-trip mismatch: %+v", back)
			}
		})
	}
	for _, raw := range []string{`null`, `"br-only"`, `["GRU","SFO"]`} {
		var r WorkerResidency
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatalf("unmarshal %s failed: %v", raw, err)
		}
	}
	var r WorkerResidency
	if err := json.Unmarshal([]byte(`42`), &r); err == nil {
		t.Fatal("a number is not a residency")
	}
}

func TestSetWorkerHealthWritesTheContractDocument(t *testing.T) {
	fake := newWorkerMapFake()
	c, _ := testClient(fake.handle(t))
	ctx := context.Background()

	doc := WorkerHealthDoc{
		Updated: 1725300000,
		Regions: map[string]WorkerRegionHealth{
			"gru": {OK: true, LagMS: 0, Lat: -23.43, Lon: -46.47},
			"sfo": {OK: true, LagMS: 40, Lat: 37.37, Lon: -121.92},
			"fra": {OK: false, Lat: 50.03, Lon: 8.57},
		},
	}
	if err := c.SetWorkerHealth(ctx, doc); err != nil {
		t.Fatalf("SetWorkerHealth failed: %v", err)
	}
	raw := fake.values["ns-health"]["regions"]
	var wire map[string]any
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		t.Fatalf("health value is not JSON: %v", err)
	}
	if wire["v"] != float64(1) {
		t.Fatalf("version = %v, want 1", wire["v"])
	}
	if wire["updated"] != float64(1725300000) {
		t.Fatalf("updated = %v, want the writer stamp", wire["updated"])
	}
	regions := wire["regions"].(map[string]any)
	if len(regions) != 3 {
		t.Fatalf("regions = %v, want three canonical entries", regions)
	}
	if _, ok := regions["GRU"]; !ok {
		t.Fatalf("region codes must be canonicalized to uppercase: %v", regions)
	}
	sfo := regions["SFO"].(map[string]any)
	if sfo["ok"] != true || sfo["lag_ms"] != float64(40) || sfo["lat"] != 37.37 {
		t.Fatalf("SFO entry = %v", sfo)
	}

	got, err := c.WorkerHealth(ctx)
	if err != nil {
		t.Fatalf("WorkerHealth read failed: %v", err)
	}
	if !reflect.DeepEqual(got.Regions["GRU"], WorkerRegionHealth{OK: true, Lat: -23.43, Lon: -46.47}) {
		t.Fatalf("health round-trip mismatch: %+v", got)
	}
	if got.V != 1 || got.Updated != 1725300000 {
		t.Fatalf("health document header mismatch: %+v", got)
	}
}

func TestSetWorkerHealthRejectsDroppedDocuments(t *testing.T) {
	stamped := WorkerHealthDoc{Updated: 1725300000, Regions: map[string]WorkerRegionHealth{
		"GRU": {OK: true, Lat: -23.43, Lon: -46.47},
	}}
	overfull := WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{}}
	for i := 0; i < maxWorkerHealthRegions+1; i++ {
		overfull.Regions["R"+strconv.Itoa(i)] = WorkerRegionHealth{OK: true}
	}
	cases := []struct {
		name string
		doc  WorkerHealthDoc
		want string
	}{
		{name: "missing stamp", doc: WorkerHealthDoc{Regions: stamped.Regions}, want: "stamp"},
		{name: "no regions", doc: WorkerHealthDoc{Updated: 1}, want: "at least one region"},
		{name: "too many regions", doc: overfull, want: "at most"},
		{name: "invalid code", doc: WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{
			"GRU!": {OK: true},
		}}, want: "A-Z"},
		{name: "duplicate after canonicalization", doc: WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{
			"GRU": {OK: true}, "gru": {OK: false},
		}}, want: "duplicates"},
		{name: "latitude out of range", doc: WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{
			"GRU": {OK: true, Lat: 91, Lon: 0},
		}}, want: "lat"},
		{name: "longitude NaN", doc: WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{
			"GRU": {OK: true, Lat: 0, Lon: math.NaN()},
		}}, want: "lon"},
		{name: "negative lag", doc: WorkerHealthDoc{Updated: 1, Regions: map[string]WorkerRegionHealth{
			"GRU": {OK: true, Lat: 0, Lon: 0, LagMS: -1},
		}}, want: "lag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newWorkerMapFake()
			c, _ := testClient(fake.handle(t))
			err := c.SetWorkerHealth(context.Background(), tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			if len(fake.values["ns-health"]) != 0 {
				t.Fatal("a rejected document must not be written")
			}
		})
	}
}

func TestSetWorkerPlacementsBulkChunksAndShapes(t *testing.T) {
	fake := newWorkerMapFake()
	c, _ := testClient(fake.handle(t))
	ctx := context.Background()

	placements := make(map[string]WorkerPlacement, kvBulkChunk+1)
	for i := 0; i <= kvBulkChunk; i++ { // 10,001 keys: two bulk calls
		id := "db" + strconv.Itoa(i)
		placements[id] = WorkerPlacement{
			R:   []string{"gru", "sfo"},
			U:   1725300000,
			Res: WorkerResidency{Label: "eu-only"},
		}
	}
	if err := c.SetWorkerPlacements(ctx, placements); err != nil {
		t.Fatalf("SetWorkerPlacements failed: %v", err)
	}
	if len(fake.bulkPuts) != 2 {
		t.Fatalf("bulk calls = %d, want 2", len(fake.bulkPuts))
	}
	if n := len(fake.bulkPuts[0]); n != kvBulkChunk {
		t.Fatalf("first bulk call carried %d keys, want %d", n, kvBulkChunk)
	}
	if n := len(fake.bulkPuts[1]); n != 1 {
		t.Fatalf("second bulk call carried %d keys, want 1", n)
	}
	if fake.bulkPuts[0][0] != "db:db0" {
		t.Fatalf("keys must be sorted and preserve database names: %v", fake.bulkPuts[0][0])
	}
	if fake.bulkPuts[1][0] != "db:db9999" {
		t.Fatalf("the overflow key is the lexicographically largest: %v", fake.bulkPuts[1][0])
	}

	var wire map[string]any
	if err := json.Unmarshal([]byte(fake.values["ns-place"]["db:db1"]), &wire); err != nil {
		t.Fatalf("placement value is not JSON: %v", err)
	}
	if wire["v"] != float64(1) {
		t.Fatalf("version = %v, want 1", wire["v"])
	}
	if !reflect.DeepEqual(wire["r"], []any{"GRU", "SFO"}) {
		t.Fatalf("hosting set = %v, want canonicalized and sorted", wire["r"])
	}
	if wire["res"] != "eu-only" {
		t.Fatalf("residency = %v, want the label", wire["res"])
	}
	if wire["u"] != float64(1725300000) {
		t.Fatalf("stamp = %v", wire["u"])
	}
}

func TestSetWorkerPlacementsRejectsDroppedDocuments(t *testing.T) {
	both := WorkerResidency{Label: "eu-only", Codes: []string{"FRA"}}
	cases := []struct {
		name      string
		placement WorkerPlacement
		want      string
	}{
		{name: "missing stamp", placement: WorkerPlacement{R: []string{"GRU"}}, want: "stamp"},
		{name: "empty hosting set", placement: WorkerPlacement{R: nil, U: 1}, want: "at least one hosting region"},
		{name: "too many regions", placement: WorkerPlacement{R: regions("R", maxWorkerPlacementRegions+1), U: 1}, want: "at most"},
		{name: "invalid region", placement: WorkerPlacement{R: []string{"GRU", "sfo.example"}, U: 1}, want: "A-Z"},
		{name: "duplicate region", placement: WorkerPlacement{R: []string{"GRU", "gru"}, U: 1}, want: "duplicates"},
		{name: "residency label and list", placement: WorkerPlacement{R: []string{"GRU"}, U: 1, Res: both}, want: "not both"},
		{name: "residency label needs trimming", placement: WorkerPlacement{R: []string{"GRU"}, U: 1, Res: WorkerResidency{Label: " eu-only"}}, want: "trimmed"},
		{name: "residency list empty", placement: WorkerPlacement{R: []string{"GRU"}, U: 1, Res: WorkerResidency{Codes: []string{}}}, want: "not be empty"},
		{name: "residency list invalid code", placement: WorkerPlacement{R: []string{"GRU"}, U: 1, Res: WorkerResidency{Codes: []string{"EU!"}}}, want: "A-Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newWorkerMapFake()
			c, _ := testClient(fake.handle(t))
			err := c.SetWorkerPlacements(context.Background(), map[string]WorkerPlacement{"db1": tc.placement})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			if len(fake.bulkPuts) != 0 {
				t.Fatal("a rejected placement must not be written")
			}
		})
	}
}

func regions(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, prefix+strconv.Itoa(i))
	}
	return out
}

func TestWorkerPlacementRoundTripAndDelete(t *testing.T) {
	fake := newWorkerMapFake()
	c, _ := testClient(fake.handle(t))
	ctx := context.Background()

	placement := WorkerPlacement{R: []string{"sfo", "gru"}, U: 1725300000,
		Res: WorkerResidency{Codes: []string{"gru", "sfo"}}}
	if err := c.SetWorkerPlacements(ctx, map[string]WorkerPlacement{"db1000": placement}); err != nil {
		t.Fatalf("SetWorkerPlacements failed: %v", err)
	}
	got, err := c.WorkerPlacement(ctx, "db1000")
	if err != nil {
		t.Fatalf("WorkerPlacement failed: %v", err)
	}
	if !reflect.DeepEqual(got.R, []string{"GRU", "SFO"}) || got.Res.Label != "" || !reflect.DeepEqual(got.Res.Codes, []string{"GRU", "SFO"}) {
		t.Fatalf("placement round-trip mismatch: %+v", got)
	}
	if err := c.DeleteWorkerPlacements(ctx, []string{"db1000", "db1000"}); err != nil {
		t.Fatalf("DeleteWorkerPlacements failed: %v", err)
	}
	if _, err := c.WorkerPlacement(ctx, "db1000"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestWorkerPlacementRejectsNamesOutsideProducerContract(t *testing.T) {
	for _, name := range []string{"", "DB1000", "-db", "db-", "db_name", "a/b", strings.Repeat("a", 64), "dáb"} {
		t.Run(name, func(t *testing.T) {
			fake := newWorkerMapFake()
			c, _ := testClient(fake.handle(t))
			if err := c.SetWorkerPlacements(t.Context(), map[string]WorkerPlacement{name: {R: []string{"GRU"}, U: 1}}); err == nil {
				t.Fatal("invalid producer database name accepted")
			}
			if len(fake.bulkPuts) != 0 {
				t.Fatal("invalid name reached provider")
			}
		})
	}
	for _, name := range []string{"a", "0", "customer-db", strings.Repeat("a", 63)} {
		if key, err := workerPlacementKey(name); err != nil || key != "db:"+name {
			t.Fatalf("valid name %q changed: key=%q err=%v", name, key, err)
		}
	}
}
