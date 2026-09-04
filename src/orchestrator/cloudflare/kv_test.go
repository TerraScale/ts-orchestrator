package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func kvZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", KVNamespaces: []KVNamespaceDecl{
		{Title: RegionHealthNamespace}, {Title: DBPlacementNamespace},
	}}
}

func TestKVNamespacesReconcile(t *testing.T) {
	cases := []struct {
		name       string
		live       string
		wantPlan   []string
		wantMethod []string
	}{
		{
			name:       "create both maps",
			live:       `[]`,
			wantPlan:   []string{"create kv-namespace " + DBPlacementNamespace, "create kv-namespace " + RegionHealthNamespace},
			wantMethod: []string{http.MethodPost, http.MethodPost},
		},
		{
			name:     "no-op when declared",
			live:     `[{"id":"n1","title":"ts-region-health"},{"id":"n2","title":"ts-db-placement"}]`,
			wantPlan: nil,
		},
		{
			name:       "orphan namespace is deleted",
			live:       `[{"id":"n1","title":"ts-region-health"},{"id":"n2","title":"ts-db-placement"},{"id":"n3","title":"old-maps"}]`,
			wantPlan:   []string{"delete kv-namespace old-maps"},
			wantMethod: []string{http.MethodDelete},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch {
				case call.Method == http.MethodGet && strings.Contains(call.Path, "/storage/kv/namespaces"):
					return okEnvelope(tc.live)
				case call.Method == http.MethodPost || call.Method == http.MethodDelete:
					methods = append(methods, call.Method)
					return okEnvelope(`{"id":"n9","title":"x"}`)
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
			})
			z := kvZone()
			p := &Plan{}
			if err := z.reconcileKVNamespaces(context.Background(), c, p); err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}
			if got := summarize(p); !reflect.DeepEqual(got, tc.wantPlan) {
				t.Fatalf("plan = %v\nwant %v", got, tc.wantPlan)
			}
			if err := Apply(context.Background(), p); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			if !reflect.DeepEqual(methods, tc.wantMethod) {
				t.Fatalf("applied methods = %v, want %v", methods, tc.wantMethod)
			}
		})
	}
}

// The map CRUD the I-4 writer loop will drive (D-58).
func TestKVMapCRUD(t *testing.T) {
	values := map[string]string{}
	var puts, deletes []string
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		switch {
		case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/namespaces?per_page=100"):
			return okEnvelope(`[{"id":"ns-health","title":"` + RegionHealthNamespace + `"},{"id":"ns-place","title":"` + DBPlacementNamespace + `"}]`)
		case call.Method == http.MethodPut && strings.Contains(call.Path, "/values/"):
			puts = append(puts, call.Path+" "+call.Body)
			return okEnvelope("null")
		case call.Method == http.MethodGet && strings.Contains(call.Path, "/values/"):
			key := call.Path[strings.LastIndex(call.Path, "/")+1:]
			value, ok := values[key]
			if !ok {
				return failEnvelope(http.StatusNotFound, 10004, "not found")
			}
			return http.StatusOK, value, nil // raw value, not an envelope
		case call.Method == http.MethodDelete && strings.Contains(call.Path, "/values/"):
			key := call.Path[strings.LastIndex(call.Path, "/")+1:]
			if _, ok := values[key]; !ok {
				return failEnvelope(http.StatusNotFound, 10004, "not found")
			}
			delete(values, key)
			deletes = append(deletes, call.Path)
			return okEnvelope("null")
		}
		return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
	})
	ctx := context.Background()

	health := RegionHealth{Healthy: true, Members: []string{"198.51.100.10", "198.51.100.11"}, UpdatedAt: time.Unix(1000, 0)}
	if err := c.SetRegionHealth(ctx, "gru", health); err != nil {
		t.Fatalf("SetRegionHealth failed: %v", err)
	}
	var stored RegionHealth
	if err := json.Unmarshal([]byte(strings.SplitN(puts[0], " ", 2)[1]), &stored); err != nil {
		t.Fatalf("health value is not JSON: %v", err)
	}
	// Round-trip through the fake store proves read/write symmetry.
	values["gru"] = strings.SplitN(puts[0], " ", 2)[1]
	got, err := c.RegionHealth(ctx, "gru")
	if err != nil {
		t.Fatalf("RegionHealth failed: %v", err)
	}
	if !got.Healthy || !reflect.DeepEqual(got.Members, health.Members) || got.Region != "gru" {
		t.Fatalf("health round-trip mismatch: %+v", got)
	}

	placement := DBPlacement{Regions: []string{"gru", "sfo"}, UpdatedAt: time.Unix(1000, 0)}
	if err := c.SetDBPlacement(ctx, "db-1", placement); err != nil {
		t.Fatalf("SetDBPlacement failed: %v", err)
	}
	values["db-1"] = strings.SplitN(puts[1], " ", 2)[1]
	pl, err := c.DBPlacement(ctx, "db-1")
	if err != nil {
		t.Fatalf("DBPlacement failed: %v", err)
	}
	if !reflect.DeepEqual(pl.Regions, []string{"gru", "sfo"}) || pl.Database != "db-1" {
		t.Fatalf("placement round-trip mismatch: %+v", pl)
	}

	// Values must land in the namespace resolved by TITLE, on the right key.
	if !strings.Contains(puts[0], "/namespaces/ns-health/values/gru") {
		t.Fatalf("health write went to the wrong path: %s", puts[0])
	}
	if !strings.Contains(puts[1], "/namespaces/ns-place/values/db-1") {
		t.Fatalf("placement write went to the wrong path: %s", puts[1])
	}

	// Missing key maps to ErrNotFound; delete is idempotent.
	if _, err := c.DBPlacement(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := c.DeleteDBPlacement(ctx, "db-1"); err != nil {
		t.Fatalf("DeleteDBPlacement failed: %v", err)
	}
	if err := c.DeleteDBPlacement(ctx, "db-1"); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
	if len(deletes) != 1 {
		t.Fatalf("unexpected deletes: %v", deletes)
	}
}
