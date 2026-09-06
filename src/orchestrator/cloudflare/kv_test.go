package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
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
