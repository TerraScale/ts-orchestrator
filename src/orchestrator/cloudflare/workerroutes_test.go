package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func routeZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", WorkerRoutes: []WorkerRoute{
		{Pattern: "api.terrascale.tech/*", Script: ProxyWorkerScript},
		{Pattern: "app.terrascale.tech/*", Script: DashboardWorkerScript},
	}}
}

func TestWorkerRoutesReconcile(t *testing.T) {
	cases := []struct {
		name       string
		live       string
		wantPlan   []string
		wantMethod []string
	}{
		{
			name:       "create from empty",
			live:       `[]`,
			wantPlan:   []string{"create worker-route api.terrascale.tech/* -> ts-proxy", "create worker-route app.terrascale.tech/* -> ts-dashboard"},
			wantMethod: []string{http.MethodPost, http.MethodPost},
		},
		{
			name: "no-op when declared",
			live: `[{"id":"w1","pattern":"api.terrascale.tech/*","script":"ts-proxy"},{"id":"w2","pattern":"app.terrascale.tech/*","script":"ts-dashboard"}]`,
		},
		{
			name:       "drift on script is repaired by update",
			live:       `[{"id":"w1","pattern":"api.terrascale.tech/*","script":"old-proxy"},{"id":"w2","pattern":"app.terrascale.tech/*","script":"ts-dashboard"}]`,
			wantPlan:   []string{"update worker-route api.terrascale.tech/* -> ts-proxy"},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:       "orphan route is deleted",
			live:       `[{"id":"w1","pattern":"api.terrascale.tech/*","script":"ts-proxy"},{"id":"w2","pattern":"app.terrascale.tech/*","script":"ts-dashboard"},{"id":"w3","pattern":"legacy.terrascale.tech/*","script":"legacy"}]`,
			wantPlan:   []string{"delete worker-route legacy.terrascale.tech/* -> legacy"},
			wantMethod: []string{http.MethodDelete},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch call.Method {
				case http.MethodGet:
					return okEnvelope(tc.live)
				case http.MethodPost, http.MethodPut, http.MethodDelete:
					methods = append(methods, call.Method)
					return okEnvelope(`{"id":"w9"}`)
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected")
			})
			z := routeZone()
			p := &Plan{}
			if err := z.reconcileWorkerRoutes(context.Background(), c, p); err != nil {
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

// D-55: no route may ever exist for sync.api, not even an orphan someone
// clicked into the console.
func TestWorkerRoutesNeverTouchSyncAPI(t *testing.T) {
	z := routeZone()
	for _, r := range z.WorkerRoutes {
		if r.Pattern == "sync.terrascale.tech/*" || r.Pattern == "sync.api.terrascale.tech/*" {
			t.Fatalf("a Worker on the reactive hot path is forbidden (D-55): %v", r)
		}
	}
	live := `[{"id":"bad","pattern":"sync.api.terrascale.tech/*","script":"anything"}]`
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		if call.Method == http.MethodGet {
			return okEnvelope(live)
		}
		return okEnvelope("null")
	})
	p := &Plan{}
	if err := z.reconcileWorkerRoutes(context.Background(), c, p); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	deleted := false
	for _, ch := range p.Changes {
		if ch.Action == Delete && ch.Ref == "sync.api.terrascale.tech/*" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("a sync.api route must be deleted as drift, got %v", summarize(p))
	}
}
