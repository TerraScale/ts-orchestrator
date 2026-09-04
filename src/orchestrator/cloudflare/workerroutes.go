package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WorkerRoute declares one Worker route: api. first contact to the ts-proxy
// Worker, app. to the dashboard Worker (D-58/D-59). sync.api never has a
// route — no Worker on the reactive hot path (D-55).
type WorkerRoute struct {
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

// WorkerRouteAPI is the Worker-routes surface.
type WorkerRouteAPI interface {
	ListWorkerRoutes(ctx context.Context) ([]WorkerRoute, error)
	CreateWorkerRoute(ctx context.Context, r WorkerRoute) error
	UpdateWorkerRoute(ctx context.Context, r WorkerRoute) error // r.ID required
	DeleteWorkerRoute(ctx context.Context, id string) error
}

var _ WorkerRouteAPI = (*Client)(nil)

func (c *Client) ListWorkerRoutes(ctx context.Context) ([]WorkerRoute, error) {
	var out []WorkerRoute
	err := c.do(ctx, "list worker routes", http.MethodGet, c.zonePath("/workers/routes"), nil, &out)
	return out, err
}

func (c *Client) CreateWorkerRoute(ctx context.Context, r WorkerRoute) error {
	return c.do(ctx, "create worker route", http.MethodPost, c.zonePath("/workers/routes"), r, nil)
}

func (c *Client) UpdateWorkerRoute(ctx context.Context, r WorkerRoute) error {
	return c.do(ctx, "update worker route", http.MethodPut, c.zonePath("/workers/routes/"+url.PathEscape(r.ID)), r, nil)
}

func (c *Client) DeleteWorkerRoute(ctx context.Context, id string) error {
	return c.do(ctx, "delete worker route", http.MethodDelete, c.zonePath("/workers/routes/"+url.PathEscape(id)), nil, nil)
}

func (z *Zone) reconcileWorkerRoutes(ctx context.Context, c *Client, p *Plan) error {
	api := WorkerRouteAPI(c)
	// A declared route may never put a Worker on the reactive hot path
	// (D-55): that is a configuration bug, refused before any plan exists.
	for _, r := range z.WorkerRoutes {
		if err := forbidHotPathRoute(r.Pattern, z.ZoneName); err != nil {
			return err
		}
	}
	live, err := api.ListWorkerRoutes(ctx)
	if err != nil {
		return err
	}
	key := func(r WorkerRoute) string { return r.Pattern }
	eq := func(a, b WorkerRoute) bool { return a.Script == b.Script }
	creates, deletes, updates := diff(live, z.WorkerRoutes, key, eq)
	for _, r := range creates {
		r := r
		p.Changes = append(p.Changes, Change{Action: Create, Resource: "worker-route", Ref: r.Pattern,
			Detail: r.Pattern + " -> " + r.Script,
			apply:  func(ctx context.Context) error { return api.CreateWorkerRoute(ctx, r) }})
	}
	for _, u := range updates {
		want := u.Want
		want.ID = u.Live.ID
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "worker-route", Ref: want.Pattern,
			Detail: want.Pattern + " -> " + want.Script,
			apply:  func(ctx context.Context) error { return api.UpdateWorkerRoute(ctx, want) }})
	}
	for _, r := range deletes {
		id := r.ID
		p.Changes = append(p.Changes, Change{Action: Delete, Resource: "worker-route", Ref: r.Pattern,
			Detail: r.Pattern + " -> " + r.Script,
			apply:  func(ctx context.Context) error { return api.DeleteWorkerRoute(ctx, id) }})
	}
	return nil
}

// forbidHotPathRoute rejects a declared pattern whose hostname is
// sync.api.<zone> — no Worker ever runs there (D-55) — or a wildcard, which
// would capture sync.api along with everything else. Live drift on that
// hostname is deleted as an orphan by the diff above; this guard keeps the
// bug out of the declaration itself.
func forbidHotPathRoute(pattern, zoneName string) error {
	host := strings.ToLower(pattern)
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if host == "sync.api."+strings.ToLower(zoneName) || strings.HasPrefix(host, "*.") {
		return fmt.Errorf("cloudflare: worker route %q would put a Worker on the reactive hot path (D-55)", pattern)
	}
	return nil
}
