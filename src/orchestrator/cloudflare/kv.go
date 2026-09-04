package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// KVNamespaceDecl declares one Workers KV namespace; KVNamespace is the
// observed one.
type KVNamespaceDecl struct{ Title string }

type KVNamespace struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// KVAPI is the namespace surface. The namespaces themselves are the declared
// resource; the values inside them are runtime data written by the I-4 loop
// through the CRUD methods below.
type KVAPI interface {
	ListKVNamespaces(ctx context.Context) ([]KVNamespace, error)
	CreateKVNamespace(ctx context.Context, title string) error
	DeleteKVNamespace(ctx context.Context, id string) error
}

var _ KVAPI = (*Client)(nil)

func (c *Client) ListKVNamespaces(ctx context.Context) ([]KVNamespace, error) {
	var all []KVNamespace
	for page := 1; ; page++ {
		var namespaces []KVNamespace
		suffix := "/storage/kv/namespaces?per_page=100"
		if page > 1 {
			suffix += fmt.Sprintf("&page=%d", page)
		}
		info, err := c.doPage(ctx, "list kv namespaces", http.MethodGet, c.accountPath(suffix), nil, &namespaces)
		if err != nil {
			return nil, err
		}
		all = append(all, namespaces...)
		if info == nil || info.TotalPages <= page || info.TotalPages <= 0 {
			return all, nil
		}
	}
}

func (c *Client) CreateKVNamespace(ctx context.Context, title string) error {
	var created KVNamespace
	return c.do(ctx, "create kv namespace", http.MethodPost, c.accountPath("/storage/kv/namespaces"),
		map[string]string{"title": title}, &created)
}

func (c *Client) DeleteKVNamespace(ctx context.Context, id string) error {
	return c.do(ctx, "delete kv namespace", http.MethodDelete,
		c.accountPath("/storage/kv/namespaces/"+url.PathEscape(id)), nil, nil)
}

func (z *Zone) reconcileKVNamespaces(ctx context.Context, c *Client, p *Plan) error {
	api := KVAPI(c)
	live, err := api.ListKVNamespaces(ctx)
	if err != nil {
		return err
	}
	want := make([]KVNamespace, 0, len(z.KVNamespaces))
	for _, decl := range z.KVNamespaces {
		want = append(want, KVNamespace{Title: decl.Title})
	}
	key := func(n KVNamespace) string { return n.Title }
	eq := func(a, b KVNamespace) bool { return true }
	creates, deletes, _ := diff(live, want, key, eq)
	for _, n := range creates {
		title := n.Title
		p.Changes = append(p.Changes, Change{Action: Create, Resource: "kv-namespace", Ref: title, Detail: title,
			apply: func(ctx context.Context) error { return api.CreateKVNamespace(ctx, title) }})
	}
	for _, n := range deletes {
		id := n.ID
		p.Changes = append(p.Changes, Change{Action: Delete, Resource: "kv-namespace", Ref: n.Title, Detail: n.Title,
			apply: func(ctx context.Context) error { return api.DeleteKVNamespace(ctx, id) }})
	}
	return nil
}

// RegionHealth and DBPlacement are the two maps the ts-proxy Worker reads to
// route first-contact REST (D-58): which Regions are healthy, and which
// Regions host a database. Keys are bare region codes / database ids. The
// writer loop is item I-4; this is its CRUD. Write ordering (health before
// placement) is the loop's job.
type RegionHealth struct {
	Region    string    `json:"region"`
	Healthy   bool      `json:"healthy"`
	Members   []string  `json:"members"` // healthy member addresses, sorted
	UpdatedAt time.Time `json:"updated_at"`
}

type DBPlacement struct {
	Database      string    `json:"database"`
	Regions       []string  `json:"regions"`                  // hosting Regions, sorted
	PlacementLock string    `json:"placement_lock,omitempty"` // eu-only, br-only, or explicit
	Generation    uint64    `json:"generation,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// SetRegionHealth writes one region's health entry.
func (c *Client) SetRegionHealth(ctx context.Context, region string, h RegionHealth) error {
	h.Region = region
	return putKVJSON(ctx, c, RegionHealthNamespace, region, h)
}

// RegionHealth reads one region's health entry.
func (c *Client) RegionHealth(ctx context.Context, region string) (RegionHealth, error) {
	var h RegionHealth
	err := getKVJSON(ctx, c, RegionHealthNamespace, region, &h)
	return h, err
}

// DeleteRegionHealth removes one region's health entry.
func (c *Client) DeleteRegionHealth(ctx context.Context, region string) error {
	return c.deleteKVValue(ctx, RegionHealthNamespace, region)
}

// SetDBPlacement writes one database's placement map entry.
func (c *Client) SetDBPlacement(ctx context.Context, database string, pl DBPlacement) error {
	if err := validateDBPlacementDocument(pl); err != nil {
		return err
	}
	pl.Database = database
	pl.Regions = append([]string(nil), pl.Regions...)
	sort.Strings(pl.Regions)
	return putKVJSON(ctx, c, DBPlacementNamespace, database, pl)
}

func validateDBPlacementDocument(pl DBPlacement) error {
	if len(pl.Regions) == 0 || len(pl.Regions) > 20 {
		return fmt.Errorf("cloudflare: placement needs between 1 and 20 hosting regions")
	}
	seen := map[string]struct{}{}
	for _, region := range pl.Regions {
		if err := validateKVWriterKey(region); err != nil {
			return fmt.Errorf("cloudflare: placement region: %w", err)
		}
		if _, exists := seen[region]; exists {
			return errors.New("cloudflare: placement contains duplicate hosting regions")
		}
		seen[region] = struct{}{}
	}
	if pl.PlacementLock == "" && pl.Generation != 0 {
		return errors.New("cloudflare: placement generation requires an immutable lock")
	}
	if pl.PlacementLock != "" && pl.PlacementLock != "eu-only" && pl.PlacementLock != "br-only" && pl.PlacementLock != "explicit" {
		return errors.New("cloudflare: placement lock policy is invalid")
	}
	if pl.PlacementLock != "" && pl.Generation == 0 {
		return errors.New("cloudflare: placement lock generation must be positive")
	}
	return nil
}

// DBPlacement reads one database's placement entry.
func (c *Client) DBPlacement(ctx context.Context, database string) (DBPlacement, error) {
	var pl DBPlacement
	err := getKVJSON(ctx, c, DBPlacementNamespace, database, &pl)
	return pl, err
}

// DeleteDBPlacement removes one database's placement entry (database
// deletion).
func (c *Client) DeleteDBPlacement(ctx context.Context, database string) error {
	return c.deleteKVValue(ctx, DBPlacementNamespace, database)
}

func putKVJSON(ctx context.Context, c *Client, namespace, key string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cloudflare: encode kv value: %w", err)
	}
	return c.putKVValue(ctx, namespace, key, body)
}

func getKVJSON(ctx context.Context, c *Client, namespace, key string, out any) error {
	raw, err := c.getKVValue(ctx, namespace, key)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cloudflare: kv value %s/%s is malformed: %w", namespace, key, err)
	}
	return nil
}

// namespaceID resolves a namespace title to its ID with one list call. The
// reconciler guarantees the namespaces exist; no cache, so a recreated
// namespace can never be written through a stale ID.
func (c *Client) namespaceID(ctx context.Context, title string) (string, error) {
	namespaces, err := c.ListKVNamespaces(ctx)
	if err != nil {
		return "", err
	}
	for _, ns := range namespaces {
		if ns.Title == title {
			return ns.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: kv namespace %q not found (reconcile the zone first)", title)
}

func (c *Client) kvValuePath(namespaceID, key string) string {
	return c.accountPath("/storage/kv/namespaces/" + url.PathEscape(namespaceID) + "/values/" + url.PathEscape(key))
}

func (c *Client) putKVValue(ctx context.Context, namespace, key string, value []byte) error {
	id, err := c.namespaceID(ctx, namespace)
	if err != nil {
		return err
	}
	op := fmt.Sprintf("put kv %s/%s", namespace, key)
	status, _, err := c.roundtrip(ctx, op, http.MethodPut, c.kvValuePath(id, key), value)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &APIError{Op: op, Status: status}
	}
	return nil
}

// getKVValue reads a raw KV value. Value responses are raw bytes, not the
// API envelope; errors are.
func (c *Client) getKVValue(ctx context.Context, namespace, key string) ([]byte, error) {
	id, err := c.namespaceID(ctx, namespace)
	if err != nil {
		return nil, err
	}
	op := fmt.Sprintf("get kv %s/%s", namespace, key)
	status, raw, err := c.roundtrip(ctx, op, http.MethodGet, c.kvValuePath(id, key), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, apiErrorFromEnvelope(op, status, raw)
	}
	return raw, nil
}

func (c *Client) deleteKVValue(ctx context.Context, namespace, key string) error {
	id, err := c.namespaceID(ctx, namespace)
	if err != nil {
		return err
	}
	op := fmt.Sprintf("delete kv %s/%s", namespace, key)
	status, raw, err := c.roundtrip(ctx, op, http.MethodDelete, c.kvValuePath(id, key), nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil // already gone: deletes are idempotent
	}
	if status < 200 || status >= 300 {
		return apiErrorFromEnvelope(op, status, raw)
	}
	return nil
}
