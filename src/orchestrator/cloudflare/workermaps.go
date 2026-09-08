package cloudflare

// The two KV maps the ts-proxy Worker reads to route first-contact REST
// (D-58), exactly as published in ts-proxy/docs/design.md section 3 and
// parsed by its src/route.ts: one REGIONS document on key "regions" and one
// PLACEMENT document per database on key "db:<id>". Health is written with
// an ordinary PUT; placement uses the bulk API, at most 10,000 keys per
// call. The production writer loop (kv_writer.go) projects observed control
// facts directly into these documents.
//
// Every setter canonicalizes and validates so the orchestrator can never
// publish a document the Worker would silently drop: region codes are
// uppercased and checked against the Worker's alphabet, coordinates are
// finite and in range, hosting sets are non-empty, unique, and at most
// twenty regions, and the version and clock stamp are normalized to the
// contract values instead of trusted from the caller.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	// workerHealthKey is the single REGIONS key the Worker caches per PoP.
	workerHealthKey = "regions"

	// workerPlacementPrefix namespaces the producer's immutable database names.
	workerPlacementPrefix = "db:"

	// kvBulkChunk is Cloudflare's bulk limit: 10,000 keys per call.
	kvBulkChunk = 10_000

	// workerMapVersion is the only contract version this code writes and
	// the only one the Worker accepts.
	workerMapVersion = 1

	// maxWorkerHealthRegions mirrors the Worker's ceiling on the health
	// document: D-05 designs for 20 regions, 128 is the parsed cap.
	maxWorkerHealthRegions = 128

	// maxWorkerPlacementRegions mirrors the Worker's placement cap; a
	// database may host at most 20 regions and an empty hosting set is
	// never publishable.
	maxWorkerPlacementRegions = 20

	// maxWorkerResidencyLabel mirrors the Worker's label bound.
	maxWorkerResidencyLabel = 256
)

// WorkerHealthDoc is the REGIONS document, rewritten every 10 seconds and
// on every transition.
type WorkerHealthDoc struct {
	V       int                           `json:"v"`
	Updated int64                         `json:"updated"` // unix seconds, writer clock
	Regions map[string]WorkerRegionHealth `json:"regions"` // keys are region codes
	Catalog []WorkerRegionCatalog         `json:"catalog,omitempty"`
}

// WorkerRegionCatalog is the public, provider-independent Region identity.
type WorkerRegionCatalog struct {
	Code    string  `json:"code"`
	Name    string  `json:"name"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

var publicRegionCatalog = []WorkerRegionCatalog{
	{Code: "GRU", Name: "Sao Paulo", Country: "BR", Lat: -23.43, Lon: -46.47},
	{Code: "SFO", Name: "San Francisco", Country: "US", Lat: 37.37, Lon: -121.92},
	{Code: "FRA", Name: "Frankfurt", Country: "DE", Lat: 50.03, Lon: 8.57},
}

// WorkerRegionHealth is one region inside the health document. Coordinates
// live here so adding a region (D-52) needs no Worker deploy; lag is
// carried for a later policy, not used for routing at launch.
type WorkerRegionHealth struct {
	OK    bool    `json:"ok"`
	LagMS *int    `json:"lag_ms,omitempty"`
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

// WorkerPlacement is one database's PLACEMENT document: the hosting region
// set plus the immutable placement lock (D-52).
type WorkerPlacement struct {
	V   int             `json:"v"`
	R   []string        `json:"r"`
	Res WorkerResidency `json:"res"`
	G   uint64          `json:"g"` // immutable placement-lock generation
	U   int64           `json:"u"` // unix seconds, writer clock
}

// WorkerResidency is the placement lock as it appears on the wire: a named
// lock such as "eu-only", an explicit region list, or null when the
// database is unconstrained. Exactly one of Label/Codes is set; the zero
// value marshals to null.
type WorkerResidency struct {
	Label string
	Codes []string
}

func (r WorkerResidency) MarshalJSON() ([]byte, error) {
	switch {
	case r.Label != "":
		return json.Marshal(r.Label)
	case r.Codes != nil:
		return json.Marshal(r.Codes)
	default:
		return []byte("null"), nil
	}
}

func (r *WorkerResidency) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*r = WorkerResidency{}
		return nil
	}
	var label string
	if err := json.Unmarshal(data, &label); err == nil {
		if label == "" {
			return errors.New("cloudflare: residency label must not be empty")
		}
		r.Label, r.Codes = label, nil
		return nil
	}
	var codes []string
	if err := json.Unmarshal(data, &codes); err == nil {
		r.Label, r.Codes = "", codes
		return nil
	}
	return errors.New("cloudflare: residency must be a label, a region list, or null")
}

// SetWorkerHealth writes the health document with an ordinary PUT.
func (c *Client) SetWorkerHealth(ctx context.Context, doc WorkerHealthDoc) error {
	normalized, err := doc.normalized()
	if err != nil {
		return err
	}
	return putKVJSON(ctx, c, RegionHealthNamespace, workerHealthKey, normalized)
}

// WorkerHealth reads the health document; ErrNotFound when it has never
// been written.
func (c *Client) WorkerHealth(ctx context.Context) (WorkerHealthDoc, error) {
	var doc WorkerHealthDoc
	err := getKVJSON(ctx, c, RegionHealthNamespace, workerHealthKey, &doc)
	return doc, err
}

// SetWorkerPlacements bulk-writes placement documents in sorted database
// order, at most kvBulkChunk keys per API call (design section 8).
func (c *Client) SetWorkerPlacements(ctx context.Context, placements map[string]WorkerPlacement) error {
	if len(placements) == 0 {
		return nil
	}
	normalized := make(map[string]WorkerPlacement, len(placements))
	for database, placement := range placements {
		key, err := workerPlacementKey(database)
		if err != nil {
			return err
		}
		p, err := placement.normalized()
		if err != nil {
			return fmt.Errorf("cloudflare: placement %s: %w", database, err)
		}
		normalized[key] = p
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	type kvPair struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	for start := 0; start < len(keys); start += kvBulkChunk {
		end := min(start+kvBulkChunk, len(keys))
		batch := make([]kvPair, 0, end-start)
		for _, key := range keys[start:end] {
			body, err := json.Marshal(normalized[key])
			if err != nil {
				return fmt.Errorf("cloudflare: encode kv value: %w", err)
			}
			batch = append(batch, kvPair{Key: key, Value: string(body)})
		}
		if err := c.putKVBulk(ctx, DBPlacementNamespace, batch); err != nil {
			return err
		}
	}
	return nil
}

// DeleteWorkerPlacements bulk-deletes placement keys; missing keys are
// ignored by the provider, so removal is idempotent.
func (c *Client) DeleteWorkerPlacements(ctx context.Context, databases []string) error {
	if len(databases) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(databases))
	keys := make([]string, 0, len(databases))
	for _, database := range databases {
		key, err := workerPlacementKey(database)
		if err != nil {
			return err
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for start := 0; start < len(keys); start += kvBulkChunk {
		end := min(start+kvBulkChunk, len(keys))
		if err := c.deleteKVBulk(ctx, DBPlacementNamespace, keys[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// WorkerPlacement reads one database's placement document; ErrNotFound
// when the database has no entry.
func (c *Client) WorkerPlacement(ctx context.Context, database string) (WorkerPlacement, error) {
	key, err := workerPlacementKey(database)
	if err != nil {
		return WorkerPlacement{}, err
	}
	var placement WorkerPlacement
	err = getKVJSON(ctx, c, DBPlacementNamespace, key, &placement)
	return placement, err
}

func (c *Client) putKVBulk(ctx context.Context, namespace string, batch any) error {
	id, err := c.namespaceID(ctx, namespace)
	if err != nil {
		return err
	}
	return c.do(ctx, "bulk put kv "+namespace, http.MethodPut, c.kvBulkPath(id), batch, nil)
}

func (c *Client) deleteKVBulk(ctx context.Context, namespace string, keys []string) error {
	id, err := c.namespaceID(ctx, namespace)
	if err != nil {
		return err
	}
	return c.do(ctx, "bulk delete kv "+namespace, http.MethodDelete, c.kvBulkPath(id), keys, nil)
}

func (c *Client) kvBulkPath(namespaceID string) string {
	return c.accountPath("/storage/kv/namespaces/" + url.PathEscape(namespaceID) + "/bulk")
}

// workerPlacementKey preserves the public API's immutable database name.
// TerraBase control::validate_name owns the 1–63 byte lowercase name contract.
func workerPlacementKey(database string) (string, error) {
	if len(database) < 1 || len(database) > 63 || strings.HasPrefix(database, "-") || strings.HasSuffix(database, "-") {
		return "", errors.New("cloudflare: invalid database name")
	}
	for _, character := range database {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return "", errors.New("cloudflare: invalid database name")
		}
	}
	return workerPlacementPrefix + database, nil
}

func (d WorkerHealthDoc) normalized() (WorkerHealthDoc, error) {
	if d.Updated <= 0 {
		return WorkerHealthDoc{}, errors.New("cloudflare: health document needs a unix-seconds stamp")
	}
	if len(d.Regions) == 0 {
		return WorkerHealthDoc{}, errors.New("cloudflare: health document needs at least one region")
	}
	if len(d.Regions) > maxWorkerHealthRegions {
		return WorkerHealthDoc{}, fmt.Errorf("cloudflare: health document holds at most %d regions", maxWorkerHealthRegions)
	}
	catalog := d.Catalog
	if catalog == nil {
		catalog = publicRegionCatalog
	}
	normalizedCatalog, err := normalizeWorkerCatalog(catalog)
	if err != nil {
		return WorkerHealthDoc{}, err
	}
	out := WorkerHealthDoc{V: workerMapVersion, Updated: d.Updated,
		Regions: make(map[string]WorkerRegionHealth, len(d.Regions)), Catalog: normalizedCatalog}
	for region, entry := range d.Regions {
		code, err := canonicalWorkerRegion(region)
		if err != nil {
			return WorkerHealthDoc{}, fmt.Errorf("cloudflare: health region %q: %w", region, err)
		}
		if _, dup := out.Regions[code]; dup {
			return WorkerHealthDoc{}, fmt.Errorf("cloudflare: health region %q duplicates %s", region, code)
		}
		if err := entry.validate(); err != nil {
			return WorkerHealthDoc{}, fmt.Errorf("cloudflare: health region %s: %w", code, err)
		}
		out.Regions[code] = entry
	}
	return out, nil
}

func normalizeWorkerCatalog(catalog []WorkerRegionCatalog) ([]WorkerRegionCatalog, error) {
	if len(catalog) == 0 || len(catalog) > maxWorkerPlacementRegions {
		return nil, fmt.Errorf("cloudflare: admitted catalog must contain 1..%d regions", maxWorkerPlacementRegions)
	}
	out := make([]WorkerRegionCatalog, 0, len(catalog))
	seen := make(map[string]struct{}, len(catalog))
	for _, entry := range catalog {
		code := strings.ToUpper(strings.TrimSpace(entry.Code))
		if len(code) != 3 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return nil, fmt.Errorf("cloudflare: admitted catalog region %q must be three uppercase letters", entry.Code)
		}
		if _, ok := seen[code]; ok {
			return nil, fmt.Errorf("cloudflare: admitted catalog region %s is duplicated", code)
		}
		if strings.TrimSpace(entry.Name) != entry.Name || entry.Name == "" || len(entry.Name) > 128 {
			return nil, fmt.Errorf("cloudflare: admitted catalog region %s has invalid name", code)
		}
		if len(entry.Country) != 2 || strings.ToUpper(entry.Country) != entry.Country {
			return nil, fmt.Errorf("cloudflare: admitted catalog region %s has invalid country", code)
		}
		if !finite(entry.Lat) || entry.Lat < -90 || entry.Lat > 90 || !finite(entry.Lon) || entry.Lon < -180 || entry.Lon > 180 {
			return nil, fmt.Errorf("cloudflare: admitted catalog region %s has invalid coordinates", code)
		}
		seen[code] = struct{}{}
		out = append(out, WorkerRegionCatalog{Code: code, Name: entry.Name, Country: entry.Country, Lat: entry.Lat, Lon: entry.Lon})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

func (h WorkerRegionHealth) validate() error {
	if !finite(h.Lat) || h.Lat < -90 || h.Lat > 90 {
		return errors.New("lat must be a finite value in [-90, 90]")
	}
	if !finite(h.Lon) || h.Lon < -180 || h.Lon > 180 {
		return errors.New("lon must be a finite value in [-180, 180]")
	}
	if h.LagMS != nil && *h.LagMS < 0 {
		return errors.New("lag must not be negative")
	}
	return nil
}

func (p WorkerPlacement) normalized() (WorkerPlacement, error) {
	if p.U <= 0 {
		return WorkerPlacement{}, errors.New("cloudflare: placement needs a unix-seconds stamp")
	}
	if len(p.R) == 0 {
		return WorkerPlacement{}, errors.New("cloudflare: placement needs at least one hosting region")
	}
	if len(p.R) > maxWorkerPlacementRegions {
		return WorkerPlacement{}, fmt.Errorf("cloudflare: placement holds at most %d regions", maxWorkerPlacementRegions)
	}
	residency, err := p.Res.normalized()
	if err != nil {
		return WorkerPlacement{}, fmt.Errorf("cloudflare: residency: %w", err)
	}
	regions := make([]string, 0, len(p.R))
	seen := make(map[string]struct{}, len(p.R))
	for _, region := range p.R {
		code, err := canonicalWorkerRegion(region)
		if err != nil {
			return WorkerPlacement{}, fmt.Errorf("cloudflare: placement region %q: %w", region, err)
		}
		if _, dup := seen[code]; dup {
			return WorkerPlacement{}, fmt.Errorf("cloudflare: placement region %q duplicates %s", region, code)
		}
		seen[code] = struct{}{}
		regions = append(regions, code)
	}
	if residency.Codes != nil {
		allowed := make(map[string]struct{}, len(residency.Codes))
		for _, code := range residency.Codes {
			allowed[code] = struct{}{}
		}
		for _, code := range regions {
			if _, ok := allowed[code]; !ok {
				return WorkerPlacement{}, fmt.Errorf("cloudflare: placement region %s is outside the immutable residency lock", code)
			}
		}
	}
	sort.Strings(regions) // deterministic bytes: one write shape, no drift churn
	return WorkerPlacement{V: workerMapVersion, R: regions, Res: residency, G: p.G, U: p.U}, nil
}

func (r WorkerResidency) normalized() (WorkerResidency, error) {
	switch {
	case r.Label != "" && r.Codes != nil:
		return WorkerResidency{}, errors.New("carries either a label or a region list, not both")
	case r.Label != "":
		trimmed := strings.TrimSpace(r.Label)
		if trimmed == "" || trimmed != r.Label || len(r.Label) > maxWorkerResidencyLabel {
			return WorkerResidency{}, fmt.Errorf("label must be a trimmed string of at most %d characters", maxWorkerResidencyLabel)
		}
		return WorkerResidency{Label: r.Label}, nil
	case r.Codes != nil:
		if len(r.Codes) == 0 {
			return WorkerResidency{}, errors.New("region list must not be empty")
		}
		codes := make([]string, 0, len(r.Codes))
		seen := make(map[string]struct{}, len(r.Codes))
		for _, region := range r.Codes {
			code, err := canonicalWorkerRegion(region)
			if err != nil {
				return WorkerResidency{}, err
			}
			if _, dup := seen[code]; dup {
				return WorkerResidency{}, fmt.Errorf("region %q duplicates %s", region, code)
			}
			seen[code] = struct{}{}
			codes = append(codes, code)
		}
		sort.Strings(codes)
		return WorkerResidency{Codes: codes}, nil
	default:
		return WorkerResidency{}, nil // unconstrained: null on the wire
	}
}

// canonicalWorkerRegion uppercases a region code and checks it against the
// Worker's alphabet (ts-proxy src/geo.ts): 1-16 characters of A-Z, 0-9,
// and '-', never '-' first.
func canonicalWorkerRegion(region string) (string, error) {
	code := strings.ToUpper(region)
	if len(code) == 0 || len(code) > 16 {
		return "", errors.New("region code must be 1-16 characters")
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-' && i > 0:
			// The Worker's alphabet: A-Z, 0-9, and '-' never first.
		default:
			return "", errors.New("region code may hold only A-Z, 0-9, and '-'")
		}
	}
	return code, nil
}

func finite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
