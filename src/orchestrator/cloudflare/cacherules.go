package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The D-14 reactive surface below the reactive prefix (the ts-proxy design
// §16 route contract): view attach is a POST served by members and never
// cache-eligible; the cache-eligible leaves are exactly the delta log and
// the immutable snapshot chunks.
const (
	reactiveViewsPath    = "/api/v1/reactive/views/"
	reactiveLogLeaf      = "/log"
	reactiveSnapshotPart = "/snapshot/"
)

// CacheRule declares one Cloudflare Cache Rule (D-55): the reactive snapshot
// and log paths on sync.api are cache-eligible. Edge TTL respects the origin
// because the D-14 contract already speaks for itself — data-bearing
// responses carry their immutable retention TTL, long-poll timeouts are
// no-store — and the cache lock plus Smart Tiered Cache do the collapsing.
type CacheRule struct {
	Ref         string
	Hostname    string
	PathPrefix  string
	PathSuffix  string // optional leaf matched with ends_with (the /log leaf)
	PathSegment string // optional segment matched with contains (the /snapshot/<n> chunks)
	Eligible    bool
	EdgeTTLMode string // "respect_origin" or "override_origin"
}

func (r CacheRule) rule() Rule {
	params, _ := json.Marshal(map[string]any{
		"cache":    r.Eligible,
		"edge_ttl": map[string]any{"mode": r.EdgeTTLMode},
	})
	return Rule{Ref: r.Ref, Expression: r.expression(),
		Action: "set_cache_settings", ActionParameters: params, Enabled: true}
}

// expression anchors the rule to the host and prefix and, when leaves are
// declared, admits exactly them: everything else under the prefix — attach
// POSTs, unknown paths — stays at Cloudflare's default (not eligible). The
// capability header never enters the cache key (D-14) and the Snippet strips
// it before the fetch (D-55), so path matching is the whole cache-key story.
func (r CacheRule) expression() string {
	conds := []string{
		fmt.Sprintf("http.host eq %q", r.Hostname),
		fmt.Sprintf("starts_with(http.request.uri.path, %q)", r.PathPrefix),
	}
	var leaves []string
	if r.PathSuffix != "" {
		leaves = append(leaves, fmt.Sprintf("ends_with(http.request.uri.path, %q)", r.PathSuffix))
	}
	if r.PathSegment != "" {
		leaves = append(leaves, fmt.Sprintf("contains(http.request.uri.path, %q)", r.PathSegment))
	}
	switch len(leaves) {
	case 1:
		conds = append(conds, leaves[0])
	case 2:
		conds = append(conds, "("+strings.Join(leaves, " or ")+")")
	}
	return "(" + strings.Join(conds, " and ") + ")"
}

func hostPathExpression(host, prefix string) string {
	return fmt.Sprintf("(http.host eq %q and starts_with(http.request.uri.path, %q))", host, prefix)
}

// TieredCacheAPI toggles Smart Tiered Cache, which bounds origin fills
// across PoPs (D-55).
type TieredCacheAPI interface {
	SmartTieredCache(ctx context.Context) (bool, error)
	SetSmartTieredCache(ctx context.Context, on bool) error
}

var _ TieredCacheAPI = (*Client)(nil)

func (c *Client) SmartTieredCache(ctx context.Context) (bool, error) {
	var result struct {
		Value string `json:"value"`
	}
	err := c.do(ctx, "get tiered cache", http.MethodGet, c.zonePath("/cache/tiered_cache_smart_topology_enable"), nil, &result)
	return result.Value == "on", err
}

func (c *Client) SetSmartTieredCache(ctx context.Context, on bool) error {
	value := "off"
	if on {
		value = "on"
	}
	return c.do(ctx, "set tiered cache", http.MethodPut, c.zonePath("/cache/tiered_cache_smart_topology_enable"),
		map[string]string{"value": value}, nil)
}

func (z *Zone) reconcileCache(ctx context.Context, c *Client, p *Plan) error {
	rules := make([]Rule, 0, len(z.CacheRules))
	for _, r := range z.CacheRules {
		rules = append(rules, r.rule())
	}
	if err := reconcilePhase(ctx, c, p, "http_request_cache_settings", "cache-rule", rules); err != nil {
		return err
	}
	on, err := TieredCacheAPI(c).SmartTieredCache(ctx)
	if err != nil {
		return err
	}
	if on != z.SmartTieredCache {
		want := z.SmartTieredCache
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "tiered-cache", Ref: "smart-topology",
			Detail: fmt.Sprintf("smart tiered cache -> %v", want),
			apply:  func(ctx context.Context) error { return c.SetSmartTieredCache(ctx, want) }})
	}
	return nil
}
