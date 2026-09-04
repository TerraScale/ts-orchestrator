package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// SSLSettings declares the zone TLS posture. Universal SSL covers
// terrascale.tech and *.terrascale.tech only; the two-label reactive and
// region hostnames (sync.api., gru.api., ...) need Total TLS on top of the
// Advanced Certificate Manager add-on — Pro-compatible, no Enterprise
// features (D-63); buying the add-on is the owner's step O-4. Cloudflare for
// SaaS custom hostnames are Enterprise-only and deliberately absent.
type SSLSettings struct {
	Mode           string // zone "ssl" setting; "strict" = Full (strict)
	MinTLSVersion  string // zone "min_tls_version"
	TLS13          bool   // zone "tls_1_3"
	AlwaysUseHTTPS bool   // zone "always_use_https"
}

type settingItem struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func (s SSLSettings) items() []settingItem {
	tls13, https := "off", "off"
	if s.TLS13 {
		tls13 = "on"
	}
	if s.AlwaysUseHTTPS {
		https = "on"
	}
	return []settingItem{
		{ID: "ssl", Value: s.Mode},
		{ID: "min_tls_version", Value: s.MinTLSVersion},
		{ID: "tls_1_3", Value: tls13},
		{ID: "always_use_https", Value: https},
	}
}

// ZoneSettingsAPI is the zone-settings surface.
type ZoneSettingsAPI interface {
	ZoneSettings(ctx context.Context) (map[string]string, error)
	PatchZoneSettings(ctx context.Context, items []settingItem) error
}

var _ ZoneSettingsAPI = (*Client)(nil)

func (c *Client) ZoneSettings(ctx context.Context) (map[string]string, error) {
	var result []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	if err := c.do(ctx, "list zone settings", http.MethodGet, c.zonePath("/settings"), nil, &result); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(result))
	for _, item := range result {
		var value string
		if json.Unmarshal(item.Value, &value) == nil {
			out[item.ID] = value
		}
	}
	return out, nil
}

func (c *Client) PatchZoneSettings(ctx context.Context, items []settingItem) error {
	return c.do(ctx, "patch zone settings", http.MethodPatch, c.zonePath("/settings"),
		map[string]any{"items": items}, nil)
}

type TotalTLS struct {
	Enabled              bool   `json:"enabled"`
	CertificateAuthority string `json:"certificate_authority"`
}

// TotalTLSAPI manages Total TLS (all proxied hostnames get certificates,
// including the multi-label ones).
type TotalTLSAPI interface {
	GetTotalTLS(ctx context.Context) (TotalTLS, error)
	SetTotalTLS(ctx context.Context, enabled bool) error
}

var _ TotalTLSAPI = (*Client)(nil)

func (c *Client) GetTotalTLS(ctx context.Context) (TotalTLS, error) {
	var out TotalTLS
	err := c.do(ctx, "get total tls", http.MethodGet, c.zonePath("/ssl/total_tls"), nil, &out)
	return out, err
}

func (c *Client) SetTotalTLS(ctx context.Context, enabled bool) error {
	body := TotalTLS{Enabled: enabled}
	return c.do(ctx, "set total tls", http.MethodPost, c.zonePath("/ssl/total_tls"), body, nil)
}

func (z *Zone) reconcileSSL(ctx context.Context, c *Client, p *Plan) error {
	live, err := ZoneSettingsAPI(c).ZoneSettings(ctx)
	if err != nil {
		return err
	}
	for _, item := range z.SSL.items() {
		if live[item.ID] == item.Value {
			continue
		}
		item := item
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "zone-setting", Ref: item.ID,
			Detail: fmt.Sprintf("%s -> %s", item.ID, item.Value),
			apply:  func(ctx context.Context) error { return c.PatchZoneSettings(ctx, []settingItem{item}) }})
	}
	tls, err := c.GetTotalTLS(ctx)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) &&
			(apiErr.Status == http.StatusForbidden || apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusPaymentRequired) {
			// Advanced Certificate Manager not on the zone yet (owner step
			// O-4): surface it, do not fail the whole pass.
			p.Changes = append(p.Changes, Change{Action: Alert, Resource: "total-tls", Ref: "total-tls",
				Detail: "certificate add-on unavailable; multi-label hostnames (sync.api., <region>.api.) cannot get certificates until it is enabled (O-4)"})
			return nil
		}
		return err
	}
	if tls.Enabled != z.TotalTLS {
		want := z.TotalTLS
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "total-tls", Ref: "total-tls",
			Detail: fmt.Sprintf("total tls enabled=%v", want),
			apply:  func(ctx context.Context) error { return c.SetTotalTLS(ctx, want) }})
	}
	return nil
}
