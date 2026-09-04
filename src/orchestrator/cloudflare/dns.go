package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// DNSRecord is the declared record (ID empty) and the observed one. TTL 1 is
// Cloudflare "auto"; every TerraScale record is proxied.
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// DNSAPI is the Cloudflare surface the DNS reconciler needs.
type DNSAPI interface {
	ListDNSRecords(ctx context.Context) ([]DNSRecord, error)
	CreateDNSRecord(ctx context.Context, rec DNSRecord) error
	UpdateDNSRecord(ctx context.Context, rec DNSRecord) error // rec.ID required
	DeleteDNSRecord(ctx context.Context, id string) error
}

var _ DNSAPI = (*Client)(nil)

func (c *Client) ListDNSRecords(ctx context.Context) ([]DNSRecord, error) {
	var all []DNSRecord
	for page := 1; ; page++ {
		var records []DNSRecord
		suffix := "/dns_records?per_page=100"
		if page > 1 {
			suffix = fmt.Sprintf("/dns_records?per_page=100&page=%d", page)
		}
		path := c.zonePath(suffix)
		info, err := c.doPage(ctx, "list dns records", http.MethodGet, path, nil, &records)
		if err != nil {
			return nil, err
		}
		all = append(all, records...)
		if info == nil || info.TotalPages <= page || info.TotalPages <= 0 {
			return all, nil
		}
	}
}

func (c *Client) CreateDNSRecord(ctx context.Context, rec DNSRecord) error {
	var created DNSRecord
	return c.do(ctx, "create dns record", http.MethodPost, c.zonePath("/dns_records"), rec, &created)
}

func (c *Client) UpdateDNSRecord(ctx context.Context, rec DNSRecord) error {
	path := c.zonePath("/dns_records/" + url.PathEscape(rec.ID))
	return c.do(ctx, "update dns record", http.MethodPatch, path, rec, nil)
}

func (c *Client) DeleteDNSRecord(ctx context.Context, id string) error {
	path := c.zonePath("/dns_records/" + url.PathEscape(id))
	return c.do(ctx, "delete dns record", http.MethodDelete, path, nil, nil)
}

func (z *Zone) reconcileDNS(ctx context.Context, c *Client, p *Plan) error {
	api := DNSAPI(c)
	live, err := api.ListDNSRecords(ctx)
	if err != nil {
		return err
	}
	// Cloudflare-managed NS/SOA records are never ours to reconcile.
	managed := make([]DNSRecord, 0, len(live))
	for _, rec := range live {
		if rec.Type == "NS" || rec.Type == "SOA" {
			continue
		}
		managed = append(managed, rec)
	}
	// Identity is (name, type, content): multi-A record sets for sync.api
	// and the region hostnames are keyed per address, so a replaced member
	// is one delete plus one create.
	key := func(r DNSRecord) string { return r.Name + "\x00" + r.Type + "\x00" + r.Content }
	eq := func(a, b DNSRecord) bool { return a.TTL == b.TTL && a.Proxied == b.Proxied }
	creates, deletes, updates := diff(managed, z.DNSRecords, key, eq)
	for _, rec := range creates {
		rec := rec
		p.Changes = append(p.Changes, Change{Action: Create, Resource: "dns-record",
			Ref:    rec.Type + " " + rec.Name,
			Detail: fmt.Sprintf("%s %s -> %s proxied=%v", rec.Type, rec.Name, rec.Content, rec.Proxied),
			apply:  func(ctx context.Context) error { return api.CreateDNSRecord(ctx, rec) }})
	}
	for _, u := range updates {
		want := u.Want
		want.ID = u.Live.ID
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "dns-record",
			Ref:    want.Type + " " + want.Name,
			Detail: fmt.Sprintf("%s %s -> %s proxied=%v", want.Type, want.Name, want.Content, want.Proxied),
			apply:  func(ctx context.Context) error { return api.UpdateDNSRecord(ctx, want) }})
	}
	for _, rec := range deletes {
		id := rec.ID
		p.Changes = append(p.Changes, Change{Action: Delete, Resource: "dns-record",
			Ref:    rec.Type + " " + rec.Name,
			Detail: fmt.Sprintf("%s %s -> %s", rec.Type, rec.Name, rec.Content),
			apply:  func(ctx context.Context) error { return api.DeleteDNSRecord(ctx, id) }})
	}
	return nil
}
