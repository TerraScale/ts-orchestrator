package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	// Tags is Cloudflare's native ownership marker.  A deterministic name is
	// not ownership evidence: records without DNSOwnershipTag are foreign.
	Tags []string `json:"tags,omitempty"`
}

const DNSOwnershipTag = "terrascale-managed"

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
	if !validCloudflareResourceID(id) {
		return fmt.Errorf("cloudflare: dns record identity is invalid")
	}
	path := c.zonePath("/dns_records/" + url.PathEscape(id))
	return c.do(ctx, "delete dns record", http.MethodDelete, path, nil, nil)
}

func (z *Zone) reconcileDNS(ctx context.Context, c *Client, p *Plan) error {
	api := DNSAPI(c)
	live, err := api.ListDNSRecords(ctx)
	if err != nil {
		return err
	}
	// Cloudflare-managed NS/SOA records are never ours to reconcile.  Every
	// other untagged record is also foreign: an accidental matching name must
	// not grant deletion authority.
	managed := make([]DNSRecord, 0, len(live))
	foreignKeys := make(map[string]bool)
	for _, rec := range live {
		if rec.Type == "NS" || rec.Type == "SOA" {
			continue
		}
		if dnsRecordOwned(rec, z.ZoneName) {
			managed = append(managed, rec)
		} else {
			foreignKeys[rec.Name+"\x00"+rec.Type+"\x00"+rec.Content] = true
			foreign := rec
			p.Changes = append(p.Changes, Change{Action: Alert, Resource: "dns-record",
				Ref:    foreign.Type + " " + foreign.Name,
				Detail: fmt.Sprintf("preserving unowned DNS record %s %s -> %s", foreign.Type, foreign.Name, foreign.Content)})
		}
	}
	// Identity is (name, type, content): multi-A record sets for sync.api
	// and the region hostnames are keyed per address, so a replaced member
	// is one delete plus one create.
	key := func(r DNSRecord) string { return r.Name + "\x00" + r.Type + "\x00" + r.Content }
	eq := func(a, b DNSRecord) bool { return a.TTL == b.TTL && a.Proxied == b.Proxied }
	want := make([]DNSRecord, 0, len(z.DNSRecords))
	for _, rec := range z.DNSRecords {
		rec.Tags = appendOwnershipTag(rec.Tags)
		want = append(want, rec)
	}
	creates, deletes, updates := diff(managed, want, key, eq)
	filteredCreates := creates[:0]
	for _, rec := range creates {
		if !foreignKeys[key(rec)] {
			filteredCreates = append(filteredCreates, rec)
		}
	}
	creates = filteredCreates
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
		expected := rec
		p.Changes = append(p.Changes, Change{Action: Delete, Resource: "dns-record",
			Ref:    rec.Type + " " + rec.Name,
			Detail: fmt.Sprintf("%s %s -> %s", rec.Type, rec.Name, rec.Content),
			apply: func(ctx context.Context) error {
				// The plan is only an observation.  Re-read before deletion so a
				// replaced record cannot be deleted through a stale ID.
				current, err := api.ListDNSRecords(ctx)
				if err != nil {
					return err
				}
				for _, candidate := range current {
					if candidate.ID != id {
						continue
					}
					if !dnsRecordOwned(candidate, z.ZoneName) || !sameDNSRecord(candidate, expected) {
						return fmt.Errorf("cloudflare: refusing stale or unowned DNS deletion for %s", id)
					}
					return api.DeleteDNSRecord(ctx, id)
				}
				return nil // already absent is a safe idempotent outcome
			}})
	}
	return nil
}

func appendOwnershipTag(tags []string) []string {
	for _, tag := range tags {
		if tag == DNSOwnershipTag {
			return append([]string(nil), tags...)
		}
	}
	return append(append([]string(nil), tags...), DNSOwnershipTag)
}

func dnsRecordOwned(record DNSRecord, zone string) bool {
	if !validDNSName(record.Name, zone) || !validCloudflareResourceID(record.ID) {
		return false
	}
	for _, tag := range record.Tags {
		if tag == DNSOwnershipTag {
			return true
		}
	}
	return false
}

func validDNSName(name, zone string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if name == "" || zone == "" || strings.ContainsAny(name+zone, "\r\n/\\?") {
		return false
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func validCloudflareResourceID(id string) bool {
	if len(id) == 0 || len(id) > 128 || strings.ContainsAny(id, "\r\n/\\?#") {
		return false
	}
	return true
}

func sameDNSRecord(a, b DNSRecord) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Name == b.Name && a.Content == b.Content &&
		a.TTL == b.TTL && a.Proxied == b.Proxied && sameStrings(a.Tags, b.Tags)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
