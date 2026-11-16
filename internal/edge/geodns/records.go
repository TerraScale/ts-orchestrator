package geodns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type record struct {
	Domain     string `json:"domain"`
	Rtype      string `json:"rtype"`
	Rdata      string `json:"rdata"`
	TTL        int    `json:"ttl"`
	RecordHash string `json:"recordHash,omitempty"`
}

type operation struct {
	record
	Operation string `json:"operation"`
}

func (c *Client) snapshot(ctx context.Context, zone string) ([]record, string, error) {
	var all []record
	query := url.Values{}
	etag := ""
	for {
		var page struct{ Items []record }
		headers, err := c.request(ctx, http.MethodGet, c.dns+"/zones/"+zone+"/records?"+query.Encode(), "", nil, &page)
		if err != nil {
			return nil, "", err
		}
		if etag != "" && etag != headers.Get("etag") {
			return nil, "", fmt.Errorf("zone changed during record pagination")
		}
		etag = headers.Get("etag")
		for i := range page.Items {
			page.Items[i].Domain = strings.ToLower(strings.TrimSuffix(page.Items[i].Domain, "."))
			page.Items[i].Rtype = strings.ToUpper(page.Items[i].Rtype)
		}
		all = append(all, page.Items...)
		if headers.Get("opc-next-page") == "" {
			return all, etag, nil
		}
		query.Set("page", headers.Get("opc-next-page"))
	}
}

func (c *Client) records(ctx context.Context, cfg Config, zone string, apply bool, admit func(Change) error) ([]Change, error) {
	have, etag, err := c.snapshot(ctx, zone)
	if err != nil {
		return nil, err
	}
	var changes []Change
	var ops []operation
	wanted := map[string]Region{}
	for _, r := range cfg.Regions {
		wanted[r.APIName] = r
	}
	prefix := "ts-orchestrator " + cfg.Owner + " " + cfg.Cell + "/dns-record/"
	current := map[string]record{}
	for _, r := range have {
		if r.Rtype != "TXT" || !strings.HasPrefix(r.Domain, "_ts-orch.") || !strings.HasPrefix(strings.Trim(r.Rdata, "\""), prefix) {
			continue
		}
		domain := strings.TrimPrefix(r.Domain, "_ts-orch.")
		if _, ok := current[domain]; ok {
			return changes, fmt.Errorf("duplicate ownership record for %s", domain)
		}
		current[domain] = r
	}
	for domain, marker := range current {
		parts := strings.Fields(strings.Trim(marker.Rdata, "\""))
		if len(parts) != 4 || parts[2] != cfg.key("dns-record", strings.TrimSuffix(domain, ".api."+cfg.Zone)).String() {
			return changes, fmt.Errorf("invalid record ownership at %s", marker.Domain)
		}
		var actual []record
		for _, r := range have {
			if r.Domain == domain && (r.Rtype == "A" || r.Rtype == "AAAA" || r.Rtype == "CNAME") {
				actual = append(actual, r)
			}
		}
		if len(actual) != 1 || actual[0].Rtype != "A" || actual[0].Rdata != parts[3] {
			return changes, fmt.Errorf("owned record %s was changed outside the DNS pass", domain)
		}
		want, exists := wanted[domain]
		if exists && actual[0].Rdata == want.IP && actual[0].TTL == cfg.TTL && marker.TTL == cfg.TTL {
			changes = append(changes, Change{Action: "ok", Kind: "dns-record", Name: domain})
			delete(wanted, domain)
			continue
		}
		ops = append(ops, operation{record: actual[0], Operation: "REMOVE"}, operation{record: marker, Operation: "REMOVE"})
		verb := "removed"
		if exists {
			verb = "updated"
		}
		if !apply {
			verb = "differs"
		}
		if err := admit(Change{Action: "update", Kind: "dns-record", Name: domain}); err != nil {
			return changes, err
		}
		changes = append(changes, Change{Action: verb, Kind: "dns-record", Name: domain})
	}
	for domain, r := range wanted {
		if _, owned := current[domain]; !owned {
			for _, h := range have {
				if h.Domain == domain && (h.Rtype == "A" || h.Rtype == "AAAA" || h.Rtype == "CNAME") || h.Domain == "_ts-orch."+domain {
					return changes, fmt.Errorf("foreign record at %s or its ownership name", domain)
				}
			}
			verb := "missing"
			if apply {
				verb = "created"
			}
			if err := admit(Change{Action: "create", Kind: "dns-record", Name: domain}); err != nil {
				return changes, err
			}
			changes = append(changes, Change{Action: verb, Kind: "dns-record", Name: domain})
		}
		ops = append(ops,
			operation{record: record{Domain: domain, Rtype: "A", Rdata: r.IP, TTL: cfg.TTL}, Operation: "ADD"},
			operation{record: record{Domain: "_ts-orch." + domain, Rtype: "TXT", Rdata: fmt.Sprintf("%q", "ts-orchestrator "+cfg.Owner+" "+cfg.key("dns-record", r.Label).String()+" "+r.IP), TTL: cfg.TTL}, Operation: "ADD"})
	}
	if apply && len(ops) > 0 {
		if etag == "" {
			return changes, fmt.Errorf("no zone-record etag")
		}
		_, err = c.request(ctx, http.MethodPatch, c.dns+"/zones/"+zone+"/records", etag, map[string]any{"items": ops}, nil)
	}
	return changes, err
}
