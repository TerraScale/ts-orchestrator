package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func dnsZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", DNSRecords: []DNSRecord{
		{Type: "A", Name: "api.terrascale.tech", Content: "192.0.2.1", TTL: 1, Proxied: true},
		{Type: "A", Name: "sync.api.terrascale.tech", Content: "198.51.100.10", TTL: 1, Proxied: true},
	}}
}

func TestDNSReconcile(t *testing.T) {
	cases := []struct {
		name       string
		live       string // GET dns_records result
		wantPlan   []string
		wantMethod []string // methods after apply, in order (GET excluded)
	}{
		{
			name:       "create from empty zone",
			live:       `[]`,
			wantPlan:   []string{"create dns-record A api.terrascale.tech -> 192.0.2.1 proxied=true", "create dns-record A sync.api.terrascale.tech -> 198.51.100.10 proxied=true"},
			wantMethod: []string{http.MethodPost, http.MethodPost},
		},
		{
			name:     "no-op when declared",
			live:     `[{"id":"r1","type":"A","name":"api.terrascale.tech","content":"192.0.2.1","ttl":1,"proxied":true,"tags":["terrascale-managed"]},{"id":"r2","type":"A","name":"sync.api.terrascale.tech","content":"198.51.100.10","ttl":1,"proxied":true,"tags":["terrascale-managed"]}]`,
			wantPlan: nil,
		},
		{
			name:       "drift on proxied flag is repaired by update",
			live:       `[{"id":"r1","type":"A","name":"api.terrascale.tech","content":"192.0.2.1","ttl":1,"proxied":false,"tags":["terrascale-managed"]},{"id":"r2","type":"A","name":"sync.api.terrascale.tech","content":"198.51.100.10","ttl":1,"proxied":true,"tags":["terrascale-managed"]}]`,
			wantPlan:   []string{"update dns-record A api.terrascale.tech -> 192.0.2.1 proxied=true"},
			wantMethod: []string{http.MethodPatch},
		},
		{
			// Ownership is the tag, not the name: an owned but undeclared
			// record is deleted, an unowned record is preserved with an
			// alert (D-67: deletion authority must be proven).
			name: "owned orphan deleted; unowned record preserved with an alert",
			live: `[{"id":"r1","type":"A","name":"api.terrascale.tech","content":"192.0.2.1","ttl":1,"proxied":true,"tags":["terrascale-managed"]},` +
				`{"id":"r2","type":"A","name":"sync.api.terrascale.tech","content":"198.51.100.10","ttl":1,"proxied":true,"tags":["terrascale-managed"]},` +
				`{"id":"old","type":"CNAME","name":"legacy.terrascale.tech","content":"elsewhere.example","ttl":3600,"proxied":true,"tags":["terrascale-managed"]},` +
				`{"id":"fx","type":"A","name":"stray.terrascale.tech","content":"203.0.113.99","ttl":3600,"proxied":true}]`,
			wantPlan: []string{
				"alert dns-record preserving unowned DNS record A stray.terrascale.tech -> 203.0.113.99",
				"delete dns-record CNAME legacy.terrascale.tech -> elsewhere.example",
			},
			wantMethod: []string{http.MethodDelete},
		},
		{
			name: "replaced member is one delete and one create",
			live: `[{"id":"r1","type":"A","name":"api.terrascale.tech","content":"192.0.2.1","ttl":1,"proxied":true,"tags":["terrascale-managed"]},` +
				`{"id":"r2","type":"A","name":"sync.api.terrascale.tech","content":"198.51.100.99","ttl":1,"proxied":true,"tags":["terrascale-managed"]}]`,
			wantPlan: []string{
				"create dns-record A sync.api.terrascale.tech -> 198.51.100.10 proxied=true",
				"delete dns-record A sync.api.terrascale.tech -> 198.51.100.99",
			},
			wantMethod: []string{http.MethodPost, http.MethodDelete},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
				switch call.Method {
				case http.MethodGet:
					return okEnvelope(tc.live)
				case http.MethodPost, http.MethodPatch, http.MethodDelete:
					methods = append(methods, call.Method)
					return okEnvelope(`{"id":"new"}`)
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected")
			})
			z := dnsZone()
			p := &Plan{}
			if err := z.reconcileDNS(context.Background(), c, p); err != nil {
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
			// The observe list plus one re-observation before every delete.
			relists := 0
			for _, m := range tc.wantMethod {
				if m == http.MethodDelete {
					relists++
				}
			}
			if len(tc.wantMethod) > 0 && len(ft.recorded()) != len(tc.wantMethod)+1+relists {
				t.Fatalf("unexpected call count: %d", len(ft.recorded()))
			}
		})
	}
}

func TestDNSIgnoresCloudflareManagedRecords(t *testing.T) {
	live := `[{"id":"ns1","type":"NS","name":"terrascale.tech","content":"beth.ns.cloudflare.com"},{"id":"soa","type":"SOA","name":"terrascale.tech","content":"..."}]`
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		if call.Method == http.MethodGet {
			return okEnvelope(live)
		}
		t.Errorf("NS/SOA must never be mutated, saw %v", call)
		return okEnvelope("null")
	})
	z := dnsZone()
	p := &Plan{}
	if err := z.reconcileDNS(context.Background(), c, p); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	// Only the two declared creates; no deletes for NS/SOA.
	if len(p.Changes) != 2 {
		t.Fatalf("want 2 creates, got %v", summarize(p))
	}
	for _, ch := range p.Changes {
		if ch.Action == Delete {
			t.Fatalf("NS/SOA deletion planned: %v", summarize(p))
		}
	}
}

func TestDNSAPIErrorFailsTheStep(t *testing.T) {
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		return failEnvelope(http.StatusInternalServerError, 999, "boom")
	})
	z := dnsZone()
	if err := z.reconcileDNS(context.Background(), c, &Plan{}); err == nil {
		t.Fatal("observe errors must fail the step")
	}
}
