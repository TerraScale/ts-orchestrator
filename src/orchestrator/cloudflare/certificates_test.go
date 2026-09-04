package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func sslZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", TotalTLS: true,
		SSL: SSLSettings{Mode: "strict", MinTLSVersion: "1.2", TLS13: true, AlwaysUseHTTPS: true}}
}

func settingsEnvelope() string {
	return `[{"id":"ssl","value":"strict"},{"id":"min_tls_version","value":"1.2"},{"id":"tls_1_3","value":"on"},` +
		`{"id":"always_use_https","value":"on"},{"id":"brotli","value":"on"},{"id":"0rtt","value":"off"}]`
}

func TestSSLSettingsReconcile(t *testing.T) {
	cases := []struct {
		name     string
		live     string
		wantPlan []string
	}{
		{
			name: "no-op when declared",
			live: settingsEnvelope(),
		},
		{
			name: "downgraded TLS posture is repaired setting by setting",
			live: `[{"id":"ssl","value":"flexible"},{"id":"min_tls_version","value":"1.0"},{"id":"tls_1_3","value":"off"},{"id":"always_use_https","value":"off"}]`,
			wantPlan: []string{
				"update zone-setting ssl -> strict",
				"update zone-setting min_tls_version -> 1.2",
				"update zone-setting tls_1_3 -> on",
				"update zone-setting always_use_https -> on",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var patches []string
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch {
				case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/settings"):
					return okEnvelope(tc.live)
				case call.Method == http.MethodPatch:
					patches = append(patches, call.Body)
					return okEnvelope("null")
				case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/ssl/total_tls"):
					return okEnvelope(`{"enabled":true,"certificate_authority":"google"}`)
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
			})
			z := sslZone()
			p := &Plan{}
			if err := z.reconcileSSL(context.Background(), c, p); err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}
			if got := summarize(p); !reflect.DeepEqual(got, tc.wantPlan) {
				t.Fatalf("plan = %v\nwant %v", got, tc.wantPlan)
			}
			if err := Apply(context.Background(), p); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			if len(patches) != len(tc.wantPlan) {
				t.Fatalf("patches = %v, want %d", patches, len(tc.wantPlan))
			}
		})
	}
}

func TestTotalTLSReconcile(t *testing.T) {
	t.Run("drift on total tls is repaired", func(t *testing.T) {
		var posts []string
		c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
			switch {
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/settings"):
				return okEnvelope(settingsEnvelope())
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/ssl/total_tls"):
				return okEnvelope(`{"enabled":false,"certificate_authority":""}`)
			case call.Method == http.MethodPost:
				posts = append(posts, call.Body)
				return okEnvelope(`{"enabled":true}`)
			}
			return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
		})
		z := sslZone()
		p := &Plan{}
		if err := z.reconcileSSL(context.Background(), c, p); err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		want := []string{"update total-tls total tls enabled=true"}
		if got := summarize(p); !reflect.DeepEqual(got, want) {
			t.Fatalf("plan = %v, want %v", got, want)
		}
		if err := Apply(context.Background(), p); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if len(posts) != 1 || !strings.Contains(posts[0], `"enabled":true`) {
			t.Fatalf("posts = %v", posts)
		}
	})

	t.Run("certificate add-on not purchased is an alert, not a failed pass (O-4)", func(t *testing.T) {
		c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
			switch {
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/settings"):
				return okEnvelope(settingsEnvelope())
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/ssl/total_tls"):
				return failEnvelope(http.StatusForbidden, 10062, "advanced certificate manager is required")
			}
			return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
		})
		z := sslZone()
		p := &Plan{}
		if err := z.reconcileSSL(context.Background(), c, p); err != nil {
			t.Fatalf("the whole pass must not fail on a missing add-on: %v", err)
		}
		if len(p.Changes) != 1 || p.Changes[0].Action != Alert {
			t.Fatalf("want one alert, got %v", summarize(p))
		}
		if err := Apply(context.Background(), p); err != nil {
			t.Fatalf("alerts are skipped by apply: %v", err)
		}
	})

	t.Run("add-on alert names every hostname without certificate coverage", func(t *testing.T) {
		c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
			switch {
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/settings"):
				return okEnvelope(settingsEnvelope())
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/ssl/total_tls"):
				return failEnvelope(http.StatusPaymentRequired, 10062, "advanced certificate manager is required")
			}
			return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
		})
		z := sslZone()
		z.DNSRecords = []DNSRecord{
			{Name: "terrascale.tech"},
			{Name: "api.terrascale.tech"},
			{Name: "sync.api.terrascale.tech"},
			{Name: "gru.api.terrascale.tech"},
			{Name: "gru.api.terrascale.tech"}, // duplicates collapse
			{Name: "fra.api.terrascale.tech"},
		}
		p := &Plan{}
		if err := z.reconcileSSL(context.Background(), c, p); err != nil {
			t.Fatal(err)
		}
		if len(p.Changes) != 1 || p.Changes[0].Action != Alert {
			t.Fatalf("want one alert, got %v", summarize(p))
		}
		detail := p.Changes[0].Detail
		want := "certificate add-on unavailable (O-4); 3 hostname(s) have no certificate coverage: " +
			"fra.api.terrascale.tech, gru.api.terrascale.tech, sync.api.terrascale.tech"
		if detail != want {
			t.Fatalf("alert detail = %q\nwant %q", detail, want)
		}
	})

	t.Run("declaring total tls off while serving multi-label hostnames is a coverage alert", func(t *testing.T) {
		c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
			switch {
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/settings"):
				return okEnvelope(settingsEnvelope())
			case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/ssl/total_tls"):
				return okEnvelope(`{"enabled":true,"certificate_authority":"google"}`)
			}
			return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
		})
		z := sslZone()
		z.TotalTLS = false
		z.DNSRecords = []DNSRecord{{Name: "api.terrascale.tech"}, {Name: "sfo.api.terrascale.tech"}}
		p := &Plan{}
		if err := z.reconcileSSL(context.Background(), c, p); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"update total-tls total tls enabled=false",
			"alert total-tls total tls is declared off; 1 hostname(s) have no certificate coverage: sfo.api.terrascale.tech",
		}
		if got := summarize(p); !reflect.DeepEqual(got, want) {
			t.Fatalf("plan = %v\nwant %v", got, want)
		}
	})
}

func TestUniversalSSLCovers(t *testing.T) {
	cases := []struct {
		hostname string
		want     bool
	}{
		{hostname: "terrascale.tech", want: true},
		{hostname: "api.terrascale.tech", want: true},
		{hostname: "app.terrascale.tech", want: true},
		{hostname: "sync.api.terrascale.tech", want: false},
		{hostname: "gru.api.terrascale.tech", want: false},
		{hostname: "terrascale.tech.evil.example", want: false},
		{hostname: "other.example", want: false},
	}
	for _, tc := range cases {
		if got := universalSSLCovers(tc.hostname, "terrascale.tech"); got != tc.want {
			t.Errorf("universalSSLCovers(%q) = %v, want %v", tc.hostname, got, tc.want)
		}
	}
	z := &Zone{ZoneName: "terrascale.tech", DNSRecords: []DNSRecord{
		{Name: "terrascale.tech"}, {Name: "api.terrascale.tech"}, {Name: "sync.api.terrascale.tech"},
		{Name: "gru.api.terrascale.tech"}, {Name: "sfo.api.terrascale.tech"}, {Name: "fra.api.terrascale.tech"},
	}}
	want := []string{"fra.api.terrascale.tech", "gru.api.terrascale.tech", "sfo.api.terrascale.tech", "sync.api.terrascale.tech"}
	if got := z.certificateCoverageGap(); !reflect.DeepEqual(got, want) {
		t.Fatalf("certificateCoverageGap() = %v, want %v", got, want)
	}
}
