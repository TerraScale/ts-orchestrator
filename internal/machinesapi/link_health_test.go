package machinesapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type linkHealthSource func(context.Context, bool) (observability.ClusterSnapshot, error)

func (source linkHealthSource) Cluster(ctx context.Context, metrics bool) (observability.ClusterSnapshot, error) {
	return source(ctx, metrics)
}

func TestPublicLinkHealthPreservesEvidenceAndMissingControllers(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	probeTime := now.Add(-3 * time.Minute)
	calls := 0
	f.server.links = linkHealthSource(func(ctx context.Context, metrics bool) (observability.ClusterSnapshot, error) {
		calls++
		if metrics {
			t.Fatal("public health requested private metrics")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("public health gather has no bounded deadline")
		}
		return observability.ClusterSnapshot{Cell: "gru", ObservedAt: now, Expected: []string{"a", "b"},
			Members: []observability.MemberSnapshot{{Cell: "gru", Member: "a", ObservedAt: now,
				Credentials: []observability.CredentialView{{Name: "private-credential"}},
				Metrics:     "private-metric", Errors: map[string]string{"private-error": "hidden"},
				Links: []observability.RegionLinkProbe{{Region: "sfo", ObservedAt: probeTime, Reach: "ok", WAN: "ok", LagGroups: new(0.0)}}}}}, nil
	})
	for range 2 {
		response := httptest.NewRecorder()
		f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/link-health", nil))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("public health = %d, %s", response.Code, response.Body)
		}
		var report LinkHealth
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Version != 1 || report.Region != "gru" || len(report.Expected) != 2 ||
			len(report.Missing) != 1 || report.Missing[0] != "b" || len(report.Members) != 1 ||
			!report.Members[0].Links[0].ObservedAt.Equal(probeTime) || report.Members[0].Links[0].LagGroups == nil {
			t.Fatalf("public health refreshed or lost evidence: %+v", report)
		}
		if strings.Contains(response.Body.String(), "private-") || strings.Contains(response.Body.String(), "hidden") {
			t.Fatalf("public health exposed private snapshot fields: %s", response.Body)
		}
	}
	if calls != 1 {
		t.Fatalf("public requests repeated the local gather: %d calls", calls)
	}
}

func TestPublicLinkHealthFailsClosedWithoutChangingLiveness(t *testing.T) {
	f := newFixture(t)
	for _, source := range []linkHealthSource{
		nil,
		func(context.Context, bool) (observability.ClusterSnapshot, error) {
			return observability.ClusterSnapshot{}, errors.New("private-source-error")
		},
		func(context.Context, bool) (observability.ClusterSnapshot, error) {
			return observability.ClusterSnapshot{Cell: "gru", ObservedAt: time.Now()}, nil
		},
		func(context.Context, bool) (observability.ClusterSnapshot, error) {
			return observability.ClusterSnapshot{Cell: "gru", ObservedAt: time.Now(), Expected: []string{"a"},
				Members: []observability.MemberSnapshot{{Cell: "sfo", Member: "a"}}}, nil
		},
	} {
		f.server.links = source
		if source == nil {
			f.server.links = nil
		}
		f.server.linkCache = observability.Cache[observability.ClusterSnapshot]{}
		code, body, _ := call(t, f.server, "", "/v1/link-health")
		if code != http.StatusServiceUnavailable || strings.Contains(body["message"].(string), "private-") {
			t.Fatalf("invalid public health = %d, %+v", code, body)
		}
		if code, _, _ := call(t, f.server, "", "/healthz"); code != http.StatusOK {
			t.Fatalf("missing link health changed liveness: %d", code)
		}
		if code, _, _ := call(t, f.server, "", "/v1/apps"); code != http.StatusUnauthorized {
			t.Fatalf("public health bypassed app authentication: %d", code)
		}
	}
}
