package observability

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRouteRTTMetricsAndHistoryPreservePartialCoverage(t *testing.T) {
	t.Parallel()
	view := NATSView{ServerName: "server-a", RouteRTTsTruncated: true, RouteRTTs: []RouteRTTView{
		{RemoteName: "peer-b", Connections: 3, MeasuredConnections: 2, RTTSeconds: new(0.005)},
		{RemoteName: "peer-c", Connections: 4},
	}}
	sampler := new(SnapshotSampler)
	cluster := ClusterSnapshot{Members: []MemberSnapshot{{Member: "member-a", NATS: &view}}}
	for _, measured := range []bool{true, false, true} {
		view.RouteRTTs[0].RTTSeconds = nil
		view.RouteRTTs[0].MeasuredConnections = 0
		if measured {
			view.RouteRTTs[0].RTTSeconds = new(0.005)
			view.RouteRTTs[0].MeasuredConnections = 2
		}
		collector, _ := testCollector(t, "route", nil)
		collector.config.NATS = func(context.Context) (NATSView, error) { return view, nil }
		output := metricsOverHTTP(t, collector)
		wantRTT := `ts_orch_nats_route_rtt_seconds{server="server-a",peer="peer-b"} 0.005`
		if strings.Contains(output, wantRTT) != measured || strings.Contains(output, `nats_route_rtt_seconds{server="server-a",peer="peer-c"}`) {
			t.Fatalf("RTT availability was not preserved:\n%s", output)
		}
		for _, want := range []string{
			`ts_orch_nats_route_connections{server="server-a",peer="peer-b"} 3`,
			`ts_orch_nats_route_connections{server="server-a",peer="peer-c"} 4`,
			`ts_orch_nats_route_measured_connections{server="server-a",peer="peer-c"} 0`,
			`ts_orch_nats_route_rtts_truncated{server="server-a"} 1`,
		} {
			if !strings.Contains(output, want) {
				t.Errorf("metrics lack %s", want)
			}
		}
		values := map[string]float64{}
		history := NewHistory(HistoryConfig{})
		history.Append(time.Now(), sampler.Samples(cluster))
		for _, metric := range history.Metrics() {
			recorder := httptest.NewRecorder()
			HistoryHandler(history).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/history?metric="+metric, nil))
			var retained HistoryResult
			if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &retained) != nil {
				t.Fatalf("route history API = %d %s", recorder.Code, recorder.Body.String())
			}
			for _, series := range retained.Series {
				values[Series(metric, "member", series.Labels["member"], "peer", series.Labels["peer"], "server", series.Labels["server"])] = series.Points[len(series.Points)-1].Value
			}
		}
		key := func(metric, peer string) string {
			return Series(metric, "member", "member-a", "peer", peer, "server", "server-a")
		}
		if value, present := values[key(HistNATSRouteRTT, "peer-b")]; present != measured || present && value != 0.005 {
			t.Fatalf("sampled RTT = %v, present = %v, measured = %v", value, present, measured)
		}
		if _, present := values[key(HistNATSRouteRTT, "peer-c")]; present {
			t.Fatal("unknown RTT became a measured zero")
		}
		for metric, want := range map[string]float64{HistNATSRouteConnections: 3, HistNATSRouteMeasuredConnections: float64(view.RouteRTTs[0].MeasuredConnections)} {
			if got, present := values[key(metric, "peer-b")]; !present || got != want {
				t.Fatalf("%s coverage = %v (present %v), want %v", metric, got, present, want)
			}
		}
	}
	data, err := json.Marshal(NATSView{RouteRTTs: []RouteRTTView{{RemoteName: "peer-c", Connections: 4}}})
	if err != nil || !bytes.Contains(data, []byte(`"rtt_seconds":null`)) || !bytes.Contains(data, []byte(`"route_rtts_truncated":false`)) {
		t.Fatalf("JSON lost explicit unknown RTT or truncation state: %s, %v", data, err)
	}
}

func TestRouteRTTHistoryUsesExistingPersistenceAndAPI(t *testing.T) {
	t.Parallel()
	history := NewHistory(HistoryConfig{})
	view := NATSView{ServerName: "server-a", RouteRTTs: []RouteRTTView{{RemoteName: "peer-b", Connections: 3, MeasuredConnections: 2, RTTSeconds: new(0.005)}}}
	sampler := new(SnapshotSampler)
	history.Append(time.Now().UTC(), sampler.Samples(ClusterSnapshot{Members: []MemberSnapshot{{Member: "member-a", NATS: &view}}}))
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	for metric, want := range map[string]string{HistNATSRouteRTT: `"v":0.005`, HistNATSRouteConnections: `"v":3`, HistNATSRouteMeasuredConnections: `"v":2`} {
		recorder := httptest.NewRecorder()
		path := "/v1/history?metric=" + metric + "&tier=1m&label.member=member-a&label.server=server-a&label.peer=peer-b"
		HistoryHandler(restored).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), want) || !strings.Contains(recorder.Body.String(), `"peer":"peer-b"`) {
			t.Fatalf("restored %s API = %d %s", metric, recorder.Code, recorder.Body.String())
		}
	}
}
