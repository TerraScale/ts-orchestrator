package terrabase

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Names and scope labels match the native C# WanMetrics/OpenTelemetry exporter.
const wanMetricsFixture = `# TYPE terrabase_wan_lag gauge
terrabase_wan_lag{region="sfo-1",otel_scope_name="TerraScale.TerraBase",otel_scope_version=""} 7
terrabase_wan_staleness_seconds{region="sfo-1"} 12.5
terrabase_wan_members{region="sfo-1"} 3
terrabase_wan_unregistered{region="sfo-1"} 2
terrabase_wan_conflicts{region="sfo-1"} 1
terrabase_wan_failures_total{region="sfo-1",reason="ahead"} 4
terrabase_wan_failures_total{region="sfo-1",reason="pull"} 2
dotnet_process_memory_working_set_bytes 100
`

func TestParseWANMetricsPreservesRawRegionsAndScrapeTime(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	observation, err := ParseWANMetrics([]byte(wanMetricsFixture), "gru-native-region", at)
	if err != nil || observation == nil || !observation.ObservedAt.Equal(at) || len(observation.Sources) != 1 {
		t.Fatalf("WAN observation = %+v, %v", observation, err)
	}
	source := observation.Sources[0]
	if source.SourceRegion != "sfo-1" || observation.ReceiverRegion != "gru-native-region" || *source.LagGroups != 7 ||
		*source.StalenessSeconds != 12.5 || *source.Members != 3 || *source.Unregistered != 2 ||
		*source.Conflicts != 1 || *source.AheadFailuresTotal != 4 {
		t.Fatalf("source gauge values = %+v", source)
	}
	moreSources := wanMetricsFixture + strings.ReplaceAll(wanMetricsFixture, "sfo-1", "new-native-zone")
	if got, err := ParseWANMetrics([]byte(moreSources), "gru-native-region", at); err != nil || got == nil || len(got.Sources) != 2 {
		t.Fatalf("unmapped raw native source was not collected: %+v, %v", got, err)
	}
	for _, region := range []string{"", "GRU", "1-gru", "gru.*"} {
		if got, err := ParseWANMetrics([]byte(wanMetricsFixture), region, at); err == nil || got != nil {
			t.Fatalf("invalid receiver region accepted: %+v, %v", got, err)
		}
	}
	if got, err := ParseWANMetrics([]byte("dotnet_process_memory_working_set_bytes 100\n"), "gru-1", at); err != nil || got != nil {
		t.Fatalf("older runtime without WAN gauges = %+v, %v", got, err)
	}
	// Unanswered() can retain old lag or first emit zero: preserve members=0.
	unanswered := strings.ReplaceAll(strings.ReplaceAll(wanMetricsFixture, "} 3\n", "} 0\n"), "} 7\n", "} 0\n")
	got, err := ParseWANMetrics([]byte(unanswered), "gru-1", at)
	if err != nil || got == nil || *got.Sources[0].Members != 0 || *got.Sources[0].LagGroups != 0 {
		t.Fatalf("unanswered evidence lost: %+v, %v", got, err)
	}
}

func TestParseWANMetricsRejectsIncompleteOrAmbiguousScrapes(t *testing.T) {
	var tooMany strings.Builder
	for i := range MaxWANRegions + 1 {
		tooMany.WriteString(strings.ReplaceAll(wanMetricsFixture, "sfo-1", fmt.Sprintf("native-%d", i)))
	}
	for name, input := range map[string]string{
		"missing gauge":         strings.ReplaceAll(wanMetricsFixture, "terrabase_wan_conflicts{region=\"sfo-1\"} 1\n", ""),
		"duplicate":             wanMetricsFixture + "terrabase_wan_lag{region=\"sfo-1\"} 7\n",
		"bare duplicate":        wanMetricsFixture + "terrabase_wan_lag\n",
		"NaN":                   strings.ReplaceAll(wanMetricsFixture, "} 7\n", "} NaN\n"),
		"infinity":              strings.ReplaceAll(wanMetricsFixture, "} 12.5\n", "} +Inf\n"),
		"negative":              strings.ReplaceAll(wanMetricsFixture, "} 7\n", "} -1\n"),
		"fractional count":      strings.ReplaceAll(wanMetricsFixture, "} 3\n", "} 1.5\n"),
		"inexact count":         strings.ReplaceAll(wanMetricsFixture, "} 7\n", "} 9007199254740992\n"),
		"unknown label":         strings.ReplaceAll(wanMetricsFixture, "region=\"sfo-1\"", "region=\"sfo-1\",database=\"x\""),
		"duplicate label":       strings.ReplaceAll(wanMetricsFixture, "region=\"sfo-1\"", "region=\"sfo-1\",region=\"sfo-1\""),
		"bad token":             strings.ReplaceAll(wanMetricsFixture, "sfo-1", "sfo.*"),
		"foreign scope":         strings.ReplaceAll(wanMetricsFixture, "TerraScale.TerraBase", "foreign"),
		"timestamp":             strings.ReplaceAll(wanMetricsFixture, "} 7\n", "} 7 1234\n"),
		"empty reason on gauge": strings.ReplaceAll(wanMetricsFixture, "region=\"sfo-1\"", "region=\"sfo-1\",reason=\"\""),
		"unknown reason":        strings.ReplaceAll(wanMetricsFixture, "reason=\"ahead\"", "reason=\"other\""),
		"truncated labels":      wanMetricsFixture + "terrabase_wan_lag{region=\"sfo-1\" 7\n",
		"body bound":            strings.Repeat("#", wanBodyBytes+1),
		"line bound":            strings.Repeat("#", 16<<10),
		"source bound":          tooMany.String(),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseWANMetrics([]byte(input), "gru-1", time.Now().UTC()); err == nil || got != nil {
				t.Fatalf("invalid scrape accepted: %+v, %v", got, err)
			}
		})
	}
}

func TestWANFreshness(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		at    time.Time
		fresh bool
	}{
		{now, true}, {now.Add(-WANFreshFor), true}, {now.Add(-WANFreshFor - time.Nanosecond), false}, {now.Add(time.Nanosecond), false}, {time.Time{}, false},
	} {
		if got := (WANObservation{ObservedAt: test.at}).Fresh(now); got != test.fresh {
			t.Errorf("Fresh(%v) = %v", test.at, got)
		}
	}
}

func TestCollectWANLoopbackBoundsAndNoRedirect(t *testing.T) {
	var mode atomic.Int32
	var redirected atomic.Int32
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/metrics" {
			redirected.Add(1)
			return
		}
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case 2:
			fmt.Fprint(w, strings.Repeat(" ", wanBodyBytes+1))
		case 3:
			<-r.Context().Done()
		default:
			fmt.Fprint(w, wanMetricsFixture)
		}
	}))
	defer server.Close()
	address, _ := url.Parse(server.URL)
	env := map[string]string{EnvAdminPort: address.Port(), EnvPeerPort: "9443", EnvPeers: "node-a=127.0.0.1:9443", EnvRegion: "gru-native-region"}
	started := time.Now().UTC()
	got, err := CollectWAN(t.Context(), env)
	if err != nil || got == nil || got.ReceiverRegion != "gru-native-region" || got.Sources[0].SourceRegion != "sfo-1" ||
		got.ObservedAt.Before(started) || got.ObservedAt.After(time.Now()) {
		t.Fatalf("loopback scrape = %+v, %v", got, err)
	}
	// A missing existing native region is invalid evidence, never a scrape switch.
	delete(env, EnvRegion)
	before := requests.Load()
	if got, err := CollectWAN(t.Context(), env); err == nil || got != nil {
		t.Fatalf("missing native identity accepted: %+v, %v", got, err)
	}
	if requests.Load() != before+1 {
		t.Fatal("missing native identity disabled the scrape")
	}
	env[EnvRegion] = "gru-native-region"
	for _, value := range []int32{1, 2, 3} {
		mode.Store(value)
		if got, err := CollectWAN(t.Context(), env); err == nil || got != nil {
			t.Fatalf("mode %d accepted: %+v, %v", value, got, err)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("collector followed a redirect")
	}
}
