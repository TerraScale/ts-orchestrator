package devfake

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type sampledRegion struct {
	region     *region
	now, start time.Time
}

func (source sampledRegion) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.region.cluster(source.now, source.start).Members[0], nil
}
func (source sampledRegion) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	return source.region.cluster(source.now, source.start), nil
}

func TestFixtureClockReachesDashboardResourcesAndReadiness(t *testing.T) {
	t.Parallel()
	world := New()
	now := time.Now().UTC()
	for _, region := range world.regions {
		previous := map[string][2]uint64{}
		var previousThrottled uint64
		for _, age := range []time.Duration{0, time.Hour, 10 * time.Hour} {
			source := sampledRegion{region: region, start: now, now: now.Add(age)}
			options := world.Options()
			options.Snapshots = source
			options.Cluster = source
			options.Now = func() time.Time { return source.now }
			server := httptest.NewServer(dashboard.New(options).Handler())
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 5 * time.Second
			for _, path := range []string{"/oci", "/region", "/nats", "/members"} {
				response, err := client.Get(server.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("%s sample %s %s = %d", region.name, age, path, response.StatusCode)
				}

				if path == "/oci" {
					matches := regexp.MustCompile(`<td class="wrap"><code>([^<]+)</code></td>\s*<td>([0-9]+)</td>\s*<td[^>]*>[0-9]+</td>\s*<td[^>]*>([0-9]+)</td>`).FindAllStringSubmatch(string(body), -1)
					if len(matches) == 0 {
						t.Fatal("OCI operation counters missing")
					}
					var totalThrottled uint64
					for _, match := range matches {
						operation := html.UnescapeString(match[1])
						calls, _ := strconv.ParseUint(match[2], 10, 64)
						throttled, _ := strconv.ParseUint(match[3], 10, 64)
						if last, ok := previous[operation]; ok && (calls <= last[0] || throttled < last[1]) {
							t.Fatalf("%s %s counters stopped at %s", region.name, operation, age)
						}
						previous[operation] = [2]uint64{calls, throttled}
						totalThrottled += throttled
					}
					if region.throttled && age > 0 && totalThrottled <= previousThrottled {
						t.Fatal("throttling storm stopped counting")
					}
					previousThrottled = totalThrottled
				}

				if path == "/region" && region.name == "fra" && !strings.Contains(string(body), "regional cluster is below its full replica count") {
					t.Fatal("FRA failing readiness check was hidden")
				}
			}
			server.Close()
		}
	}
}
