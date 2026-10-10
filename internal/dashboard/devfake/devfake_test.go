package devfake_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard/devfake"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

func TestWorldHasThreeMovingRegions(t *testing.T) {
	t.Parallel()
	world := devfake.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go world.Run(ctx)
	regions := world.Regions(ctx)
	if len(regions) != 3 || !regions[0].Local || regions[0].Region != "gru" {
		t.Fatalf("regions = %+v", regions)
	}
	if !regions[1].MixedVersions() || len(regions[2].Quorum.Missing) != 1 {
		t.Fatalf("SFO should run mixed versions and FRA miss a controller: %+v %+v", regions[1], regions[2])
	}
	options := world.Options()
	cluster, err := options.Cluster.Cluster(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range cluster.Members {
		if member.Placement == nil {
			continue
		}
		for _, db := range member.Placement.Databases {
			if !entityid.Valid(db.DatabaseID) || !entityid.Valid(db.PartitionID) {
				t.Fatalf("invalid preview database identity: %+v", db)
			}
			for _, seat := range db.Members {
				if !entityid.Valid(seat.SeatID) {
					t.Fatalf("invalid preview seat identity: %s", seat.SeatID)
				}
			}
		}
	}
	result, err := options.Journal.Decisions.Query(ctx, decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindRollback}})
	if err != nil || len(result.Decisions) == 0 {
		t.Fatalf("no rollback decision: %v %v", result, err)
	}
	holds, err := options.Journal.Decisions.Query(ctx, decisionlog.Query{
		Kinds: []decisionlog.Kind{decisionlog.KindHeld, decisionlog.KindHoldCleared}, Limit: decisionlog.MaxQueryLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	matched := map[decisionlog.Kind]bool{}
	for _, event := range holds.Decisions {
		if event.Subject.Kind == "database" {
			if event.Attrs["database_id"] != event.Subject.ID ||
				event.Attrs["partition_id"] != entityid.Derive("preview-partition", event.Subject.ID) {
				t.Fatalf("database hold lacks partition correlation: %+v", event)
			}
			matched[event.Kind] = true
		}
	}
	if !matched[decisionlog.KindHeld] || !matched[decisionlog.KindHoldCleared] {
		t.Fatal("preview lacks database hold and clearing")
	}
	if evaluation := options.Journal.Insights.Current(); len(evaluation.Insights) == 0 {
		t.Fatal("the fake world raises no insight")
	}
	versions, _ := options.Journal.Versions.Versions(ctx)
	kinds := map[string]bool{}
	for _, unit := range versions {
		kinds[unit.Kind] = true
	}
	if !kinds["controller"] || !kinds["host"] || !kinds["seat"] {
		t.Fatalf("version kinds = %v", kinds)
	}
}

func TestEveryPageAndStreamRendersTheFakeWorld(t *testing.T) {
	t.Parallel()
	world := devfake.New()
	options := world.Options()
	options.Interval = 20 * time.Millisecond
	board := dashboard.New(options)
	server := httptest.NewServer(board.Handler())
	t.Cleanup(server.Close)
	for _, path := range []string{"/", "/region", "/region?r=sfo", "/insights", "/decisions", "/releases", "/rollouts",
		"/ci", "/topology", "/members", "/nats", "/terrabase", "/storage", "/oci", "/events"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.StatusCode)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/global/stream?range=24h", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "region-switcher") {
			return
		}
	}
	t.Fatalf("the global stream never patched the page: %v", scanner.Err())
}

// TestProductionBinaryDoesNotLinkTheFake keeps fixtures confined to tests.
func TestProductionBinaryDoesNotLinkTheFake(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the production binary's dependencies with the go tool")
	}
	t.Parallel()
	output, err := exec.Command("go", "list", "-deps", "git.terrascale.tech/TerraScale/ts-orchestrator/cmd/terrascale-orchestrator").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "internal/dashboard/devfake") {
		t.Fatal("the orchestrator binary links the dev-only fake data provider")
	}
	if !strings.Contains(string(output), "internal/dashboard\n") {
		t.Fatal("go list did not list the dashboard; the check is not looking at the right binary")
	}
	sources, err := exec.Command("go", "list", "-f", "{{join .GoFiles \"\\n\"}}", "git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard/devfake").CombinedOutput()
	if err != nil {
		t.Fatalf("go list fixture sources: %v\n%s", err, sources)
	}
	if strings.TrimSpace(string(sources)) != "" {
		t.Fatalf("fake sources must be test-only: %s", sources)
	}
}
