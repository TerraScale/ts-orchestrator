package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
)

func installCases(ctx context.Context, conn *nats.Conn, nodes []*process, boot func(int) *process, roots, order, names []string, launcher string, baseline swarmruntime.ServiceSpec) {
	spec := baseline
	spec.Name, spec.Port, spec.Args = "install-canary", 18092, []string{"--port", "18092"}
	spec.Regions = order[:2]
	spec.Image = strings.Replace(baseline.Image, "/terrabase@", "/install-canary@", 1)
	release := &mesh.Deployment{Repository: "TerraScale/ts-orchestrator", RunID: "1", RunAttempt: 1, Revision: revision, Image: spec.Image, Workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main"}
	generation := declaration(ctx, conn, &spec, spec.Name, release)
	for i := range roots[:2] {
		installEvidence(ctx, roots[i], spec.Name, generation, false)
		if i == 0 {
			reconnect := conn.StatusChanged(nats.CONNECTED)
			nodes[0].kill()
			must(os.Remove(filepath.Join(roots[0], "mesh", fmt.Sprintf("bake-%s-%d.json", spec.Name, generation))))
			nodes[0] = boot(0)
			select {
			case <-reconnect:
			case <-ctx.Done():
				panic(ctx.Err())
			}
			repeated := installEvidence(ctx, roots[0], spec.Name, generation, false)
			require(repeated.Bake.Finished.IsZero(), "deleted receipt did not restart observation")
		}
		if i+1 < 2 {
			assertWaiting(ctx, conn, order[i+1], spec.Name, generation, order[i], "passed bake missing")
			assertRuntimeBefore(ctx, names[i+1], launcher, roots[i+1], spec.Name, generation)
		}
		installEvidence(ctx, roots[i], spec.Name, generation, true)
	}
	logStep("first installation bakes in each region in order before admission")
	spec.Regions = order
	added := declaration(ctx, conn, &spec, spec.Name, release)
	for i := range roots {
		started := installEvidence(ctx, roots[i], spec.Name, added, false)
		require(started.Bake.Finished.IsZero(), "added-region generation skipped its bake")
		installEvidence(ctx, roots[i], spec.Name, added, true)
	}
	logStep("deleted bake records require a new bake; a newly added target bakes before reporting ready")
	bad := spec
	bad.Name, bad.Port, bad.Args = "invalid-canary", 18093, []string{"--port", "18093"}
	bad.Image = strings.Replace(baseline.Image, "/terrabase@", "/invalid-canary@", 1)
	invalid := *release
	invalid.Image, invalid.Revision = bad.Image, strings.Repeat("b", 40)
	generation = declaration(ctx, conn, &bad, bad.Name, &invalid)
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Failed[bad.Name] == generation })
	require(states(ctx, conn)[order[0]].Ready[bad.Name] != generation, "invalid release identity reported ready")
	assertWaiting(ctx, conn, order[1], bad.Name, generation, order[0], "bake failed")
	assertRuntimeBefore(ctx, names[1], launcher, roots[1], bad.Name, generation)
	logStep("invalid first-install release identity is failed, never ready, and never applied downstream")
}

func installEvidence(ctx context.Context, root, name string, generation int64, finished bool) receipt {
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(filepath.Join(root, "mesh")))
	for {
		data, err := os.ReadFile(filepath.Join(root, "mesh", fmt.Sprintf("bake-%s-%d.json", name, generation)))
		if err == nil {
			var r receipt
			must(json.Unmarshal(data, &r))
			if !r.Bake.Started.IsZero() && (!finished || !r.Bake.Finished.IsZero()) {
				require(r.Bake.Reason == "", "installation bake failed: "+r.Bake.Reason)
				return r
			}
		}
		select {
		case <-watcher.Events:
		case err := <-watcher.Errors:
			panic(err)
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
}

func assertRuntimeBefore(ctx context.Context, namespace, launcher, root, name string, generation int64) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, os.Args[0], "inventory", root).Output()
	require(err == nil, fmt.Sprintf("runtime inventory: %v %s", err, output))
	var rows []swarmruntime.ServiceSpecStatus
	must(json.Unmarshal(output, &rows))
	for _, row := range rows {
		require(row.Name != name || row.Generation < generation, "runtime applied an unadmitted generation")
	}
}
