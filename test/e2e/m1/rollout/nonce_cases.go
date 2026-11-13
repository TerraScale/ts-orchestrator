package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

func nonceCases(ctx context.Context, conn *nats.Conn, roots, order, names []string, launcher string, baseline swarmruntime.ServiceSpec) {
	for i, root := range roots {
		must(os.WriteFile(filepath.Join(root, "clock-offset"), []byte(fmt.Sprint(int64(time.Duration(i)*10*time.Minute))), 0600))
	}

	spec := baseline
	spec.Dependencies = new([]string{})
	spec.Name, spec.Port, spec.Args, spec.Regions = "nonce-canary", 18094, []string{"--port", "18094"}, []string{"syd", order[0]}
	spec.Image = strings.Replace(baseline.Image, "/terrabase@", "/nonce-canary@", 1)
	var mode, generation atomic.Int64
	sub, err := conn.Subscribe(mesh.StateSubject, func(m *nats.Msg) {
		var request struct{ Nonce string }
		if json.Unmarshal(m.Data, &request) != nil || request.Nonce == "" {
			return
		}
		selected := mode.Load()
		nonce := request.Nonce
		switch selected {
		case 0:
			nonce = "wrong"
		case 1:
			nonce = ""
		}
		reply := map[string]any{"region": "syd", "nonce": nonce, "desired": map[string]any{}, "ready": map[string]int64{spec.Name: generation.Load()}}
		if selected == 4 {
			delete(reply, "nonce")
		}
		if selected != 4 {
			reply["serving"] = map[string]mesh.ServingResult{spec.Name: {Generation: generation.Load(), Serving: true, At: time.Now().Add(-10 * time.Minute)}}
		}
		data, err := json.Marshal(reply)
		must(err)
		if selected == 2 {
			time.AfterFunc(6*time.Second, func() { _ = m.Respond(data) })
			return
		}
		must(m.Respond(data))
	})
	must(err)
	defer sub.Unsubscribe()
	must(conn.Flush())
	for _, selected := range []int64{0, 1, 2} {
		mode.Store(selected)
		generation.Store(declaration(ctx, conn, &spec, spec.Name, nil))
		assertWaiting(ctx, conn, order[0], spec.Name, generation.Load(), "syd", "region reply missing")
		if selected == 2 {
			bound := time.NewTimer(7 * time.Second)
			select {
			case <-bound.C:
			case <-ctx.Done():
				panic(ctx.Err())
			}
			assertWaiting(ctx, conn, order[0], spec.Name, generation.Load(), "syd", "region reply missing")
		}
		assertRuntimeBefore(ctx, names[0], launcher, roots[0], spec.Name, generation.Load())
	}
	logStep("wrong, missing and replies delayed beyond the requester monotonic bound do not admit or run")
	for _, selected := range []int64{3, 4} {
		mode.Store(selected)
		generation.Store(declaration(ctx, conn, &spec, spec.Name, nil))
		installEvidence(ctx, roots[0], spec.Name, generation.Load(), true)
		observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Ready[spec.Name] == generation.Load() })
	}
	logStep("nonce replies admit across ten-minute wall offsets; main reply shape admits during a rolling update")
}
