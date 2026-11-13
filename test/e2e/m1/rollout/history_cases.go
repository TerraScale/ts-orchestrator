package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
)

func declaration(ctx context.Context, conn *nats.Conn, spec *swarmruntime.ServiceSpec, name string, deployment *mesh.Deployment) int64 {
	generation := time.Now().UnixNano()
	data, err := json.Marshal(mesh.ApplyRequest{Name: name, Entry: mesh.Entry{Generation: generation, Spec: spec, Deployment: deployment}})
	must(err)
	must(conn.PublishRequest(mesh.ApplySubject, nats.NewInbox(), data))
	must(conn.Flush())
	return generation
}

func historyCases(ctx context.Context, conn *nats.Conn, roots, order []string, baseline swarmruntime.ServiceSpec, releases *nats.Conn, key *rsa.PrivateKey) {
	spec := baseline
	spec.Name, spec.Port, spec.Args, spec.Regions = "history-canary", 18092, []string{"--port", "18092"}, []string{order[0]}
	spec.Image = strings.Replace(baseline.Image, "/terrabase@", "/history-canary@", 1)
	old := declaration(ctx, conn, &spec, spec.Name, nil)
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Ready[spec.Name] == old })
	spec.Regions = order
	release := &mesh.Deployment{Repository: "TerraScale/ts-orchestrator", RunID: "1", RunAttempt: 1, Revision: revision, Image: spec.Image}
	generation := declaration(ctx, conn, &spec, spec.Name, release)
	observe(ctx, conn, func(s map[string]state) bool {
		for _, region := range order {
			if s[region].Ready[spec.Name] != generation {
				return false
			}
		}
		for i := range order {
			files, err := filepath.Glob(filepath.Join(roots[i], "mesh", fmt.Sprintf("bake-%s-%d.json", spec.Name, generation)))
			must(err)
			require(len(files) == boolCount(i == 0), "region without history wrote a bake receipt")
		}
		for i, region := range order {
			require(s[region].BakeRequired[spec.Name] == (i == 0), "regions disagreed with their own local history")
		}
		return true
	})
	logStep("one generation bakes only where there is local history and admission completes in new regions")
	image := strings.Replace(baseline.Image, "/terrabase@", "/app-canary@", 1)
	require(releaseReply(ctx, releases, key, "app-canary", image, "50").State == "accepted", "first signed history release refused")
	observe(ctx, conn, func(s map[string]state) bool {
		return releaseReply(ctx, releases, key, "app-canary", image, "50").State == "done"
	})
	must(mesh.Remove(ctx, conn, "app-canary", io.Discard))
	observe(ctx, conn, func(s map[string]state) bool {
		for _, region := range order {
			if s[region].Serving["app-canary"].Serving {
				return false
			}
		}
		return true
	})
	require(releaseReply(ctx, releases, key, "app-canary", image, "51").State == "accepted", "signed recreation refused")
	observe(ctx, conn, func(s map[string]state) bool {
		for _, region := range order {
			var desired struct{ Signed *mesh.Entry }
			must(json.Unmarshal(s[region].Desired["app-canary"], &desired))
			if desired.Signed == nil || desired.Signed.Deployment.RunID != "51" {
				return false
			}
			targeted := len(desired.Signed.Spec.Regions) == 0 || slices.Contains(desired.Signed.Spec.Regions, region)
			if targeted && s[region].Ready["app-canary"] != desired.Signed.Generation {
				return false
			}
			if targeted {
				files, err := filepath.Glob(filepath.Join(roots[slices.Index(order, region)], "mesh", fmt.Sprintf("bake-app-canary-%d.json", desired.Signed.Generation)))
				must(err)
				require(len(files) == 1, "signed recreation omitted a required bake receipt")
			}
			require(s[region].BakeRequired["app-canary"] == targeted, "signed recreation erased or imported local history")
		}
		return true
	})
	logStep("removing a released service retains its floor and its authenticated recreation bakes in every returning target region")

}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func olderHoldReceipt(root string, generation int64) {
	path := filepath.Join(root, "mesh", fmt.Sprintf("bake-terrabase-%d.json", generation))
	data, err := os.ReadFile(path)
	must(err)
	var record map[string]json.RawMessage
	must(json.Unmarshal(data, &record))
	delete(record, "release")
	data, err = json.Marshal(record)
	must(err)
	must(os.WriteFile(path, data, 0600))
}

func fillMesh(root string) {
	directory := filepath.Join(root, "mesh")
	entries, err := os.ReadDir(directory)
	must(err)
	snapshot := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		must(err)
		snapshot[entry.Name()] = data
	}
	must(syscall.Mount("tmpfs", directory, "tmpfs", 0, "size=16m"))
	for name, data := range snapshot {
		must(os.WriteFile(filepath.Join(directory, name), data, 0600))
	}
	file, err := os.Create(filepath.Join(directory, "full"))
	must(err)
	chunk := make([]byte, 1<<20)
	for {
		_, err := file.Write(chunk)
		if errors.Is(err, syscall.ENOSPC) {
			break
		}
		must(err)
	}
	must(file.Close())
}

func topologyReady(ctx context.Context, roots []string) {
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	for _, root := range roots {
		must(watcher.Add(filepath.Join(root, "mesh")))
	}
	for {
		complete := true
		for _, root := range roots {
			data, err := os.ReadFile(filepath.Join(root, "mesh", "admitted-peers.json"))
			if errors.Is(err, os.ErrNotExist) {
				complete = false
				continue
			}
			must(err)
			var peers []json.RawMessage
			must(json.Unmarshal(data, &peers))
			complete = complete && len(peers) == len(roots)
		}
		if complete {
			return
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
