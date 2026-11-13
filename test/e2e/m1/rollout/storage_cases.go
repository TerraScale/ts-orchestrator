package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
