//go:build live_podman

// Package live holds the on-host smoke proofs that exercise real rootless
// podman. This file is gated twice: it compiles only under the live_podman
// build tag, and it skips itself unless TS_ORCH_LIVE=1 is set, so the
// ordinary test sweep never touches a real container runtime.
package live

import (
	"context"
	"fmt"
	"os"
	goruntime "runtime"
	"strconv"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// The local image the smoke run uses; it is present on the development host
// and is never pulled from the network.
const liveSmokeImage = "localhost/benchmark-csharp-noble:latest"

// liveSmokeTimeout bounds the whole smoke run.
const liveSmokeTimeout = 90 * time.Second

// TestProcessPodmanClientRootlessSmoke drives the real ProcessPodmanClient
// under the current unprivileged account: preflight proves the rootless
// environment, create builds the container from the local image (no pull)
// without starting it, start starts it, inspect observes it Running, stop
// stops it, rm deletes it, and a final inspect observes Absent. The create
// loads the seccomp profile named by the rootless context, proving the
// profile plumbing end to end. The container is removed on every exit path.
func TestProcessPodmanClientRootlessSmoke(t *testing.T) {
	if os.Getenv("TS_ORCH_LIVE") != "1" {
		t.Skip("live rootless podman smoke: set TS_ORCH_LIVE=1 (and build with -tags live_podman) to run")
	}
	podmanBinary := liveSmokePodmanBinary(t)
	uid := uint32(os.Getuid())
	xdgRuntimeDir := fmt.Sprintf("/run/user/%d", uid)
	rootless, err := runtime.NewRootlessPodmanContext(
		podmanBinary, xdgRuntimeDir, liveSmokeSeccompProfile(t), uid)
	if err != nil {
		t.Fatalf("rootless context (uid %d, %s, %s): %v", uid, podmanBinary, xdgRuntimeDir, err)
	}
	client, err := runtime.NewProcessPodmanClient(rootless, runtime.ProcessHostCommandRunner{})
	if err != nil {
		t.Fatalf("podman client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), liveSmokeTimeout)
	defer cancel()

	if err := client.Preflight(ctx); err != nil {
		t.Fatalf("rootless podman preflight failed: %v", err)
	}

	containerId := "terrascale-live-smoke-" + strconv.Itoa(os.Getpid())
	request, err := runtime.NewPodmanRunRequest(
		containerId,
		liveSmokeImage,
		"linux/"+liveSmokeArchitecture(),
		1000,
		1000,
		"terrascale/live-smoke",
		[]string{"ALL"},
		256*1024*1024,
		128,
		100,
		100,
		nil,
		map[string]string{
			runtime.PodmanLabelAllocation:  "live-smoke",
			runtime.PodmanLabelFingerprint: liveSmokeFingerprintPlaceholder(),
		})
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	// Delete on every exit path so a failed assertion never strands a
	// container on the host.
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = client.Delete(cleanupContext, containerId)
	})

	// Create builds the container without starting it; with the local image
	// present it never resolves anything from the network.
	if err := client.Create(ctx, request); err != nil {
		t.Fatalf("podman create of the local image failed: %v", err)
	}
	created, err := client.Inspect(ctx, containerId)
	if err != nil {
		t.Fatalf("inspect after create: %v", err)
	}
	if created.State != runtime.PodmanAllocationStateCreating {
		t.Fatalf("state after create = %s; want Creating (created, not started)", created.State)
	}

	if err := client.Start(ctx, containerId); err != nil {
		t.Fatalf("podman start failed: %v", err)
	}

	// The container's entrypoint is a server, but startup takes a moment:
	// poll inspect for the Running observation inside a bounded window.
	running := false
	deadline := time.Now().Add(30 * time.Second)
	for !running {
		observation, observeErr := client.Inspect(ctx, containerId)
		if observeErr != nil {
			t.Fatalf("inspect after start: %v", observeErr)
		}
		if observation.State == runtime.PodmanAllocationStateRunning {
			if observation.ImageReference != liveSmokeImage {
				t.Fatalf("observed image = %q; want %q", observation.ImageReference, liveSmokeImage)
			}
			running = true
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("container never reached Running; last state %s", observation.State)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if err := client.Stop(ctx, containerId); err != nil {
		t.Fatalf("podman stop failed: %v", err)
	}
	stopped, err := client.Inspect(ctx, containerId)
	if err != nil {
		t.Fatalf("inspect after stop: %v", err)
	}
	if stopped.State != runtime.PodmanAllocationStateStopped {
		t.Fatalf("state after stop = %s; want Stopped", stopped.State)
	}

	if err := client.Delete(ctx, containerId); err != nil {
		t.Fatalf("podman rm failed: %v", err)
	}
	absent, err := client.Inspect(ctx, containerId)
	if err != nil {
		t.Fatalf("inspect after rm: %v", err)
	}
	if absent.State != runtime.PodmanAllocationStateAbsent {
		t.Fatalf("state after rm = %s; want Absent", absent.State)
	}
}

// liveSmokeSeccompProfile writes the smoke's seccomp profile document and
// returns its absolute path. The profile is deliberately permissive: the
// smoke proves the create/start plumbing loads a real profile document (the
// create fails when the document is absent), not the policy inside it.
func liveSmokeSeccompProfile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/terrascale-default-v1.json"
	if err := os.WriteFile(path, []byte(`{"defaultAction":"SCMP_ACT_ALLOW"}`), 0o600); err != nil {
		t.Fatalf("seccomp profile fixture: %v", err)
	}
	return path
}

// liveSmokePodmanBinary resolves the absolute podman binary: the explicit
// override first, then /usr/bin/podman, then the first absolute podman on
// PATH (the layout of this NixOS host).
func liveSmokePodmanBinary(t *testing.T) string {
	t.Helper()
	if override := os.Getenv("TS_ORCH_LIVE_PODMAN_BINARY"); override != "" {
		return override
	}
	if _, err := os.Stat("/usr/bin/podman"); err == nil {
		return "/usr/bin/podman"
	}
	return "/run/current-system/sw/bin/podman"
}

// liveSmokeArchitecture maps the host architecture onto the closed platform
// vocabulary of the run request.
func liveSmokeArchitecture() string {
	if goruntime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

// liveSmokeFingerprintPlaceholder supplies the 64-character lowercase
// fingerprint the fencing labels require; a smoke container carries the smoke
// marker instead of a canonical plan digest.
func liveSmokeFingerprintPlaceholder() string {
	const digits = "0123456789abcdef"
	fingerprint := make([]byte, 0, 64)
	for index := 0; index < 64; index++ {
		fingerprint = append(fingerprint, digits[index%len(digits)])
	}
	return string(fingerprint)
}
