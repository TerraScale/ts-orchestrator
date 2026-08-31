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

// liveSmokeTimeout bounds the whole smoke run.
const liveSmokeTimeout = 90 * time.Second

// TestSystemdUserPodmanClientRootlessSmoke drives the real production client
// under the current unprivileged account. Preflight proves both rootless
// Podman and the systemd user manager; start creates a fenced transient unit;
// inspect observes the joined container and unit state; stop goes through the
// unit's ExecStop; delete removes the container. The create also loads the
// configured seccomp profile. The container is removed on every exit path.
func TestSystemdUserPodmanClientRootlessSmoke(t *testing.T) {
	if os.Getenv("TS_ORCH_LIVE") != "1" {
		t.Skip("live rootless podman smoke: set TS_ORCH_LIVE=1 (and build with -tags live_podman) to run")
	}
	podmanBinary := liveSmokePodmanBinary(t)
	image := liveSmokeImage(t)
	uid := uint32(os.Getuid())
	xdgRuntimeDir := fmt.Sprintf("/run/user/%d", uid)
	rootless, err := runtime.NewRootlessPodmanContext(
		podmanBinary, xdgRuntimeDir, liveSmokeSeccompProfile(t), uid)
	if err != nil {
		t.Fatalf("rootless context (uid %d, %s, %s): %v", uid, podmanBinary, xdgRuntimeDir, err)
	}
	runner := runtime.ProcessHostCommandRunner{}
	processClient, err := runtime.NewProcessPodmanClient(rootless, runner)
	if err != nil {
		t.Fatalf("podman client: %v", err)
	}
	client, err := runtime.NewSystemdUserPodmanClient(
		processClient,
		rootless,
		liveSmokeBinary("TS_ORCH_LIVE_SYSTEMCTL_BINARY", "/usr/bin/systemctl"),
		liveSmokeBinary("TS_ORCH_LIVE_SYSTEMD_RUN_BINARY", "/usr/bin/systemd-run"),
		runner,
	)
	if err != nil {
		t.Fatalf("systemd user podman client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), liveSmokeTimeout)
	defer cancel()

	if err := client.Preflight(ctx); err != nil {
		t.Fatalf("rootless podman preflight failed: %v", err)
	}

	containerId := "terrascale-live-smoke-" + strconv.Itoa(os.Getpid())
	request, err := runtime.NewPodmanRunRequest(
		containerId,
		image,
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
			if observation.ImageReference != image {
				t.Fatalf("observed image = %q; want %q", observation.ImageReference, image)
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

func liveSmokeImage(t *testing.T) string {
	t.Helper()
	image := os.Getenv("TS_ORCH_LIVE_PODMAN_IMAGE")
	if image == "" {
		t.Fatal("TS_ORCH_LIVE_PODMAN_IMAGE must name an image already present in the rootless store")
	}
	return image
}

func liveSmokeBinary(environment string, defaultPath string) string {
	if override := os.Getenv(environment); override != "" {
		return override
	}
	return defaultPath
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
