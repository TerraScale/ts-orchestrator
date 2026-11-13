package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
)

func budgetCases(ctx context.Context, conn, releases *nats.Conn, nodes, swarms []*process, boot func(int) *process, roots, order, names, addresses []string, launcher string, spec swarmruntime.ServiceSpec) {
	generation := declaration(ctx, conn, &spec, spec.Name, &mesh.Deployment{Repository: "TerraScale/terrascale", RunID: "100", RunAttempt: 1, Revision: revision, Image: spec.Image, Workflow: "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"})
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	budgetReconnected := conn.StatusChanged(nats.CONNECTED)
	nodes[0].kill()
	budgetBefore := evidence(ctx, roots[0], generation, func(r receipt) bool { return true })
	must(os.WriteFile(filepath.Join(roots[0], "budget-full"), nil, 0600))
	nodes[0] = boot(0)
	select {
	case <-budgetReconnected:
	case <-ctx.Done():
		panic(ctx.Err())
	}
	observe(ctx, conn, func(s map[string]state) bool {
		return s[order[0]].Failed[spec.Name] == generation && s[order[0]].Unsaved[spec.Name] == generation
	})
	budgetAfter := evidence(ctx, roots[0], generation, func(r receipt) bool { return true })
	require(budgetAfter.Interruptions == budgetBefore.Interruptions && budgetAfter.Bake.Started.Equal(budgetBefore.Bake.Started) && budgetAfter.Bake.Samples == budgetBefore.Bake.Samples, "full disk started an uncounted bake window")
	nodes[0].kill()
	must(os.Remove(filepath.Join(roots[0], "budget-full")))
	nodes[0] = boot(0)
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Interruptions == 1 })
	logStep("full disk at budget advance reports failed unsaved without starting a window")
	for interruption := 2; interruption <= 3; interruption++ {
		reconnect := conn.StatusChanged(nats.CONNECTED)
		nodes[0].kill()
		nodes[0] = boot(0)
		select {
		case <-reconnect:
		case <-ctx.Done():
			panic(ctx.Err())
		}
		interrupted := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Interruptions == interruption })
		if interruption < 3 {
			require(interrupted.Bake.Reason == "" && interrupted.Bake.Finished.IsZero(), "interruption held before the limit")
		} else {
			require(strings.Contains(interrupted.Bake.Reason, "could not complete") && !interrupted.Bake.Finished.IsZero(), "third interruption did not save a finished hold")
		}
	}
	assertWaiting(ctx, conn, order[1], spec.Name, generation, order[0], "bake failed")
	logStep("three interrupted bake windows save a hold at the limit and not before")
	pid, err := os.ReadFile(filepath.Join(roots[0], "containerd.pid"))
	must(err)
	runtimePID := strings.TrimSpace(string(pid))
	must(exec.Command("kill", "-STOP", runtimePID).Run())
	defer func() { _ = exec.Command("kill", "-CONT", runtimePID).Run() }()
	require(len(states(ctx, conn)) == 3, "mesh stopped with containerd")
	response, err := http.Get("http://" + addresses[0] + ":18085/health")
	must(err)
	response.Body.Close()
	require(response.StatusCode == http.StatusOK, "shim task stopped with containerd")
	namedHealth, unnamedHealth := health(ctx, releases, spec.Name), health(ctx, releases, "")
	require(strings.Contains(namedHealth, "container runtime unreachable"), "stopped runtime health omitted the runtime failure: "+namedHealth)
	require(strings.Contains(unnamedHealth, "container runtime unreachable"), "stopped runtime health omitted the runtime failure: "+unnamedHealth)
	logStep("stopped runtime fails health while mesh, swarm agent and shim-owned service remain alive")
	must(exec.Command("kill", "-CONT", runtimePID).Run())
	require(health(ctx, releases, "") == "ok", "runtime did not recover before swarm-only case")
	sampler := start(ctx, names[0], launcher, roots[0], "sampler")
	fifo := filepath.Join(roots[0], "blocked-stat")
	must(syscall.Mkfifo(fifo, 0600))
	output, err := exec.CommandContext(ctx, "nsenter", "-t", fmt.Sprint(sampler.command.Process.Pid), "-m", "mount", "--bind", fifo, "/proc/stat").CombinedOutput()
	require(err == nil, fmt.Sprintf("isolated host sampler FIFO mount: %v %s", err, output))
	must(os.WriteFile(filepath.Join(roots[0], "sample"), nil, 0600))
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(roots[0]))
	for {
		if _, err := os.Stat(filepath.Join(roots[0], "blocked")); err == nil {
			break
		}
		select {
		case <-watcher.Events:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	output, err = exec.CommandContext(ctx, "nsenter", "-t", fmt.Sprint(sampler.command.Process.Pid), "-m", "umount", "-l", "/proc/stat").CombinedOutput()
	require(err == nil, fmt.Sprintf("host sampler unblock: %v %s", err, output))
	must(os.WriteFile(filepath.Join(roots[0], "unblocked"), nil, 0600))
	select {
	case <-sampler.done:
		require(sampler.result == nil, fmt.Sprintf("host sampler journey: %v", sampler.result))
	case <-ctx.Done():
		panic(ctx.Err())
	}
	logStep("host health abandons a blocked read and recovers after the path becomes readable")
	swarms[0].stop()
	swarms[0] = nil
	require(len(states(ctx, conn)) == 3, "mesh stopped with the swarm node")
	require(health(ctx, releases, "") != "ok", "unnamed binary health ignored the unavailable swarm node")
	logStep("unnamed orchestrator health fails while mesh is up and the swarm node is unavailable")

}

func unsavedCase(ctx context.Context, conn, releases *nats.Conn, key *rsa.PrivateKey, nodes []*process, boot func(int) *process, roots, order, addresses []string, spec swarmruntime.ServiceSpec) {
	previous := newGeneration(states(ctx, conn), order[0])
	signedRelease(ctx, releases, key, spec.Image, "99")
	observe(ctx, conn, func(s map[string]state) bool { return newGeneration(s, order[0]) > previous })
	generation := newGeneration(states(ctx, conn), order[0])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	setHealth(ctx, addresses[0], 18085, "503")
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.FailedSamples >= 8 })
	readonly(nodes[0], filepath.Join(roots[0], "mesh"))
	observe(ctx, conn, func(s map[string]state) bool {
		return s[order[0]].Failed[spec.Name] == generation && s[order[0]].Unsaved[spec.Name] == generation
	})
	assertWaiting(ctx, conn, order[1], spec.Name, generation, order[0], "bake failed")
	disk := evidence(ctx, roots[0], generation, func(r receipt) bool { return true })
	require(disk.Bake.Reason == "" && disk.Bake.FailedSamples >= 8, "read-only disk unexpectedly saved the terminal failure")
	meshReconnected := conn.StatusChanged(nats.CONNECTED)
	healthReconnected := releases.StatusChanged(nats.CONNECTED)
	nodes[0].kill()
	nodes[0] = nil
	setHealth(ctx, addresses[0], 18085, "200")
	nodes[0] = boot(0)
	for _, connected := range []chan nats.Status{meshReconnected, healthReconnected} {
		select {
		case <-connected:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	restartedUnsaved := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Started.After(disk.Bake.Started) })
	require(restartedUnsaved.Interruptions == disk.Interruptions+1, "possible unsaved failure was not counted as an interruption")
	log, err := os.ReadFile(filepath.Join(roots[0], "region.log"))
	must(err)
	require(strings.Contains(string(log), "may have an unsaved failure"), "possible unsaved failure restart was not logged")
	require(restartedUnsaved.Bake.Finished.IsZero(), "unsaved failure restart skipped the new window")
	unsavedPassed := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(unsavedPassed.Bake.Reason == "" && unsavedPassed.Bake.Finished.Sub(restartedUnsaved.Bake.Started) >= rollout.BakeWindow, "unsaved failure restart did not run a full healthy window")
	evidence(ctx, roots[1], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	logStep("failure write refused reports failed unsaved; restart runs a full new window whose pass admits the next region")
}
