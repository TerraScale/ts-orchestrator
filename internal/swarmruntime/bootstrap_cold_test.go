package swarmruntime

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

func coldPins() ColdBootstrap {
	owner := rolloutmaintenance.Job{ID: "cold-owner", Member: "fra-2", Owner: "fra-2", Epoch: 7, Phase: "held", Process: rolloutmaintenance.Process{PID: 1, Start: 1},
		Source: rolloutmaintenance.Pin{Node: "worker", Service: "terrabase", Task: "old-owner", Image: "registry/app@sha256:" + strings.Repeat("a", 64), Fingerprint: strings.Repeat("a", 64)},
		Target: rolloutmaintenance.Pin{Node: "worker", Service: "terrabase", Image: "registry/app@sha256:" + strings.Repeat("b", 64)}}
	local := owner
	local.ID, local.Member, local.Source.Node, local.Target.Node, local.Source.Task = "cold-founder", "fra-1", "founder", "founder", "old-follower"
	return ColdBootstrap{Local: local, Owner: owner}
}

func TestColdBootstrapRetainsTheWorkerOwnersIngressOnTheFounder(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dir := t.TempDir()
	input := coldPins()
	if err := retainColdBootstrap(ctx, dir, input); err != nil {
		t.Fatal(err)
	}
	if err := retainColdBootstrap(ctx, dir, input); err != nil {
		t.Fatal("exact interrupted offline arm must resume", err)
	}
	reopened, err := rolloutmaintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	local, err := reopened.Status(ctx)
	if err != nil || local == nil || *local != input.Local {
		t.Fatal(local, err)
	}
	owner, err := reopened.Ingress(ctx)
	if err != nil || owner == nil || *owner != input.Owner {
		t.Fatal(owner, err)
	}
	if err := reopened.Publication(ctx, "terrabase"); err == nil {
		t.Fatal("cold arm allowed automatic publication")
	}
}

func TestColdBootstrapRejectsLiveSourceRuntimeAndInconsistentPins(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	process := exec.Command("sleep", "60")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	identity, err := processIdentity(uint32(process.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := coldProcessExited(identity); err == nil {
		t.Fatal("live source accepted")
	}
	_ = process.Process.Kill()
	_ = process.Wait()
	if err := coldProcessExited(identity); err != nil {
		t.Fatal("physical exit refused", err)
	}
	socket := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := coldRuntimeStopped(ctx, socket); err == nil {
		t.Fatal("running runtime accepted")
	}
	_ = listener.Close()
	if err := coldRuntimeStopped(ctx, socket); err != nil {
		t.Fatal("stopped runtime refused", err)
	}
	for _, corrupt := range []func(*ColdBootstrap){
		func(p *ColdBootstrap) { p.Owner.Epoch++ },
		func(p *ColdBootstrap) { p.Local.Deadline = time.Now() },
		func(p *ColdBootstrap) { p.Owner.Target.Image = p.Owner.Source.Image },
	} {
		input := coldPins()
		corrupt(&input)
		if err := retainColdBootstrap(ctx, t.TempDir(), input); err == nil {
			t.Fatal("inconsistent cold pins accepted")
		}
	}
}
