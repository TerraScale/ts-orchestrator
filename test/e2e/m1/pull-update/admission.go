package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
)

func (l *lane) admissionGate(ctx context.Context, release published, original, base string) {
	target := l.release(release)
	for _, mode := range []string{"missing", "another", "unsigned", "rolled_back"} {
		l.github.gateMode(release.tag, mode)
		reply := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: target})
		require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && strings.Contains(reply.Refusal.Reason, "staging gate"), "%s staging record admitted: %+v", mode, reply)
		fmt.Printf("production host refuses staging record %s: %s\n", mode, reply.Refusal.Reason)
	}
	before := l.blockedSeconds(ctx, "sjc-w")
	alternate := l.github.prepare(target.SHA, "1010", asset, l.candidate("c101"), l.candidate("c101"), l.sigstore.Bundle(sigstore.MainIdentity, target.SHA, "1010", map[string][]byte{asset: l.candidate("c101")}))
	l.github.gateMode(alternate.tag, "missing")
	refused := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.release(alternate)})
	require(refused.Refusal != nil, "unapproved newer tag must refuse")
	after := l.blockedSeconds(ctx, "sjc-w")
	require(after >= before, "newest-tag change reset the receiver gate timer: %f to %f", before, after)
	fmt.Println("continuous receiver refusal is exported and survives newest-tag changes")
	l.github.gateMode(release.tag, "missing")
	identity := sigstore.Identity{Workflow: releasegate.Workflow, Ref: releaseattest.MainRef, Trigger: "workflow_dispatch"}
	now := time.Now().UTC().Truncate(time.Second)
	admission := releasegate.Attestation{Target: releasegate.ReleaseTarget(target), IssuedAt: now, ExpiresAt: now.Add(releasegate.Lifetime), Reason: "node E2E staging outage"}
	otherTag := admission
	otherTag.Tag = releaseattest.Tag(strings.Repeat("f", 40), "999")
	otherDigest := admission
	otherDigest.Binaries = map[string]string{}
	for arch := range admission.Binaries {
		otherDigest.Binaries[arch] = strings.Repeat("0", 64)
	}
	expired := admission
	expired.IssuedAt, expired.ExpiresAt = now.Add(-25*time.Hour), now.Add(-time.Hour)
	wrongWorkflow := identity
	wrongWorkflow.Workflow = strings.ReplaceAll(identity.Workflow, "staging-admission.yml", "outside-probe.yml")
	wrongRef := identity
	wrongRef.Ref = "refs/heads/feature"
	wrongRef.Workflow = strings.ReplaceAll(identity.Workflow, releaseattest.MainRef, wrongRef.Ref)
	wrongTrigger := identity
	wrongTrigger.Trigger = "push"
	for _, trial := range []struct {
		name      string
		identity  sigstore.Identity
		admission releasegate.Attestation
	}{
		{"another release", identity, otherTag},
		{"another binary digest", identity, otherDigest},
		{"expired", identity, expired},
		{"another workflow", wrongWorkflow, admission},
		{"another ref", wrongRef, admission},
		{"push trigger", wrongTrigger, admission},
	} {
		l.github.admission(release.tag, l.sigstore.Admission(trial.identity, l.build, "9001", trial.admission))
		reply := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: target})
		require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, "admission %s allowed installation: %+v", trial.name, reply)
		fmt.Printf("production host refuses admission %s\n", trial.name)
	}
	l.requireVersions(ctx, original, base, l.region("sjc", "fra", "gru")...)
	l.github.admission(release.tag, l.sigstore.Admission(identity, l.build, "9001", admission))
	for _, mode := range []string{"rolled_back", "withdrawn_without_completion"} {
		l.github.gateMode(release.tag, mode)
		reply := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: target})
		require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && strings.Contains(reply.Refusal.Reason, "staging gate withdrawn"),
			"valid main dispatch admitted a signed withdrawal in %s: %+v", mode, reply)
	}
	l.github.gateMode(release.tag, "missing")
	reply := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: target})
	require(reply.State == "installed", "valid main dispatch admission must install: %+v", reply)
	l.waitReady(ctx, "sjc.sjc-w", release.digest)
	host := l.hosts["sjc-w"]
	state, binary := filepath.Join(host.dir, "state"), filepath.Join(host.dir, "bin", "terrascale-orchestrator")
	ok, detail := releasepush.AdmissionDetail(state, binary)
	require(ok && detail == "admitted without staging by run 9001", "the observe check must retain authorizing run across restart: %t %s", ok, detail)
	var metrics bytes.Buffer
	releasepush.WriteReleaseMetrics(&metrics, state, binary)
	require(strings.Contains(metrics.String(), `ts_orch_release_staging_admission{`) && strings.Contains(metrics.String(), `run="9001"`), "break-glass admission must raise the existing production alert: %s", metrics.String())
	fmt.Printf("%s; retained after restart, production alert series exported\n", detail)
	l.github.admission(release.tag, nil)
}

func (l *lane) blockedSeconds(ctx context.Context, host string) float64 {
	message, err := l.conn.RequestWithContext(ctx, "e2e.release.metrics."+host, nil)
	must(err)
	for _, line := range strings.Split(string(message.Data), "\n") {
		if strings.HasPrefix(line, "ts_orch_release_staging_gate_blocked_seconds{") {
			fields := strings.Fields(line)
			value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
			must(err)
			return value
		}
	}
	panic("production receiver exports no blocked admission metric")
}

func (l *lane) bootAdmission(ctx context.Context, release published, identity sigstore.Identity, admission releasegate.Attestation) {
	prototype := l.hosts["sjc-w"]
	dir := filepath.Join(filepath.Dir(prototype.dir), "sjc-boot")
	state := filepath.Join(dir, "state")
	must(os.MkdirAll(filepath.Join(dir, "bin"), 0o700))
	must(os.MkdirAll(filepath.Join(state, "nats"), 0o700))
	binary := filepath.Join(dir, "bin", "terrascale-orchestrator")
	must(os.WriteFile(binary, l.candidate("c101"), 0o755))
	pending, err := json.Marshal(releasegate.Receipt{Target: admission.Target, Region: "sjc"})
	must(err)
	pendingPath := filepath.Join(state, "nats", "release-boot-admission.json")
	must(os.WriteFile(pendingPath, pending, 0o600))
	args := append([]string(nil), prototype.args...)
	args[1], args[3], args[4] = dir, "sjc-boot", "worker"
	l.github.gateMode(release.tag, "missing")
	l.github.admission(release.tag, nil)
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	require(err != nil && strings.Contains(string(output), "staging gate missing"), "unapproved fresh host booted: %v %s", err, output)
	require(strings.Contains(string(output), "admission") || strings.Contains(string(output), "staging gate"), "boot must refuse through admission")
	expired := admission
	expired.IssuedAt, expired.ExpiresAt = expired.IssuedAt.Add(-25*time.Hour), expired.ExpiresAt.Add(-25*time.Hour)
	l.github.admission(release.tag, l.sigstore.Admission(identity, l.build, "9000", expired))
	output, err = exec.CommandContext(ctx, binary, args...).CombinedOutput()
	require(err != nil && strings.Contains(string(output), "expired"), "expired configuration approval booted a fresh host: %v %s", err, output)
	l.github.admission(release.tag, l.sigstore.Admission(identity, l.build, "9001", admission))
	boot, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(boot, binary, args...)
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	must(command.Start())
	defer func() { cancel(); _ = command.Wait() }()
	l.waitReady(ctx, "sjc.sjc-boot", release.digest)
	ok, detail := releasepush.AdmissionDetail(state, binary)
	require(ok && detail == "admitted without staging by run 9001", "fresh host must retain its current authorizing run: %s", detail)
	_, err = os.Stat(pendingPath)
	require(os.IsNotExist(err), "fresh host must consume the pending boot admission")
	fmt.Println("fresh host refuses missing/expired approval, then verifies current approval before serving and retains its run")
}
