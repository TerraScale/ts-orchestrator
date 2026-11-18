package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
)

func (l *lane) admissionGate(ctx context.Context, release published, original, base string) {
	target := l.release(release)
	for _, mode := range []string{"missing", "another", "unsigned"} {
		l.github.gateMode(release.tag, mode)
		reply := l.ask(ctx, "sjc-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: target})
		require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && strings.Contains(reply.Refusal.Reason, "staging gate"), "%s staging record admitted: %+v", mode, reply)
		fmt.Printf("production host refuses staging record %s: %s\n", mode, reply.Refusal.Reason)
	}
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
