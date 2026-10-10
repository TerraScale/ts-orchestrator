package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

func nativeTestTrust(t *testing.T, root string) testSpecTrust {
	t.Helper()
	return newTestSpecTrust(t, root, cellspec.Identity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"})
}

func applyNativeTestSpec(t *testing.T, cfg Config, runtime *natscell.Runtime, keys testSpecTrust, services []cellspec.Service, generation uint64) {
	t.Helper()
	path := keys.signRoot(t, t.TempDir(), cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity,
		Generation: generation, RequiresBinary: cellspec.BinaryLevel, Services: services})
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := requestCellSpec(t.Context(), cfg, runtime, cellSpecApplyKind, wire); err != nil {
		t.Fatal(err)
	}
}

// This controller reads the real ordered host log and rechecks real sessions;
// the test copy cannot commit host mutations or serve host RPCs.
type nativeReadOnlyMutations struct{ *authority.Reader }

func (nativeReadOnlyMutations) CommitHostMutation(context.Context, uint64, authority.HostMutationKind, string, string, uint64, []byte) (uint64, error) {
	return 0, authority.ErrFenced
}

func nativeTestHistory(t *testing.T, cfg Config, runtime *natscell.Runtime, service *delivery.Service, fencer authority.Fencer) *nativeHistory {
	t.Helper()
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.open(t.Context(), runtime.JetStream(), 1); err != nil {
		t.Fatal(err)
	}
	kv, err := openNativeHistory(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := authority.OpenReader(t.Context(), runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		t.Fatal(err)
	}
	key, err := readPrivateKey(cfg.Controller.ResponseKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := host.NewController(t.Context(), host.ControllerConfig{Cell: cfg.NATS.Cell,
		Conn: runtime.Conn(), JS: runtime.JetStream(), Artifacts: service.Artifacts(), StateReplicas: 1,
		HostMutations: nativeReadOnlyMutations{reader}, ResponseKey: key,
		AuthorityEpoch: func() uint64 { return fencer.Current().Epoch }, AuthorityGuard: fencer.Guard})
	if err != nil {
		t.Fatal(err)
	}
	return &nativeHistory{kv: kv, js: runtime.JetStream(), services: registry, deliveries: service,
		hosts: controller, fencer: fencer, cfg: cfg}
}

func TestNativeGoodProofRejectsIncompleteEvidence(t *testing.T) {
	now := time.Now().UTC()
	profile := WorkloadProfile{Args: []string{"a"}, Env: map[string]string{"setting": "A"}}
	intent := delivery.Intent{Cell: "gru", Role: terrabase.Role, Environment: "test", ArtifactDigest: strings.Repeat("a", 64),
		ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, nil), Generation: 3, DesiredReplicas: 2}
	desired := []host.Desired{}
	statuses := []host.HostStatus{}
	for _, node := range []string{"a", "b"} {
		desired = append(desired, host.Desired{Cell: "gru", Node: node, Role: terrabase.Role, Environment: "test", Digest: intent.ArtifactDigest,
			Generation: 3, Args: profile.Args, Env: profile.Env})
		statuses = append(statuses, host.HostStatus{Verified: true, SessionExpiresAt: now.Add(time.Minute),
			Registration: host.Registration{Cell: "gru", Node: node, Environment: "test", Roles: []string{terrabase.Role}},
			Reports: []host.Report{{Cell: "gru", Node: node, Role: terrabase.Role, Environment: "test", Digest: intent.ArtifactDigest,
				Generation: 3, SessionID: entityid.New(), Epoch: 1, State: "running", ObservedAt: now}}})
	}
	if nodes, err := nativeReady(statuses, desired, intent, now); err != nil || !slices.Equal(nodes, []string{"a", "b"}) {
		t.Fatalf("valid proofs: %v, %v", nodes, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]host.HostStatus, []host.Desired)
	}{
		{"expired session", func(s []host.HostStatus, _ []host.Desired) { s[0].SessionExpiresAt = now }},
		{"unverified", func(s []host.HostStatus, _ []host.Desired) { s[0].Verified = false }},
		{"future", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports[0].ObservedAt = now.Add(time.Nanosecond) }},
		{"expired report", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports[0].ObservedAt = now.Add(-host.ReportMaxAge) }},
		{"duplicate report", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports = append(s[0].Reports, s[0].Reports[0]) }},
		{"duplicate host", func(s []host.HostStatus, _ []host.Desired) { s[1] = s[0] }},
		{"missing report", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports = nil }},
		{"failed", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports[0].State = "failed" }},
		{"wrong node", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports[0].Node = "other" }},
		{"wrong generation", func(s []host.HostStatus, _ []host.Desired) { s[0].Reports[0].Generation++ }},
		{"wrong config", func(_ []host.HostStatus, d []host.Desired) { d[0].Env = map[string]string{"setting": "B"} }},
		{"duplicate expected node", func(_ []host.HostStatus, d []host.Desired) { d[1] = d[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := slices.Clone(statuses)
			for i := range s {
				s[i].Reports = slices.Clone(s[i].Reports)
			}
			d := slices.Clone(desired)
			tc.mutate(s, d)
			if nodes, _ := nativeReady(s, d, intent, now); len(nodes) != 0 {
				t.Fatalf("invalid proof marked good: %v", nodes)
			}
		})
	}
}

func TestNativeGoodRetentionKeepsTenSuccessfulProfiles(t *testing.T) {
	state := nativeReleaseHistory{Schema: 1}
	for i := range 14 {
		p := WorkloadProfile{Env: map[string]string{"revision": string(rune('a' + i))}}
		b := nativeReleaseBinding{Artifact: delivery.ArtifactRecord{Digest: strings.Repeat(string(rune('a'+i%6)), 64)},
			Profile: p, ProfileDigest: nativeProfileDigest(p)}
		addNativeGood(&state, nativeGoodRelease{Binding: b, Nodes: []string{"node-a"}, GoodAt: time.Now()})
		state.Pending = &nativeReleaseBinding{Artifact: delivery.ArtifactRecord{Digest: strings.Repeat("f", 64)}, ProfileDigest: "failed"}
	}
	if len(state.Good) != nativeGoodLimit || state.Good[0].Binding.Profile.Env["revision"] != "n" || state.Good[9].Binding.Profile.Env["revision"] != "e" {
		t.Fatalf("good retention: %+v", state.Good)
	}
	for _, good := range state.Good {
		if good.Binding.ProfileDigest == "failed" {
			t.Fatal("failed candidate consumed a good slot")
		}
	}
	wire, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var saved nativeReleaseHistory
	if err := json.Unmarshal(wire, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Good) != 10 {
		t.Fatal("history was not persisted")
	}
}

func TestNativeRollbackTemplateKeepsRestoredFullConfig(t *testing.T) {
	profile, _ := tsAuthGRUConfig(t)
	profile.Args = []string{"--restored"}
	profile.Env = maps.Clone(profile.Env)
	profile.Env["NONSECRET_SETTING"] = "A"
	gen, _ := workload.ReleaseGeneration(3)
	old := host.Desired{Node: "ctl-1", Generation: gen, Digest: strings.Repeat("a", 64), Args: profile.Args, Env: profile.Env, Secrets: profile.Secrets}
	failed := old
	failed.Node = "ctl-2"
	failed.Generation, _ = workload.ReleaseGeneration(2)
	failed.Env = maps.Clone(old.Env)
	failed.Env["NONSECRET_SETTING"] = "B"
	release, err := workload.CurrentRelease(workload.Observation{HighWater: gen, Active: map[string]host.Desired{"ctl-1": old, "ctl-2": failed}})
	if err != nil || release.Template.Env["NONSECRET_SETTING"] != "A" || !slices.Equal(release.Template.Args, profile.Args) || !maps.Equal(release.Template.Secrets, profile.Secrets) {
		t.Fatalf("reconciler selected failed config: %+v, %v", release, err)
	}
}

func seedNativeTestBinding(t *testing.T, history *nativeHistory, intent delivery.Intent, previous string, recovery *delivery.Intent) {
	t.Helper()
	state, revision, err := history.load(t.Context(), intent.Role)
	if err != nil {
		t.Fatal(err)
	}
	var target *nativeGoodRelease
	for _, good := range state.Good {
		if good.Binding.Artifact.Digest == previous {
			copy := good
			target = &copy
			break
		}
	}
	if previous != "" && target == nil {
		t.Fatalf("seed requires a retained proven-good target: %s", previous)
	}
	profile := history.services.profiles()[intent.Role]
	provenance, err := history.currentProvenance(t.Context(), intent.Role, profile)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := history.deliveries.ResolveAdmittedArtifact(t.Context(), intent.ArtifactDigest, intent.Role, intent.Environment)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := nativeBinding(intent, artifact, profile, provenance)
	if err != nil {
		t.Fatal(err)
	}
	binding.Deadline = time.Now().Add(time.Minute)
	state.Pending, state.Previous, state.Recovery, state.Rejected = &binding, target, nil, ""
	if recovery != nil {
		recovery.ConfigDigest = target.Binding.Intent.ConfigDigest
		recovery.DesiredReplicas = target.Binding.Intent.DesiredReplicas
		recovery.Generation = intent.Generation + 1
		b, err := nativeBinding(*recovery, target.Binding.Artifact, target.Binding.Profile, target.Binding.Provenance)
		if err != nil {
			t.Fatal(err)
		}
		b.Deadline = time.Now().Add(time.Minute)
		state.Recovery, state.Rejected = &b, binding.Fingerprint
	}
	if err := history.save(t.Context(), history.fencer.Current().Epoch, intent.Role, state, revision); err != nil {
		t.Fatal(err)
	}
}

// The competing writer advances the real head before the attempted CAS.
type nativeConflictingKV struct{ jetstream.KeyValue }

func (k nativeConflictingKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	entry, err := k.KeyValue.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	if _, err := k.KeyValue.Update(ctx, key, entry.Value(), revision); err != nil {
		return 0, err
	}
	return k.KeyValue.Update(ctx, key, value, revision)
}

type nativeDeniedFence struct{ authority.Fencer }

func (nativeDeniedFence) Guard(context.Context, uint64) error { return authority.ErrFenced }

func checkNativeHistoryMutationFailures(t *testing.T, h *nativeHistory) {
	t.Helper()
	ctx, role := t.Context(), terrabase.Role
	before, _, err := h.load(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	desiredBefore, err := h.hosts.ListDesired(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	good := before.Good[0]
	profile := h.services.profiles()[role]
	intent := nativeIntent(good.Binding.Artifact, nativeRelease{Role: role, Replicas: good.Binding.Intent.DesiredReplicas, Profile: profile}, nextReleaseGeneration(desiredBefore))
	intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, entityid.New(), h.fencer.Current().Epoch
	fencer := h.fencer
	h.fencer = nativeDeniedFence{fencer}
	_, err = h.prepare(ctx, nativePrepareRequest{Intent: intent, Deadline: time.Now().Add(time.Minute)})
	h.fencer = fencer
	if !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("unguarded prepare: %v", err)
	}
	kv := h.kv
	h.kv = nativeConflictingKV{kv}
	_, err = h.prepare(ctx, nativePrepareRequest{Intent: intent, Deadline: time.Now().Add(time.Minute)})
	h.kv = kv
	if !errors.Is(err, jetstream.ErrKeyExists) {
		t.Fatalf("competing CAS was accepted: %v", err)
	}
	after, revision, err := h.load(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	if after.Pending.Fingerprint != before.Pending.Fingerprint || after.Recovery.Fingerprint != before.Recovery.Fingerprint {
		t.Fatal("failed prepare selected a new target")
	}
	if receipt, err := h.deliveries.StatusFor(ctx, intent); !errors.Is(err, delivery.ErrPending) {
		t.Fatalf("failed prepare submitted: %+v, %v", receipt, err)
	}
	// Oversized private proof refuses before metadata/reference changes.
	oversized := after
	copy := *after.Pending
	copy.Provenance.Config = make([]byte, nativeHistoryMaxBytes)
	oversized.Pending = &copy
	if err := h.save(ctx, intent.AuthorityEpoch, role, oversized, revision); err == nil {
		t.Fatal("oversized provenance was persisted")
	}
	if _, got, err := h.load(ctx, role); err != nil || got != revision {
		t.Fatalf("oversized state changed reference: %d, %v", got, err)
	}
	// Missing admitted bytes refuse a newly published reference.
	missing := after
	copy = *after.Pending
	copy.Artifact.Digest = strings.Repeat("f", 64)
	missing.Pending = &copy
	if err := h.save(ctx, intent.AuthorityEpoch, role, missing, revision); err == nil {
		t.Fatal("missing bytes gained a durable reference")
	}
	if _, got, err := h.load(ctx, role); err != nil || got != revision {
		t.Fatalf("missing bytes changed reference: %d, %v", got, err)
	}
	desiredAfter, err := h.hosts.ListDesired(ctx, role)
	left, _ := json.Marshal(desiredBefore, json.Deterministic(true))
	right, _ := json.Marshal(desiredAfter, json.Deterministic(true))
	if err != nil || string(left) != string(right) {
		t.Fatalf("failed preparation touched hosts: %v", err)
	}
}

func TestNativePrepareReplyKeepsProvenancePrivateAndBounded(t *testing.T) {
	good := &nativeGoodRelease{Binding: nativeReleaseBinding{Artifact: delivery.ArtifactRecord{Digest: strings.Repeat("a", 64)},
		Intent:     delivery.Intent{ConfigDigest: strings.Repeat("b", 64), DesiredReplicas: 3},
		Profile:    WorkloadProfile{Env: map[string]string{"PRIVATE_CONTROLLER_SETTING": "internal"}},
		Provenance: nativeProfileProvenance{Config: make([]byte, 2<<20), Manifest: []byte("signed"), MaterialChain: make([]byte, 2<<20)}}}
	wire, err := encodeNativeReply(nativePrepareReply{Previous: nativeTarget(good), previous: good}, 1<<20)
	if err != nil || len(wire) > 2048 || strings.Contains(string(wire), "PRIVATE_CONTROLLER_SETTING") || strings.Contains(string(wire), "provenance") {
		t.Fatalf("proof leaked in prepare reply: %d bytes, %v", len(wire), err)
	}
	if _, err := encodeNativeReply(nativePrepareReply{Previous: nativeTarget(good)}, 128); err == nil {
		t.Fatal("small broker payload bound ignored")
	}
	if _, err := encodeNativeReply(nativePrepareReply{Error: strings.Repeat("x", maxRegistrationBytes+1)}, 1<<20); err == nil {
		t.Fatal("large public reply accepted")
	}
}

func TestNativeGoodNeedsFreshReportsAcrossObservation(t *testing.T) {
	at := time.Now()
	first := map[string]host.Report{"a": {SessionID: "one", Epoch: 1, Generation: 3, Digest: "good", ObservedAt: at}}
	second := maps.Clone(first)
	if nativeProofsAdvance(first, second) {
		t.Fatal("one running snapshot certified good")
	}
	next := second["a"]
	next.ObservedAt = at.Add(time.Second - time.Nanosecond)
	second["a"] = next
	if nativeProofsAdvance(first, second) {
		t.Fatal("early running snapshot certified good")
	}
	next.ObservedAt = at.Add(time.Second)
	second["a"] = next
	if !nativeProofsAdvance(first, second) {
		t.Fatal("complete observation refused")
	}
	next.SessionID = "renewed"
	second["a"] = next
	if nativeProofsAdvance(first, second) {
		t.Fatal("proofs from different sessions combined")
	}
}

func checkNativeHistoryCanaryCannotCertifyEarlyRunning(t *testing.T, h *nativeHistory) {
	t.Helper()
	ctx, role := t.Context(), terrabase.Role
	original, revision, err := h.load(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	active := original.Pending
	if original.Recovery != nil {
		active = original.Recovery
	}
	intent := active.Intent
	candidate := original
	candidate.Good = slices.DeleteFunc(slices.Clone(original.Good), func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == active.Fingerprint })
	// Model a forward proof for the current serving operation, not a recovery.
	candidate.Pending, candidate.Recovery, candidate.Rejected = active, nil, ""
	binding := *candidate.Pending
	binding.Deadline = time.Now().Add(time.Minute)
	candidate.Pending = &binding
	if err := h.save(ctx, h.fencer.Current().Epoch, role, candidate, revision); err != nil {
		t.Fatal(err)
	}
	kv, err := h.js.KeyValue(ctx, releasechannel.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := h.hosts.ListDesired(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	if nodes, err := h.ready(ctx, intent); err != nil || len(nodes) == 0 {
		t.Fatalf("test needs early valid running snapshot: %v,%v", nodes, err)
	}
	backend := lb.Backend{IP: "10.0.0.11", Port: 9465}
	balancer := &fenceLB{t: t, sets: map[string][]lb.Backend{role: {backend, {IP: "10.0.0.12", Port: 9465}}}, down: map[string]bool{}}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "test-lb", BackendSets: []cellspec.FencedSet{{Name: role, Port: 9465, MinServing: 1}}, Canary: &cellspec.Canary{Project: "native-history-test"}}
	fence := &releaseFence{kv: kv, hosts: h.hosts, fencer: h.fencer, spec: func() (*cellspec.ReleaseFence, map[string]string) {
		return spec, map[string]string{desired[0].Node: backend.IP}
	},
		open: func(context.Context) (lb.API, error) { return balancer, nil }, sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }}
	oldFence, oldCanary := h.fences, h.canary
	h.fences = fence
	calls := 0
	h.canary = func(context.Context, canaryTarget) map[string]string {
		calls++
		return map[string]string{checkDocuments: "candidate regression"}
	}
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	empty := nativeReleaseHistory{Schema: 1}
	if good, err := h.baseline(ctx, role, &empty); good != nil || !errors.Is(err, errBadRelease) || len(empty.Good) != 0 {
		t.Fatalf("empty baseline bypassed current canary: %+v,%v", good, err)
	}
	ready, observeErr := h.observe(ctx, intent)
	h.fences, h.canary = oldFence, oldCanary
	if ready || !errors.Is(observeErr, errBadRelease) || calls == 0 {
		t.Fatalf("early running bypassed failed canary: %v,%v,calls=%d", ready, observeErr, calls)
	}
	failed, head, err := h.load(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(failed.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == binding.Fingerprint }) {
		t.Fatal("failed canary became good")
	}
	// Remove this test's profile rejection and fence; the real prior recovery remains good.
	if err := h.kv.Delete(ctx, nativeBadProfileKey(binding)); err != nil {
		t.Fatal(err)
	}
	spec = nil
	if err := fence.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.save(ctx, h.fencer.Current().Epoch, role, original, head); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDesiredRefusesContendedAdoptionBeforeWrites(t *testing.T) {
	for _, lock := range []string{"release effects", "spec adoption"} {
		t.Run(lock, func(t *testing.T) {
			h := &nativeHistory{services: &specRegistry{}}
			var unlock func()
			if lock == "release effects" {
				h.effects.Lock()
				unlock = h.effects.Unlock
			} else {
				h.services.launches.Lock()
				unlock = h.services.launches.Unlock
			}
			defer unlock()
			done := make(chan error, 1)
			go func() { _, err := h.ApplyDesired(t.Context(), host.Desired{Role: terrabase.Role}); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, delivery.ErrConflict) {
					t.Fatalf("contended native write reached lookup/hosts: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("native write waited while spec adoption can wait for reconciler writes")
			}
		})
	}
}
