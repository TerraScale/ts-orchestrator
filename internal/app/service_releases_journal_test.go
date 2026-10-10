package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// Inspect the real durable channel head at the native CAS, not a callback's
// in-memory state. The handoff must already contain the exact native request.
type nativeJournalCheckedKV struct {
	jetstream.KeyValue
	t         *testing.T
	channel   jetstream.KeyValue
	key       string
	committed bool
}

func (k *nativeJournalCheckedKV) check(key string, wire []byte) {
	if key != terrabase.Role {
		return
	}
	state, _, err := loadServiceRelease(k.t.Context(), k.channel, k.key)
	if err != nil || state.Preparation == nil {
		k.t.Fatalf("native CAS without persisted channel preparation: %v", err)
	}
	var history nativeReleaseHistory
	if err := json.Unmarshal(wire, &history); err != nil {
		k.t.Fatal(err)
	}
	binding := history.Pending
	if state.Preparation.RecoveryOf != "" {
		binding = history.Recovery
	}
	fp, err := state.Preparation.Intent.Fingerprint()
	if err != nil || binding == nil || binding.Fingerprint != fp {
		k.t.Fatalf("native CAS differs from channel request: %v", err)
	}
}

func (k *nativeJournalCheckedKV) Create(ctx context.Context, key string, wire []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	k.check(key, wire)
	rev, err := k.KeyValue.Create(ctx, key, wire, opts...)
	if err == nil && key == terrabase.Role {
		k.committed = true
	}
	return rev, err
}
func (k *nativeJournalCheckedKV) Update(ctx context.Context, key string, wire []byte, prev uint64) (uint64, error) {
	k.check(key, wire)
	rev, err := k.KeyValue.Update(ctx, key, wire, prev)
	if err == nil && key == terrabase.Role {
		k.committed = true
	}
	return rev, err
}

func TestNativeChannelHandoffsSurviveNativeCASBeforeChannelCAS(t *testing.T) {
	for _, phase := range []string{"initial", "forward refresh", "initial recovery", "recovery refresh"} {
		t.Run(phase, func(t *testing.T) {
			f := newRetainedConsumerFixture(t)
			profile := nativeRegressionProfile()
			proof := nativeRegressionAdopt(t, f, profile, 1)
			previous := f.binding(t, terrabase.Role, profile, proof, 1)
			pending := f.binding(t, terrabase.Role, profile, proof, 2)
			kv, err := openChannelBucket(t.Context(), f.history.js, 1)
			if err != nil {
				t.Fatal(err)
			}
			key := releasechannel.ServiceStatusKey("GRU", terrabase.Role)
			bucket := newChannelBucket()
			location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
			claim, err := f.codec.SignArtifact(t.Context(), pending.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			bucket.objects[releasechannel.ServiceBinaryObject(terrabase.Role, pending.Artifact.Digest)] = []byte(fmt.Sprintf("%s release %d", terrabase.Role, 2))
			bucket.objects[releasechannel.ServiceReleaseObject(terrabase.Role)] = claim
			sum := sha256.Sum256(claim)
			state := serviceReleaseState{Claim: hex.EncodeToString(sum[:]), IssuedAt: time.Now().UTC(), Digest: pending.Artifact.Digest, Actor: servicePinsActor,
				State: releasechannel.StateRolling, claim: claim, location: location}
			fence := rolloutTestFence{epoch: 7}
			r := &serviceReleases{js: f.history.js, cell: "gru", deliveries: f.history.deliveries, hosts: f.history.hosts, history: f.history, fencer: fence,
				profiles: f.history.services.profiles, channel: &channelSource{location: &location}}
			history := nativeReleaseHistory{Schema: 1, Pending: &pending, Previous: &nativeGoodRelease{Binding: previous, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()},
				Good: []nativeGoodRelease{{Binding: previous, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()}}}
			if phase != "initial" {
				state.Intent, state.Previous = &pending.Intent, previous.Artifact.Digest
				if phase == "initial recovery" {
					state.IssuedAt = time.Now().Add(-rollout.ObservationBudget)
					history.Pending.Deadline = state.IssuedAt.Add(rollout.ObservationBudget)
				}
				if phase == "recovery refresh" {
					recovery := previous
					recovery.Intent.OperationID, recovery.Intent.Generation = entityid.New(), 3
					recovery.Fingerprint, _ = recovery.Intent.Fingerprint()
					history.Recovery, history.Rejected = &recovery, pending.Fingerprint
					state.Rollback = &recovery.Intent
				}
				f.save(t, terrabase.Role, history)
				if phase != "initial recovery" {
					r.fencer = rolloutTestFence{epoch: 8}
					f.history.fencer = r.fencer
				}
			}
			var revision uint64
			revision, err = saveServiceRelease(t.Context(), kv, key, state, revision)
			if err != nil {
				t.Fatal(err)
			}
			checked := &nativeJournalCheckedKV{KeyValue: f.history.kv, t: t, channel: kv, key: key}
			f.history.kv = checked
			save := func(next serviceReleaseState) error {
				if checked.committed && next.Preparation == nil {
					return authority.ErrFenced
				}
				var err error
				revision, err = r.save(t.Context(), kv, key, next, revision, r.fencer.Current().Epoch)
				return err
			}
			_, err = r.release(t.Context(), kv, terrabase.Role, state, r.fencer.Current().Epoch, save)
			if !errors.Is(err, authority.ErrFenced) || !checked.committed {
				t.Fatalf("fault did not occur at native/channel handoff: %v committed=%t", err, checked.committed)
			}
			persisted, revision, err := loadServiceRelease(t.Context(), kv, key)
			if err != nil || persisted.Preparation == nil || persisted.State != releasechannel.StateRolling {
				t.Fatalf("lost journal after crash: %+v %v", persisted, err)
			}
			selected, _, err := f.history.load(t.Context(), terrabase.Role)
			if err != nil {
				t.Fatal(err)
			}
			binding := selected.Pending
			if persisted.Preparation.RecoveryOf != "" {
				binding = selected.Recovery
			}
			fp, _ := persisted.Preparation.Intent.Fingerprint()
			if binding == nil || binding.Fingerprint != fp {
				t.Fatal("selected operation does not match durable handoff")
			}
			immutable := *binding
			f.history.kv = checked.KeyValue
			r.fencer = rolloutTestFence{epoch: r.fencer.Current().Epoch + 1}
			f.history.fencer = r.fencer
			save = func(next serviceReleaseState) error {
				var err error
				revision, err = r.save(t.Context(), kv, key, next, revision, r.fencer.Current().Epoch)
				return err
			}
			if err := r.finishPreparation(t.Context(), &persisted, r.fencer.Current().Epoch, save); err != nil {
				t.Fatal("new leader could not finish exact handoff:", err)
			}
			completed, _, err := loadServiceRelease(t.Context(), kv, key)
			if err != nil || completed.Preparation != nil {
				t.Fatalf("handoff not completed: %v", err)
			}
			intent := completed.Intent
			if selected.Recovery != nil && immutable.Fingerprint == selected.Recovery.Fingerprint {
				intent = completed.Rollback
			}
			if intent == nil || *intent != immutable.Intent {
				t.Fatal("new leader changed the selected operation")
			}
			after, _, err := f.history.load(t.Context(), terrabase.Role)
			active := after.Pending
			if after.Recovery != nil {
				active = after.Recovery
			}
			if err != nil || active.Fingerprint != immutable.Fingerprint || active.ProfileDigest != immutable.ProfileDigest || !active.Deadline.Equal(immutable.Deadline) {
				t.Fatalf("immutable selection changed: %v", err)
			}
		})
	}
}

func TestNativeFirstInstallExpiredSelectionSettlesWithoutPublishing(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	b := f.binding(t, terrabase.Role, profile, proof, 1)
	b.Intent.AuthorityEpoch--
	b.Fingerprint, _ = b.Intent.Fingerprint()
	b.Deadline = time.Now().Add(-time.Minute)
	f.save(t, terrabase.Role, nativeReleaseHistory{Schema: 1, Pending: &b})
	service := nativeRegressionDelivery(t, f, nativeRegressionPlanner{history: f.history, nodes: 1}, &nativeRegressionWriter{history: f.history})
	r := &serviceReleases{history: f.history, deliveries: service, fencer: f.history.fencer}
	state := serviceReleaseState{IssuedAt: b.Deadline.Add(-rollout.ObservationBudget), Digest: b.Artifact.Digest,
		Actor: servicePinsActor, State: releasechannel.StateRolling, Intent: &b.Intent,
		Preparation: &nativePrepareRequest{Intent: b.Intent, Deadline: b.Deadline}}
	finished, err := r.release(t.Context(), nil, terrabase.Role, state, 7, func(serviceReleaseState) error { return nil })
	if err != nil || finished.State != releasechannel.StateFailed {
		t.Fatalf("expired first install: %+v %v", finished, err)
	}
	nativeRegressionReceipt(t, service, b.Intent, "rejected")
	stream, err := f.history.js.Stream(t.Context(), delivery.IntentStream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("expired selection was published: %+v %v", info, err)
	}
	next := f.binding(t, terrabase.Role, profile, proof, 2)
	if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: next.Intent, Deadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("unsent expired selection blocked next release: %v", err)
	}
}

type nativeFenceMarkFailureKV struct{ jetstream.KeyValue }

func (k nativeFenceMarkFailureKV) Create(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
	return 0, errors.New("fence mark store unavailable")
}

func TestNativeChannelFenceMarkFailureAfterSelectionRemainsRecoverable(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	binding := f.binding(t, terrabase.Role, profile, proof, 1)
	kv, err := openChannelBucket(t.Context(), f.history.js, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.history.fences = &releaseFence{kv: nativeFenceMarkFailureKV{kv}, fencer: f.history.fencer,
		spec: func() (*cellspec.ReleaseFence, map[string]string) {
			return &cellspec.ReleaseFence{LoadBalancerID: "test-lb", BackendSets: []cellspec.FencedSet{{Name: terrabase.Role, Port: 9465, MinServing: 1}}}, nil
		}}
	state := serviceReleaseState{State: releasechannel.StateRolling, IssuedAt: time.Now().UTC(), Digest: binding.Artifact.Digest,
		Preparation: &nativePrepareRequest{Intent: binding.Intent, Deadline: binding.Deadline}}
	key := releasechannel.ServiceStatusKey("GRU", terrabase.Role)
	revision, err := saveServiceRelease(t.Context(), kv, key, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &serviceReleases{history: f.history, js: f.history.js, deliveries: f.history.deliveries, hosts: f.history.hosts, fencer: f.history.fencer}
	save := func(next serviceReleaseState) error {
		var err error
		revision, err = r.save(t.Context(), kv, key, next, revision, 7)
		return err
	}
	if err := r.finishPreparation(t.Context(), &state, 7, save); !errors.Is(err, errFencePrepare) {
		t.Fatalf("expected selection followed by failed fence mark: %v", err)
	}
	persisted, _, err := loadServiceRelease(t.Context(), kv, key)
	if err != nil || persisted.State != releasechannel.StateRolling || persisted.Preparation == nil {
		t.Fatalf("fence failure finalized claim: %+v %v", persisted, err)
	}
	selected, _, err := f.history.load(t.Context(), terrabase.Role)
	if err != nil || selected.Pending == nil || selected.Pending.Fingerprint != binding.Fingerprint {
		t.Fatalf("selection missing: %v", err)
	}
	f.history.fences.kv = kv
	if err := r.finishPreparation(t.Context(), &persisted, 7, save); err != nil {
		t.Fatal(err)
	}
	if err := f.history.prepareGate(t.Context(), *persisted.Intent, selected); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get(t.Context(), sequencedKey(terrabase.Role, binding.Intent.Generation)); err != nil {
		t.Fatal("fence mark not recovered:", err)
	}
	if _, err := f.history.deliveries.StatusFor(t.Context(), binding.Intent); !errors.Is(err, delivery.ErrPending) {
		t.Fatalf("preparation submitted host work: %v", err)
	}
}
