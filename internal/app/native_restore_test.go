package app

import (
	"errors"
	"maps"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func nativeRestoreFixture(t *testing.T) (*retainedConsumerFixture, nativeReleaseBinding, nativeReleaseBinding, *nativeRegressionWriter) {
	t.Helper()
	f := newRetainedConsumerFixture(t)
	p := nativeRegressionProfile()
	p.Env["REVISION"] = "A"
	a := f.binding(t, terrabase.Role, p, nativeRegressionAdopt(t, f, p, 1), 1)
	p = cloneNativeProfile(p)
	p.Env["REVISION"], p.Resources.CPU = "B", 2
	b := f.binding(t, terrabase.Role, p, nativeRegressionAdopt(t, f, p, 2), 2)
	p = cloneNativeProfile(p)
	p.Env["REVISION"], p.Resources.CPU = "C", 3
	nativeRegressionAdopt(t, f, p, 3)
	previous := nativeGoodRelease{Binding: a, Nodes: []string{"ctl-1"}, GoodAt: time.Now()}
	f.save(t, terrabase.Role, nativeReleaseHistory{Schema: 1, Pending: &b, Previous: &previous,
		Good: []nativeGoodRelease{{Binding: b, Nodes: []string{"ctl-1"}, GoodAt: time.Now()}, previous}})
	f.desired(t, b)
	writer := &nativeRegressionWriter{history: f.history, fixture: f}
	nativeRegressionDelivery(t, f, nativeRegressionPlanner{history: f.history, nodes: 1}, writer)
	return f, a, b, writer
}

func restoreIntent(binding nativeReleaseBinding) delivery.Intent {
	i := binding.Intent
	i.OperationID, i.Generation = entityid.New(), 3
	return i
}

func TestNativeManualRestoreUsesRetainedPairAfterNewSpec(t *testing.T) {
	f, a, b, _ := nativeRestoreFixture(t)
	i := restoreIntent(a)
	deadline := time.Now().Add(time.Minute)
	if reply, err := f.history.restore(t.Context(), nativePrepareRequest{Intent: i, Deadline: deadline}, servicePinsActor); err != nil || reply.Intent != i {
		t.Fatalf("restore prepare=%+v err=%v", reply, err)
	}
	if _, err := f.history.restore(t.Context(), nativePrepareRequest{Intent: i, Deadline: deadline.Add(time.Minute)}, servicePinsActor); err != nil {
		t.Fatalf("retry: %v", err)
	}
	selected, _, err := f.history.load(t.Context(), terrabase.Role)
	if err != nil || !selected.Recovery.Deadline.Equal(deadline) || selected.Recovery.ProfileDigest != a.ProfileDigest || selected.Rejected != "" || selected.Pending.Fingerprint != b.Fingerprint || len(selected.Good) != 2 {
		t.Fatalf("retained selection/retry: %+v err=%v", selected, err)
	}
	p, err := f.history.profile(t.Context(), i)
	if err != nil || !maps.Equal(p.Env, a.Profile.Env) || p.Resources != a.Profile.Resources {
		t.Fatalf("selected profile=%+v err=%v", p, err)
	}
	if err := f.history.deliveries.SubmitVerified(t.Context(), i, servicePinsActor); err != nil {
		t.Fatal(err)
	}
	nativeRegressionReceipt(t, f.history.deliveries, i, "accepted")
	desired, err := f.history.hosts.ListDesired(t.Context(), terrabase.Role)
	if err != nil || len(desired) != 1 || desired[0].Digest != a.Artifact.Digest || !maps.Equal(desired[0].Env, a.Profile.Env) {
		t.Fatalf("restored desired=%+v err=%v", desired, err)
	}
}

func TestNativeManualRestoreRefusesNonretainedTargetDurably(t *testing.T) {
	f, _, _, writer := nativeRestoreFixture(t)
	p := nativeRegressionProfile()
	unretained := f.binding(t, terrabase.Role, p, nativeRegressionAdopt(t, f, p, 4), 4)
	i := restoreIntent(unretained)
	_, revision, _ := f.history.load(t.Context(), terrabase.Role)
	for range 2 {
		if _, err := f.history.restore(t.Context(), nativePrepareRequest{Intent: i, Deadline: time.Now().Add(time.Minute)}, servicePinsActor); err == nil {
			t.Fatal("unretained target allowed")
		}
	}
	nativeRegressionReceipt(t, f.history.deliveries, i, "rejected")
	if _, got, err := f.history.load(t.Context(), terrabase.Role); err != nil || got != revision {
		t.Fatalf("refusal changed selection: revision=%d err=%v", got, err)
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.writes) != 0 {
		t.Fatal("refusal wrote desired state")
	}
}

func TestNativeRestoreTargetRefusesAmbiguousResources(t *testing.T) {
	f, a, _, _ := nativeRestoreFixture(t)
	p := cloneNativeProfile(a.Profile)
	p.Resources.CPU++
	proof := nativeRegressionAdopt(t, f, p, 4)
	other, err := nativeBinding(a.Intent, a.Artifact, p, proof)
	if err != nil {
		t.Fatal(err)
	}
	state := nativeReleaseHistory{Schema: 1, Good: []nativeGoodRelease{{Binding: a}, {Binding: other}}}
	i := restoreIntent(a)
	if _, err := nativeRestoreTarget(state, i); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("ambiguous public target: %v", err)
	}
	state.Previous = &state.Good[0]
	target, err := nativeRestoreTarget(state, i)
	if err != nil || target.Binding.ProfileDigest != a.ProfileDigest {
		t.Fatalf("exact recorded predecessor not selected: %+v %v", target, err)
	}
}

func TestNativeManualRestoreCannotReuseForwardOperationID(t *testing.T) {
	f, a, b, _ := nativeRestoreFixture(t)
	i := restoreIntent(a)
	i.OperationID = b.Intent.OperationID
	_, revision, _ := f.history.load(t.Context(), terrabase.Role)
	if _, err := f.history.restore(t.Context(), nativePrepareRequest{Intent: i, Deadline: time.Now().Add(time.Minute)}, servicePinsActor); !errors.Is(err, delivery.ErrConflict) {
		t.Fatalf("forward ID reused: %v", err)
	}
	if _, got, err := f.history.load(t.Context(), terrabase.Role); err != nil || got != revision {
		t.Fatalf("ID collision changed history: revision=%d err=%v", got, err)
	}
}
