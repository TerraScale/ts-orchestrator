package failover

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

var request = Request{DatabaseID: "db", PartitionID: "p", VolumeID: "vol", OldInstanceID: "old",
	ReplacementInstanceID: "new", AttachKey: "reattach-1"}

func attachment(id, instance, state string) Attachment {
	return Attachment{ID: id, VolumeID: "vol", InstanceID: instance, State: state, ETag: "e-" + id}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		fenced      bool
		attachments []Attachment
		mounted     bool
		want        StepKind
	}{
		{"unfenced never detaches", false, []Attachment{attachment("a", "old", "ATTACHED")}, false, StepProveFence},
		{"detach old attached", true, []Attachment{attachment("a", "old", "ATTACHED")}, false, StepDetach},
		{"detach old attaching", true, []Attachment{attachment("a", "old", "ATTACHING")}, false, StepDetach},
		{"wait detaching", true, []Attachment{attachment("a", "old", "DETACHING")}, false, StepWaitDetached},
		{"attach after detached history", true, []Attachment{attachment("a", "old", "DETACHED")}, false, StepAttach},
		{"attach with no history", true, nil, false, StepAttach},
		{"wait replacement", true, []Attachment{attachment("a", "old", "DETACHED"), attachment("b", "new", "ATTACHING")}, false, StepWaitAttached},
		{"grant mount", true, []Attachment{attachment("a", "old", "DETACHED"), attachment("b", "new", "ATTACHED")}, false, StepGrantMount},
		{"done", true, []Attachment{attachment("b", "new", "ATTACHED")}, true, StepDone},
		{"third instance holds", true, []Attachment{attachment("c", "other", "ATTACHED")}, false, StepHold},
		{"third instance detached is history", true, []Attachment{attachment("c", "other", "DETACHED")}, false, StepAttach},
		{"two replacement attachments hold", true, []Attachment{attachment("b", "new", "ATTACHED"), attachment("d", "new", "ATTACHING")}, false, StepHold},
		{"unknown old state holds", true, []Attachment{attachment("a", "old", "FAULTY")}, false, StepHold},
		{"other volume holds", true, []Attachment{{ID: "x", VolumeID: "vol-2", InstanceID: "new", State: "ATTACHED"}}, false, StepHold},
		{"old detach precedes replacement", true, []Attachment{attachment("b", "new", "ATTACHED"), attachment("a", "old", "ATTACHED")}, false, StepDetach},
	}
	for _, test := range cases {
		if got := Decide(request, test.fenced, test.attachments, test.mounted); got.Kind != test.want {
			t.Fatalf("%s: step %s (%s), want %s", test.name, got.Kind, got.Reason, test.want)
		}
	}
}

type fakeInstances map[string]string

func (instances fakeInstances) InstanceLifecycleState(_ context.Context, id string) (string, error) {
	state, ok := instances[id]
	if !ok {
		return "", errors.New("not found")
	}
	return state, nil
}

func TestProveFencedRequiresTerminated(t *testing.T) {
	now := time.Now()
	for state, ok := range map[string]bool{"TERMINATED": true, "TERMINATING": false, "STOPPED": false, "RUNNING": false} {
		proof, err := ProveFenced(t.Context(), fakeInstances{"old": state}, "old", now)
		if ok != (err == nil) || ok && proof.State != "TERMINATED" {
			t.Fatalf("%s: proof=%+v err=%v", state, proof, err)
		}
		if !ok && !errors.Is(err, storage.ErrWriterNotFenced) {
			t.Fatalf("%s: wrong error %v", state, err)
		}
	}
	if _, err := ProveFenced(t.Context(), fakeInstances{}, "old", now); !errors.Is(err, storage.ErrWriterNotFenced) {
		t.Fatalf("unobservable instance was fenced: %v", err)
	}
}

type fakeVolumes struct {
	attachments []Attachment
	detaches    int
	attaches    int
	proofs      []FenceProof
	listings    int
}

func (volumes *fakeVolumes) VolumeAttachments(context.Context, string) ([]Attachment, error) {
	volumes.listings++
	return append([]Attachment(nil), volumes.attachments...), nil
}

func (volumes *fakeVolumes) DetachFenced(_ context.Context, _ Request, target Attachment, proof FenceProof) error {
	volumes.detaches++
	volumes.proofs = append(volumes.proofs, proof)
	for index := range volumes.attachments {
		if volumes.attachments[index].ID == target.ID {
			volumes.attachments[index].State = "DETACHING"
		}
	}
	return nil
}

func (volumes *fakeVolumes) AttachReplacement(_ context.Context, request Request, proof FenceProof) (Attachment, error) {
	volumes.attaches++
	volumes.proofs = append(volumes.proofs, proof)
	created := attachment(fmt.Sprintf("new-%d", volumes.attaches), request.ReplacementInstanceID, "ATTACHING")
	volumes.attachments = append(volumes.attachments, created)
	return created, nil
}

type fakePermits struct{ granted map[string]bool }

func (permits *fakePermits) GrantMountExisting(_ context.Context, _ Request, target Attachment) error {
	permits.granted[target.ID] = true
	return nil
}

func (permits *fakePermits) HasMountExisting(_ context.Context, _ Request, target Attachment) (bool, error) {
	return permits.granted[target.ID], nil
}

type fakeFencer struct {
	snapshot authority.Snapshot
	guardErr error
}

func (fencer *fakeFencer) Current() authority.Snapshot         { return fencer.snapshot }
func (fencer *fakeFencer) Guard(context.Context, uint64) error { return fencer.guardErr }

func leader() authority.Snapshot {
	return authority.Snapshot{Leader: true, Ready: true, Epoch: 2, Revision: 3, ExpiresAt: time.Now().Add(time.Minute)}
}

func TestReattacherDrivesTerminatedHostToMountedReplacement(t *testing.T) {
	instances := fakeInstances{"old": "RUNNING"}
	volumes := &fakeVolumes{attachments: []Attachment{attachment("a", "old", "ATTACHED")}}
	permits := &fakePermits{granted: map[string]bool{}}
	reattacher := Reattacher{Config: Config{Enabled: true}, Fencer: &fakeFencer{snapshot: leader()},
		Instances: instances, Volumes: volumes, Permits: permits}

	// A host that only stopped answering is never detached.
	if step, err := reattacher.Step(t.Context(), request); step.Kind != StepProveFence || !errors.Is(err, storage.ErrWriterNotFenced) || volumes.detaches != 0 {
		t.Fatalf("unfenced host was detached: %+v %v", step, err)
	}
	if volumes.listings != 0 {
		t.Fatalf("an unproven fence still listed attachments %d times", volumes.listings)
	}
	instances["old"] = "TERMINATED"
	want := []StepKind{StepDetach, StepWaitDetached}
	for _, kind := range want {
		step, err := reattacher.Step(t.Context(), request)
		if err != nil || step.Kind != kind {
			t.Fatalf("step = %+v, %v; want %s", step, err, kind)
		}
	}
	volumes.attachments[0].State = "DETACHED"
	for _, kind := range []StepKind{StepAttach, StepWaitAttached} {
		step, err := reattacher.Step(t.Context(), request)
		if err != nil || step.Kind != kind {
			t.Fatalf("step = %+v, %v; want %s", step, err, kind)
		}
	}
	volumes.attachments[1].State = "ATTACHED"
	for _, kind := range []StepKind{StepGrantMount, StepDone} {
		step, err := reattacher.Step(t.Context(), request)
		if err != nil || step.Kind != kind {
			t.Fatalf("step = %+v, %v; want %s", step, err, kind)
		}
	}
	if volumes.detaches != 1 || volumes.attaches != 1 || len(permits.granted) != 1 {
		t.Fatalf("effects detach=%d attach=%d permits=%v", volumes.detaches, volumes.attaches, permits.granted)
	}
	for _, proof := range volumes.proofs {
		if proof.InstanceID != "old" || proof.State != "TERMINATED" {
			t.Fatalf("effect ran without terminated proof: %+v", proof)
		}
	}
}

func TestReattacherRefusesDisabledFollowerFencedAndForeignAttachments(t *testing.T) {
	volumes := &fakeVolumes{attachments: []Attachment{attachment("a", "old", "ATTACHED")}}
	base := Reattacher{Config: Config{Enabled: true}, Fencer: &fakeFencer{snapshot: leader()},
		Instances: fakeInstances{"old": "TERMINATED"}, Volumes: volumes, Permits: &fakePermits{granted: map[string]bool{}}}

	disabled := base
	disabled.Config.Enabled = false
	if _, err := disabled.Step(t.Context(), request); !errors.Is(err, storage.ErrDisabled) {
		t.Fatalf("disabled reattach ran: %v", err)
	}
	follower := base
	follower.Fencer = &fakeFencer{snapshot: authority.Snapshot{Ready: true}}
	if _, err := follower.Step(t.Context(), request); !errors.Is(err, authority.ErrNotLeader) {
		t.Fatalf("follower reattached: %v", err)
	}
	fenced := base
	fenced.Fencer = &fakeFencer{snapshot: leader(), guardErr: authority.ErrFenced}
	if _, err := fenced.Step(t.Context(), request); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced leader reattached: %v", err)
	}
	same := request
	same.ReplacementInstanceID = same.OldInstanceID
	if _, err := base.Step(t.Context(), same); err == nil {
		t.Fatal("reattach to the lost instance itself was accepted")
	}
	volumes.attachments = []Attachment{attachment("c", "third", "ATTACHED")}
	if step, err := base.Step(t.Context(), request); step.Kind != StepHold || !errors.Is(err, storage.ErrVolumeHeld) || errors.Is(err, storage.ErrVolumeStuck) {
		t.Fatalf("foreign attachment did not hold: %+v %v", step, err)
	}
	if volumes.detaches != 0 || volumes.attaches != 0 {
		t.Fatalf("refused reattach performed effects: detach=%d attach=%d", volumes.detaches, volumes.attaches)
	}
}
