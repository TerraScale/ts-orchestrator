package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

type terminalProofProvider struct {
	*fakeProvider
	deletes int
}

func (provider *terminalProofProvider) DeleteVolume(_ context.Context, id, etag string) error {
	volume := provider.volumes[id]
	if volume.ETag != etag {
		return ErrStaleETag
	}
	provider.deletes++
	volume.LifecycleState = "TERMINATED"
	provider.volumes[id] = volume
	return nil
}

type failTerminalProofKV struct {
	jetstream.KeyValue
	failure error
	writes  int
}

func (kv *failTerminalProofKV) Create(ctx context.Context, key string, data []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	var entry journalEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return 0, err
	}
	if entry.Kind == "volume-termination" {
		kv.writes++
		if kv.failure != nil {
			return 0, kv.failure
		}
	}
	return kv.KeyValue.Create(ctx, key, data, opts...)
}

func TestTerminalVolumeTerminationProofRetriesBeforeCompletion(t *testing.T) {
	for _, initiallyTerminated := range []bool{false, true} {
		t.Run(map[bool]string{false: "mutation readback", true: "initial readback"}[initiallyTerminated], func(t *testing.T) {
			kv := &failTerminalProofKV{KeyValue: testJournalBucket(t)}
			journal, err := NewKVJournal(kv)
			if err != nil {
				t.Fatal(err)
			}
			fleet, base, fencer, intent := terminalFixtureWithJournal(t, journal)
			provider := &terminalProofProvider{fakeProvider: base}
			fleet.provider = provider
			acceptTerminalFixture(t, fencer, intent)
			target := intent.Targets[0]
			if initiallyTerminated {
				volume := provider.volumes[target.DataVolumeID]
				volume.LifecycleState = "TERMINATED"
				provider.volumes[target.DataVolumeID] = volume
			}
			kv.failure = errors.New("proof store unavailable")
			if settled, err := fleet.reconcileTerminalData(t.Context(), intent, 42, target); settled || !errors.Is(err, kv.failure) {
				t.Fatalf("failed proof write completed teardown: settled=%v err=%v", settled, err)
			}
			if gone, err := journal.volumeTerminated(t.Context(), fleet.config, target.DataVolumeID); err != nil || gone {
				t.Fatalf("failed proof write authorized cleanup: gone=%v err=%v", gone, err)
			}
			op, found, err := journal.GetOperation(t.Context(), OperationScope{Action: actionTerminalDataDelete,
				Key: digest(intent.OperationID, actionTerminalDataDelete, target.DataVolumeID), Region: fleet.config.Region,
				Generation: fleet.config.Generation, Owner: fleet.config.Owner})
			if err != nil {
				t.Fatal(err)
			}
			if found {
				if _, hasResult, err := journal.GetResult(t.Context(), op); err != nil || hasResult {
					t.Fatalf("failed proof write settled mutation result: found=%v err=%v", hasResult, err)
				}
			}
			deletes := provider.deletes
			kv.failure = nil
			if settled, err := fleet.reconcileTerminalData(t.Context(), intent, 42, target); !settled || err != nil {
				t.Fatalf("retry did not settle teardown: settled=%v err=%v", settled, err)
			}
			if provider.deletes != deletes || kv.writes != 2 {
				t.Fatalf("retry repeated delete or skipped proof: deletes=%d want=%d writes=%d", provider.deletes, deletes, kv.writes)
			}
			reopened, err := NewKVJournal(kv.KeyValue)
			if err != nil {
				t.Fatal(err)
			}
			if gone, err := reopened.volumeTerminated(t.Context(), fleet.config, target.DataVolumeID); err != nil || !gone {
				t.Fatalf("retry did not persist exact proof: gone=%v err=%v", gone, err)
			}
		})
	}
}

func TestTerminalVolumeTerminationProofPrecedesPendingInstance(t *testing.T) {
	kv := &failTerminalProofKV{KeyValue: testJournalBucket(t)}
	journal, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	fleet, provider, fencer, intent := terminalFixtureWithJournal(t, journal)
	acceptTerminalFixture(t, fencer, intent)
	id := intent.Targets[0].DataVolumeID
	volume := provider.volumes[id]
	volume.LifecycleState = "TERMINATED"
	provider.volumes[id] = volume
	kv.failure = errors.New("proof store unavailable")
	if status, err := fleet.ReconcileTerminal(t.Context(), intent, 42); !errors.Is(err, kv.failure) || status.Phase == TerminalPhaseComplete || provider.terminations != 0 {
		t.Fatalf("preflight proof failure advanced teardown: %+v terminations=%d err=%v", status, provider.terminations, err)
	}
	kv.failure = nil
	if status, err := fleet.ReconcileTerminal(t.Context(), intent, 42); err != nil || status.Phase != TerminalPhasePending {
		t.Fatalf("preflight retry: %+v err=%v", status, err)
	}
	if gone, err := journal.volumeTerminated(t.Context(), fleet.config, id); err != nil || !gone {
		t.Fatalf("pending instance skipped termination proof: gone=%v err=%v", gone, err)
	}
}

type terminalTransitionProvider struct {
	*terminalProofProvider
	reads int
}

func (provider *terminalTransitionProvider) GetVolume(ctx context.Context, id string) (CloudVolume, error) {
	provider.reads++
	if provider.reads == 2 {
		volume := provider.volumes[id]
		volume.LifecycleState = "TERMINATED"
		provider.volumes[id] = volume
	}
	return provider.fakeProvider.GetVolume(ctx, id)
}

func TestTerminalVolumeTerminationDuringOwnedReadSkipsDelete(t *testing.T) {
	fleet, base, journal, fencer, intent := terminalFixture(t)
	provider := &terminalTransitionProvider{terminalProofProvider: &terminalProofProvider{fakeProvider: base}}
	fleet.provider = provider
	acceptTerminalFixture(t, fencer, intent)
	target := intent.Targets[0]
	if settled, err := fleet.reconcileTerminalData(t.Context(), intent, 42, target); !settled || err != nil {
		t.Fatalf("late termination read: settled=%v err=%v", settled, err)
	}
	if _, proof := journal.terminations[target.DataVolumeID]; !proof || provider.deletes != 0 {
		t.Fatalf("late termination read: proof=%v deletes=%d", proof, provider.deletes)
	}
}

func TestTerminalVolumeTerminationProofRequiresExactReadback(t *testing.T) {
	for _, name := range []string{"404", "available", "terminating", "wrong ID", "wrong compartment", "wrong domain", "attachment failure"} {
		t.Run(name, func(t *testing.T) {
			fleet, provider, journal, _, intent := terminalFixture(t)
			id := intent.Targets[0].DataVolumeID
			volume := provider.volumes[id]
			volume.LifecycleState = "TERMINATED"
			wantError, wantProof := false, false
			switch name {
			case "404":
				delete(provider.volumes, id)
			case "available":
				volume.LifecycleState = "AVAILABLE"
			case "terminating":
				volume.LifecycleState = "TERMINATING"
			case "wrong ID":
				volume.ID, wantError = "other", true
			case "wrong compartment":
				volume.CompartmentID, wantError = "other", true
			case "wrong domain":
				volume.AvailabilityDomain, wantError = "other", true
			case "attachment failure":
				provider.attachmentListErr = errors.New("attachments unavailable")
				wantError, wantProof = true, true
			}
			if name != "404" {
				provider.volumes[id] = volume
			}
			settled, err := fleet.reconcileTerminalDataReadback(t.Context(), id)
			_, proof := journal.terminations[id]
			if (err != nil) != wantError || proof != wantProof || wantError && settled {
				t.Fatalf("readback: settled=%v proof=%v err=%v; want proof=%v error=%v", settled, proof, err, wantProof, wantError)
			}
		})
	}
}

func TestInspectTerminalStatusDoesNotWriteTerminationProof(t *testing.T) {
	fleet, provider, journal, _, intent := terminalFixture(t)
	readOnly := &observeReadOnlyJournal{fakeJournal: journal}
	fleet.journal = readOnly
	for _, target := range intent.Targets {
		delete(provider.instances, target.InstanceID)
		delete(provider.bootVolumes, target.BootVolumeID)
		volume := provider.volumes[target.DataVolumeID]
		volume.LifecycleState = "TERMINATED"
		provider.volumes[target.DataVolumeID] = volume
	}
	if status, err := fleet.InspectTerminalStatus(t.Context(), intent); err != nil || status.Phase != TerminalPhaseComplete {
		t.Fatalf("read-only terminal status: %+v err=%v", status, err)
	}
	if readOnly.writes != 0 || len(journal.terminations) != 0 {
		t.Fatalf("status wrote proof: writes=%d proofs=%d", readOnly.writes, len(journal.terminations))
	}
}

// TerminalVolumeProofForTest completes teardown before backup polling starts.
func TerminalVolumeProofForTest(t *testing.T) (RegionConfig, string, *KVJournal) {
	t.Helper()
	journal := VolumeBackupJournalForTest(t)
	fleet, base, fencer, intent := terminalFixtureWithJournal(t, journal)
	fleet.provider = &terminalProofProvider{fakeProvider: base}
	acceptTerminalFixture(t, fencer, intent)
	for _, target := range intent.Targets {
		instance := base.instances[target.InstanceID]
		instance.LifecycleState = "TERMINATED"
		base.instances[target.InstanceID] = instance
	}
	if status, err := fleet.ReconcileTerminal(t.Context(), intent, 42); err != nil || status.Phase != TerminalPhaseComplete {
		t.Fatalf("teardown did not finish: %+v err=%v", status, err)
	}
	return fleet.config, intent.Targets[0].DataVolumeID, journal
}
