package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
)

type channelFleet struct {
	now   time.Time
	units map[string]rolloutexec.HealthProof
	steps []string
}

func (f *channelFleet) Latest(unit string) (rolloutexec.HealthProof, bool) {
	proof, ok := f.units[unit]
	proof.ObservedAt, proof.ReceivedAt = f.now, f.now
	return proof, ok
}

func (f *channelFleet) Step(_ context.Context, step rolloutexec.Step) (rolloutexec.StepReply, error) {
	f.steps = append(f.steps, step.Unit)
	proof := f.units[step.Unit]
	proof.BinarySHA256, proof.ProcessID = step.Digest, proof.ProcessID+1
	proof.StartNonce = fmt.Sprintf("%032x", proof.ProcessID)
	f.units[step.Unit] = proof
	return rolloutexec.StepReply{OperationID: step.OperationID, Unit: step.Unit, Outcome: rolloutexec.OutcomeActivated}, nil
}

func TestReleaseChannelPromotesFreshSignedRunAfterAbandonedReservation(t *testing.T) {
	for _, marked := range []bool{false, true} {
		for _, hostOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("hostOnly=%t/marked=%t", hostOnly, marked), func(t *testing.T) {
				f := newChannelFixture(t)
				ctx := t.Context()
				binary := []byte("same signed binary after reservation crash")
				old := f.signer.channel(t, "GRU", 630, binary)
				first, err := f.control.admitChannel(old, f.signer.now)
				if err != nil {
					t.Fatal(err)
				}
				first.Actor = channelActor
				first, err = f.store.PublishRelease(ctx, 7, first)
				if err != nil {
					t.Fatal(err)
				}
				fleet := &channelFleet{now: first.CreatedAt, units: map[string]rolloutexec.HealthProof{}}
				for _, unit := range []string{"ctl-a", "ctl-b", "ctl-c", "h1"} {
					digest := strings.Repeat("a", 64)
					if hostOnly && unit != "h1" {
						digest = first.Digest
					}
					fleet.units[unit] = rolloutexec.HealthProof{Schema: rolloutexec.HealthSchema, Cell: "gru", Unit: unit,
						BinarySHA256: digest, ProcessID: 1, StartNonce: fmt.Sprintf("%032x", 1)}
				}
				controllers, err := rolloutexec.ControllerUnits([]string{"ctl-a", "ctl-b", "ctl-c"}, "ctl-a")
				if err != nil {
					t.Fatal(err)
				}
				f.control.program = rolloutexec.ReleaseProgram{Store: f.store, Proofs: fleet, Controllers: controllers,
					Hosts: func(context.Context) ([]rollout.Unit, error) {
						return rolloutexec.HostUnits(map[string][]string{"h1": {}}), nil
					},
					Policy: rollout.DefaultPolicy(), Now: func() time.Time { return fleet.now }}
				domain := rollout.ControllerReleaseDomain
				if hostOnly {
					domain = rollout.HostReleaseDomain
				}
				oldID := entityid.Derive(domain, rollout.ReleaseRolloutID(first.Generation))
				// Persist the crash boundary: a charged cell reservation and permanent marker, before its refund CAS.
				cell := rollout.CellState{SchemaVersion: rollout.SchemaVersion, Cell: "gru", ActiveRolloutID: oldID,
					Attempts: map[string]int{first.Digest: 1}}
				wire, err := json.Marshal(cell)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.rolloutKV.Create(ctx, "cell", wire); err != nil {
					t.Fatal(err)
				}
				if marked {
					if _, err := f.rolloutKV.Create(ctx, oldID, []byte(`{"abandoned_rollout":"`+oldID+`"}`)); err != nil {
						t.Fatal(err)
					}
				}
				executor := &rolloutexec.Executor{Cell: "gru", Store: f.store, Fencer: rolloutTestFence{epoch: 7},
					Driver: fleet, Proofs: fleet, Program: f.control.program.Program, Now: func() time.Time { return fleet.now }}
				if err := executor.Tick(ctx); !errors.Is(err, rollout.ErrAbandonedRollout) {
					t.Fatalf("production crash recovery = %v", err)
				}
				if cell, _, err := f.store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || cell.Attempts[first.Digest] != 0 {
					t.Fatalf("production recovery did not refund the matching reservation: %+v, %v", cell, err)
				}
				consume := func(channel releasechannel.Channel) releasechannel.Status {
					t.Helper()
					wire, err := json.Marshal(channel)
					if err != nil {
						t.Fatal(err)
					}
					if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, wire, fleet.now); err != nil {
						t.Fatal(err)
					}
					status, _ := f.report(t)
					return status
				}
				if status := consume(old); status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "abandoned") {
					t.Fatalf("old marker did not report a clear failure: %+v", status)
				}
				newSigner := f.signer
				fleet.now = fleet.now.Add(time.Minute)
				newSigner.now = fleet.now
				for _, replay := range []releasechannel.Channel{old, f.signer.channel(t, "GRU", 631, binary), newSigner.channel(t, "GRU", 630, binary)} {
					consume(replay)
					if desired, _, err := f.store.Desired(ctx); err != nil || desired.Generation() != first.Generation {
						t.Fatalf("partial signed renewal created a generation: %+v, %v", desired, err)
					}
				}
				fresh := newSigner.channel(t, "GRU", 631, binary)
				if status := consume(fresh); status.State != releasechannel.StateRolling {
					t.Fatalf("fresh signed run was refused: %+v", status)
				}
				if len(fleet.steps) != 0 {
					t.Fatalf("publication moved units: %v", fleet.steps)
				}
				desired, _, err := f.store.Desired(ctx)
				if err != nil || desired.Generation() != first.Generation+1 || !desired.Release.CreatedAt.Equal(newSigner.now) {
					t.Fatalf("fresh signed generation = %+v, %v", desired, err)
				}
				freshID := entityid.Derive(domain, rollout.ReleaseRolloutID(desired.Generation()))
				if err := executor.Tick(ctx); err != nil {
					t.Fatal(err)
				}
				if cell, _, err := f.store.Cell(ctx); err != nil || cell.ActiveRolloutID != freshID || cell.Attempts[first.Digest] != 1 {
					t.Fatalf("fresh issuance failed one-attempt recovery: %+v, %v", cell, err)
				}
				for i := 0; i < 240 && consume(fresh).State != releasechannel.StateComplete; i++ {
					fleet.now = fleet.now.Add(5 * time.Second)
					if err := executor.Tick(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if status := consume(fresh); status.State != releasechannel.StateComplete || fleet.now.Sub(newSigner.now) > rollout.ObservationBudget {
					t.Fatalf("signed retry did not fully promote within policy: %+v, elapsed %s", status, fleet.now.Sub(newSigner.now))
				}
				want := []string{"ctl-b", "ctl-c", "ctl-a", "h1"}
				if hostOnly {
					want = []string{"h1"}
				}
				if !slices.Equal(fleet.steps, want) {
					t.Fatalf("promotion order = %v, want %v", fleet.steps, want)
				}
				for unit, proof := range fleet.units {
					if proof.BinarySHA256 != first.Digest {
						t.Fatalf("%s did not promote", unit)
					}
				}
				consume(old)
				if err := executor.Tick(ctx); err != nil || !slices.Equal(fleet.steps, want) {
					t.Fatalf("old replay/completed tick moved the fleet: %v, %v", fleet.steps, err)
				}
				if bad, err := f.store.IsKnownBad(ctx, first.Digest); err != nil || bad {
					t.Fatalf("untested digest was blacklisted: %v, %v", bad, err)
				}
				if kept, err := f.store.ReleaseGeneration(ctx, first.Generation); err != nil || !kept.CreatedAt.Equal(first.CreatedAt) {
					t.Fatalf("original issuance was rewritten: %+v, %v", kept, err)
				}
				if _, _, err := f.store.Begin(ctx, rollout.Spec{Cell: "gru", RolloutID: oldID, AuthorityEpoch: 7}, fleet.now); !errors.Is(err, rollout.ErrAbandonedRollout) {
					t.Fatalf("old marked ID revived: %v", err)
				}
			})
		}
	}

}
