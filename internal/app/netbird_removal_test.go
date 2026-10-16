package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	local "github.com/TerraScale/ts-orchestrator/internal/netbird/agent"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestNetBirdRemovalKeepsFailedRollbackExchangeUntilFenceReturns(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "current"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
			if err != nil {
				t.Fatal(err)
			}
			public, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			n := netbirdRollout{cell: "gru", key: key, fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}}, services: &specRegistry{}}
			target := network.Target{Pin: pin}
			record := network.Record{ID: "0EZB50X4TS1WNE5MVCZ3S99DW3", Node: "node-a", Previous: "0.79.0", Target: target,
				PinHash: network.Hash(target), Phase: "failed", RollbackRequired: new(true)}
			if legacy {
				record.RollbackRequired = nil
			}
			if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
				t.Fatal(err)
			}
			if err := n.fence.save(t.Context(), 3, record.Node, fenceRecord{Holders: []string{netbirdHold}}); err != nil {
				t.Fatal(err)
			}
			command := network.Command{ID: network.CommandID(record.ID, "rollback"), Transaction: record.ID, Action: "rollback", Generation: 1, Target: target}
			if err := saveNetBirdTestCommand(t.Context(), &n, 3, record.Node, command); err != nil {
				t.Fatal(err)
			}
			status := network.Status{Version: record.Previous, Connected: true, IP: "10.200.1.2", DNS: "node-a.nb.ts.internal", ObservedAt: time.Now().UTC()}
			step, err := n.Exchange(t.Context(), host.Registration{Node: record.Node}, status)
			if err != nil {
				t.Fatal(err)
			}
			var envelope protocol.Envelope
			if err := json.Unmarshal(step, &envelope); err != nil {
				t.Fatal(err)
			}
			if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: n.cell, Kind: "netbird.step", Actor: record.Node,
				OperationID: command.ID, Epoch: 3, Generation: command.Generation}, public, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: local.StepLifetime}); err != nil {
				t.Fatalf("removed pin stopped delivery of its signed recovery command: %v", err)
			}
			returnErr := errors.New("LB return incomplete")
			returns := 0
			r := network.Reconciler{
				Load: func(ctx context.Context) (network.Record, error) {
					var record network.Record
					err := n.load(ctx, netbirdRecordKey, &record)
					return record, err
				},
				Save: func(ctx context.Context, record network.Record) error {
					return saveNetBirdTestRecord(ctx, &n, 3, record)
				},
				Status: n.status, Healthy: func(context.Context, string, network.Status, time.Time) error { return nil },
				Drain: func(ctx context.Context, node string) error {
					return n.fence.save(ctx, 3, node, fenceRecord{Holders: []string{netbirdHold}})
				},
				Return: func(ctx context.Context, node string) error {
					returns++
					if returnErr != nil {
						return returnErr
					}
					_, err := n.fence.restore(ctx, nil, 3, node, netbirdHold, true)
					return err
				},
			}
			if err := r.Tick(t.Context(), target, nil); err == nil || returns != 0 {
				t.Fatalf("fresh old status bypassed rollback acknowledgment: returns=%d error=%v", returns, err)
			}
			status.ActionID = command.ID
			if _, err := n.Exchange(t.Context(), host.Registration{Node: record.Node}, status); err != nil {
				t.Fatal(err)
			}
			if err := r.Tick(t.Context(), target, nil); err == nil || returns != 1 {
				t.Fatalf("failed return was not retained: returns=%d error=%v", returns, err)
			}
			if pin, err := n.target(t.Context()); err != nil || pin == nil {
				t.Fatalf("removal abandoned the unreleased failed fence: %+v %v", pin, err)
			}
			if _, found, err := n.fence.record(t.Context(), record.Node); err != nil || !found {
				t.Fatalf("failed return released its NetBird fence: found=%t error=%v", found, err)
			}
			returnErr = nil
			if err := r.Tick(t.Context(), target, nil); err == nil || returns != 2 {
				t.Fatalf("repaired worker did not return while preserving the failed-pin hold: returns=%d error=%v", returns, err)
			}
			if _, found, err := n.fence.record(t.Context(), record.Node); err != nil || found {
				t.Fatalf("successful recovery did not release its NetBird fence: found=%t error=%v", found, err)
			}
			if pin, err := n.target(t.Context()); err != nil || pin != nil {
				t.Fatalf("successful recovery did not honor pin removal: %+v %v", pin, err)
			}
			if step, err := n.Exchange(t.Context(), host.Registration{Node: record.Node}, status); err != nil || len(step) != 0 {
				t.Fatalf("removed pin continued commands after recovery: %s %v", step, err)
			}
		})
	}
}

func TestNetBirdRemovalWithoutAnOutstandingRecordStaysDisabled(t *testing.T) {
	n := netbirdRollout{fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}}, services: &specRegistry{}}
	if pin, err := n.target(t.Context()); err != nil || pin != nil {
		t.Fatalf("empty journal enabled management: %+v %v", pin, err)
	}
	for _, phase := range []string{"", "done", "failed"} {
		record := network.Record{Phase: phase, RecoveryComplete: true}
		if phase != "" {
			record.ID = "7XXDG352V7P4SAYRZ21NWHEXTJ"
		}
		if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
			t.Fatal(err)
		}
		if pin, err := n.target(t.Context()); err != nil || pin != nil {
			t.Fatalf("finished %q journal enabled management: %+v %v", phase, pin, err)
		}
	}
}
