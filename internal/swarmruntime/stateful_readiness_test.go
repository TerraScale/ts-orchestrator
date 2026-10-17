package swarmruntime

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

func TestReadinessRetainsOriginalEffectAcrossRenewal(t *testing.T) {
	now := time.Now().UTC()
	original := authority.RuntimeEffect{EffectID: "original", Phase: authority.RuntimeEffectHeld, Epoch: 3,
		Scope: authority.WorkloadScope{DatabaseID: "database", PartitionID: "partition"}, RegistrationID: "registration", HostSessionID: "session",
		WorkerPublicKey: "worker", NATSUserPublicKey: "recipient", RegistrationGeneration: 7, InstanceID: "instance", NodeID: "node",
		TaskID: "task", ServiceID: "service", TaskSHA256: "task-hash", AdmissionSHA256: "admission", MaterialSHA256: "material-hash",
		Material: []byte("material"), IssuedAt: now, ExpiresAt: now.Add(time.Second), Sequence: 2}
	renewed := original
	renewed.ExpiresAt = now.Add(2 * time.Second)
	renewed.Sequence++
	if !sameReadinessEffect(original, renewed) || original.ExpiresAt != now.Add(time.Second) {
		t.Fatal("ordinary renewal changed the original readiness deadline or identity")
	}
	for _, test := range []struct {
		name   string
		change func(*authority.RuntimeEffect)
	}{
		{"closing", func(e *authority.RuntimeEffect) { e.Phase = authority.RuntimeEffectClosing }},
		{"effect", func(e *authority.RuntimeEffect) { e.EffectID = "other" }},
		{"epoch", func(e *authority.RuntimeEffect) { e.Epoch++ }},
		{"scope", func(e *authority.RuntimeEffect) { e.Scope.PartitionID = "other" }},
		{"registration", func(e *authority.RuntimeEffect) { e.RegistrationID = "other" }},
		{"session", func(e *authority.RuntimeEffect) { e.HostSessionID = "other" }},
		{"worker key", func(e *authority.RuntimeEffect) { e.WorkerPublicKey = "other" }},
		{"recipient", func(e *authority.RuntimeEffect) { e.NATSUserPublicKey = "other" }},
		{"registration generation", func(e *authority.RuntimeEffect) { e.RegistrationGeneration++ }},
		{"instance", func(e *authority.RuntimeEffect) { e.InstanceID = "other" }},
		{"node", func(e *authority.RuntimeEffect) { e.NodeID = "other" }},
		{"task", func(e *authority.RuntimeEffect) { e.TaskID = "other" }},
		{"service", func(e *authority.RuntimeEffect) { e.ServiceID = "other" }},
		{"task hash", func(e *authority.RuntimeEffect) { e.TaskSHA256 = "other" }},
		{"admission", func(e *authority.RuntimeEffect) { e.AdmissionSHA256 = "other" }},
		{"material hash", func(e *authority.RuntimeEffect) { e.MaterialSHA256 = "other" }},
		{"material bytes", func(e *authority.RuntimeEffect) { e.Material = []byte("other") }},
		{"issued time", func(e *authority.RuntimeEffect) { e.IssuedAt = now.Add(time.Nanosecond) }},
		{"shortened expiry", func(e *authority.RuntimeEffect) { e.ExpiresAt = now }},
		{"older revision", func(e *authority.RuntimeEffect) { e.Sequence = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := renewed
			changed.Material = bytes.Clone(renewed.Material)
			test.change(&changed)
			if sameReadinessEffect(original, changed) {
				t.Fatal("changed effect admitted as the original readiness session")
			}
		})
	}
}

func TestTaskReadinessWitnessKeepsFirstDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	var calls int
	witness := &TaskReadinessWitness{deadline: deadline, recheck: func(ctx context.Context) error {
		calls++
		actual, ok := ctx.Deadline()
		if !ok || !actual.Equal(deadline) {
			t.Fatal("recheck did not retain the original deadline")
		}
		return nil
	}}
	if err := witness.Recheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || witness.Deadline() != deadline {
		t.Fatal("recheck replaced the first admission lifetime")
	}
	expired := &TaskReadinessWitness{deadline: time.Now().Add(-time.Second), recheck: witness.recheck}
	if err := expired.Recheck(t.Context()); err == nil || calls != 1 {
		t.Fatal("expired witness ran a new readiness observation")
	}
	if err := new(TaskReadinessWitness).Recheck(t.Context()); err == nil {
		t.Fatal("unsealed witness granted readiness")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := witness.Recheck(ctx); err == nil || calls != 1 {
		t.Fatal("canceled caller obtained a fresh observation")
	}
}
