package autoscaling

import (
	"context"
	"testing"
)

type escalatedTerminationSpawner struct {
	pid int
}

func (s *escalatedTerminationSpawner) Spawn(context.Context, NodeProcessSpec) (int, error) {
	return s.pid, nil
}

func (s *escalatedTerminationSpawner) Terminate(context.Context, int) error {
	return &processTerminationEscalatedError{InvalidOperationError: &InvalidOperationError{Message: "child was killed"}}
}

func TestLocalProvisionerDoesNotRetainReapedEscalatedChild(t *testing.T) {
	spawner := &escalatedTerminationSpawner{pid: 4242}
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err == nil {
		t.Fatal("the escalation diagnostic must be returned")
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); !isInvalidOperation(err) {
		t.Fatalf("a reaped child must not remain retryable: %v", err)
	}
}
