package delivery

import (
	"context"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
)

type shapedPlanner struct{ shape PlanShape }

func (shapedPlanner) Plan(context.Context, Intent) ([]host.Desired, error) {
	panic("a shaped planner must be asked for its shape")
}

func (p shapedPlanner) PlanShaped(_ context.Context, i Intent) (PlanShape, []host.Desired, error) {
	var plan []host.Desired
	for _, node := range []string{"node-a", "node-b", "node-c"}[:p.shape.Replicas] {
		plan = append(plan, host.Desired{Cell: i.Cell, Node: node, Environment: i.Environment, Role: i.Role,
			Digest: i.ArtifactDigest, Generation: p.shape.Generation, AuthorityEpoch: i.AuthorityEpoch})
	}
	return p.shape, plan, nil
}

func TestValidatePlanHonoursRecordedShape(t *testing.T) {
	digest := strings.Repeat("a", 64)
	intent := Intent{SchemaVersion: SchemaVersion, OperationID: "deploy-shaped", ArtifactDigest: digest,
		ManifestDigest: digest, Cell: "lab", Role: "worker", Environment: "production", Generation: 3,
		DesiredReplicas: 1, ConfigDigest: ConfigDigestOf(nil, nil), AuthorityEpoch: 1}
	shape := PlanShape{Generation: intent.Generation << 24, Replicas: 3}
	service := &Service{config: Config{Planner: shapedPlanner{shape: shape}}}
	gotShape, plan, err := service.plan(context.Background(), intent)
	if err != nil || gotShape != shape {
		t.Fatalf("plan shape = %#v (%v)", gotShape, err)
	}
	if err := validatePlan(intent, gotShape, plan); err != nil {
		t.Fatalf("shaped plan rejected: %v", err)
	}
	if err := validatePlan(intent, defaultPlanShape(intent), plan); err == nil {
		t.Fatal("shaped plan accepted against the intent's own shape")
	}
	op := operation{Intent: intent, Plan: plan, Shape: &gotShape}
	if op.planShape() != shape || (operation{Intent: intent}).planShape() != defaultPlanShape(intent) {
		t.Fatal("recorded operation shape was not used on resume")
	}
	for _, bad := range []PlanShape{
		{Generation: intent.Generation - 1, Replicas: 0},
		{Generation: intent.Generation, Replicas: 1025},
		{Generation: intent.Generation, Replicas: -1},
	} {
		if err := validatePlan(intent, bad, nil); err == nil {
			t.Errorf("shape %#v accepted", bad)
		}
	}
}
