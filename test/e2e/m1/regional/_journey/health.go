package app

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func WorkerReleaseJourney(ctx context.Context, state string, node *mesh.Node) error {
	admission, stored, err := swarmruntime.StoredAdmission(state)
	if err != nil || !stored || admission.Role == "manager" {
		return fmt.Errorf("worker admission: %+v, stored %t, %v", admission, stored, err)
	}
	if err := node.ReleaseHealth(ctx); err != nil {
		return fmt.Errorf("joined worker release health: %w", err)
	}
	if result := releaseHealth(ctx, state, "ts-dashboard", node, nil); result.Err() != nil {
		return result.Err()
	}
	result := releaseHealth(ctx, state, "ts-dashboard", nil, nil)
	if result.Service != nil || result.Mesh == nil || result.Mesh.Error() != "mesh not started" {
		return fmt.Errorf("worker without a mesh node: %+v", result)
	}
	return nil
}

func PullRolloutJourney(ctx context.Context, fabric *nats.Conn, save bool) error {
	if save {
		store, err := pullrelease.Open(ctx, fabric, "gru", "gru")
		if err != nil {
			return err
		}
		if lead, err := store.Lead(ctx, "gru-founder"); err != nil || !lead {
			return fmt.Errorf("founder did not lead the gru rollout: %t, %v", lead, err)
		}
		if _, err := store.Save(ctx, pullrelease.Status{Region: "gru", Owner: "gru-founder", Phase: pullrelease.PhaseIdle}, 0); err != nil {
			return err
		}
	}
	status, err := pullrelease.Observe(ctx, fabric, "gru")
	if err != nil || status.Owner != "gru-founder" {
		return fmt.Errorf("gru release record: %+v, %v", status, err)
	}
	js, err := jetstream.New(fabric)
	if err != nil {
		return err
	}
	stream, err := js.Stream(ctx, "KV_"+pullrelease.Bucket)
	if err != nil {
		return err
	}
	info, err := stream.Info(ctx)
	if err != nil || info.Config.Replicas != mesh.StoreReplicas("gru") || info.Config.Replicas != 1 {
		return fmt.Errorf("gru pull rollout store replicas: %+v, %v", info, err)
	}
	return nil
}
