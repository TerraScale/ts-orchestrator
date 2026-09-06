package control

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func masterIsEdge(request *delivery.Request) bool {
	return request != nil && request.Artifact != nil && (request.Artifact.Kind == "site" || request.Artifact.Kind == "package")
}

func (m *MasterDelivery) submitGlobalEdge(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, record *masterDeliveryRecord, revision uint64, epoch int64, fence delivery.OperationFence, check func(delivery.OperationFence) error) error {
	edge := record.GlobalEdge
	if err := check(fence); err != nil {
		return err
	}
	observed, err := m.config.GlobalEdge.Observe(ctx, request, artifact, fence, check)
	if err != nil {
		return err
	}
	if !observed {
		if edge.Attempt >= 1000 {
			return errors.New("master delivery: global edge retry bound exhausted")
		}
		edge.Attempt++
		revision, err = m.saveMaster(ctx, record, revision, epoch)
		if err != nil {
			return err
		}
		if err := check(fence); err != nil {
			return err
		}
		if err := m.config.GlobalEdge.Apply(ctx, request, artifact, fence, check); err != nil {
			return err // Keep the attempt durable; recovery observes before retrying.
		}
		if err := check(fence); err != nil {
			return err
		}
		observed, err = m.config.GlobalEdge.Observe(ctx, request, artifact, fence, check)
		if err != nil {
			return err
		}
	}
	if !observed {
		return errors.New("master delivery: global edge serving identity is unconfirmed")
	}
	edge.Accepted = true
	if _, err := m.saveMaster(ctx, record, revision, epoch); err != nil {
		edge.Accepted = false
		return err
	}
	return nil
}
