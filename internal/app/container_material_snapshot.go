package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
)

type containerSecretVersion struct {
	ID        string    `json:"id"`
	Version   int64     `json:"version"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// This service-owned Raft config records only credential versions and the
// upstream ForceUpdate generation; secret values never enter manager state.
const containerSecretSnapshotLabel = "terrascale.container-secret-snapshot"
const containerSecretSnapshotSchema = "terrascale.container-secret-versions.v1"

type containerSecretSnapshot struct {
	OperationID  string                            `json:"operation_id"`
	ServiceID    string                            `json:"service_id"`
	ConfigDigest string                            `json:"config_digest"`
	Generation   uint64                            `json:"generation"`
	Versions     map[string]containerSecretVersion `json:"versions"`
}

func encodeContainerSnapshot(snapshot containerSecretSnapshot) ([]byte, error) {
	wire, err := protocol.EncodeJSON(snapshot)
	if err != nil {
		return nil, err
	}
	if len(wire) > 32<<10 {
		return nil, containermaterial.ErrPending
	}
	return wire, nil
}

func containerSnapshotName(serviceID string) string {
	digest := sha256.Sum256([]byte(serviceID))
	return "ts-container-material-" + hex.EncodeToString(digest[:16])
}

func lookupContainerSnapshot(ctx context.Context, client api.ControlClient, serviceID string) (*api.Config, error) {
	name := containerSnapshotName(serviceID)
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	if len(listed.Configs) == 0 {
		return nil, nil
	}
	if len(listed.Configs) != 1 || listed.Configs[0] == nil || listed.Configs[0].Spec.Annotations.Name != name {
		return nil, containermaterial.ErrPending
	}
	return listed.Configs[0], nil
}

func checkContainerSnapshot(ctx context.Context, client api.ControlClient, wanted containerSecretSnapshot) error {
	config, err := lookupContainerSnapshot(ctx, client, wanted.ServiceID)
	if err != nil {
		return err
	}
	if config == nil {
		return containermaterial.ErrPending
	}
	wire, err := encodeContainerSnapshot(wanted)
	if err != nil {
		return err
	}
	if string(config.Spec.Data) != containerSecretSnapshotSchema || config.Spec.Annotations.Labels[containerSecretSnapshotLabel] != string(wire) {
		return containermaterial.ErrPending
	}
	return nil
}

// syncContainerSnapshot writes version metadata before advancing the upstream counter.
// A lost response resumes from that config; there is no parallel task lifecycle.
func syncContainerSnapshot(ctx context.Context, client api.ControlClient, fence authority.Fencer, service *api.Service, next containerSecretSnapshot) error {
	config, err := lookupContainerSnapshot(ctx, client, next.ServiceID)
	if err != nil {
		return err
	}
	epoch := fence.Current().Epoch
	if config == nil {
		wire, err := encodeContainerSnapshot(next)
		if err != nil {
			return err
		}
		if err := fence.Guard(ctx, epoch); err != nil {
			return err
		}
		_, err = client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: containerSnapshotName(next.ServiceID), Labels: map[string]string{containerSecretSnapshotLabel: string(wire)}}, Data: []byte(containerSecretSnapshotSchema)}})
		return err
	}
	var previous containerSecretSnapshot
	if string(config.Spec.Data) != containerSecretSnapshotSchema {
		return containermaterial.ErrPending
	}
	if err := protocol.DecodeStrict([]byte(config.Spec.Annotations.Labels[containerSecretSnapshotLabel]), &previous, 32<<10); err != nil {
		return err
	}
	if previous.ServiceID != next.ServiceID {
		return containermaterial.ErrPending
	}
	changed := previous.ConfigDigest != next.ConfigDigest
	newOperation := previous.OperationID != next.OperationID
	for key, value := range next.Versions {
		old, exists := previous.Versions[key]
		if exists && old.ID == value.ID && value.Version < old.Version {
			return containermaterial.ErrPending
		}
		if !exists || old != value {
			changed = true
		}
	}
	if len(previous.Versions) != len(next.Versions) {
		changed = true
	}
	if newOperation {
		wire, err := encodeContainerSnapshot(next)
		if err != nil {
			return err
		}
		spec := config.Spec.Copy()
		spec.Annotations.Labels[containerSecretSnapshotLabel] = string(wire)
		if err := fence.Guard(ctx, epoch); err != nil {
			return err
		}
		_, err = client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.ID, ConfigVersion: &config.Meta.Version, Spec: spec})
		return err
	}
	if previous.Generation > next.Generation {
		if previous.Generation != next.Generation+1 {
			return containermaterial.ErrPending
		}
		// Finish the reserved generation before observing a newer Vault version.
		next = previous
	} else if changed {
		if previous.Generation != next.Generation || next.Generation == ^uint64(0) {
			return containermaterial.ErrPending
		}
		next.Generation++
		wire, err := encodeContainerSnapshot(next)
		if err != nil {
			return err
		}
		spec := config.Spec.Copy()
		spec.Annotations.Labels[containerSecretSnapshotLabel] = string(wire)
		if err := fence.Guard(ctx, epoch); err != nil {
			return err
		}
		if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.ID, ConfigVersion: &config.Meta.Version, Spec: spec}); err != nil {
			return err
		}
	} else if previous.Generation != next.Generation {
		return containermaterial.ErrPending
	}
	if next.Generation == service.Spec.Task.ForceUpdate {
		return nil
	}
	spec := service.Spec.Copy()
	spec.Task.ForceUpdate = next.Generation
	if err := fence.Guard(ctx, epoch); err != nil {
		return err
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &service.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	return fmt.Errorf("%w: OCI Vault versions replaced upstream task generation", containermaterial.ErrPending)
}
