package app

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
)

const edgeProofKey = "TERRABASE_PEER_SECRET_FILE"

func edgeProofRef(services []*api.Service) (string, error) {
	for _, svc := range services {
		labels := svc.Spec.Annotations.Labels
		if labels[swarmruntime.LabelServiceSpec] != "terrabase" {
			continue
		}
		var refs map[string]vaultsecret.Ref
		if json.Unmarshal([]byte(labels[swarmruntime.LabelSecretRefs]), &refs) != nil {
			return "", errors.New("invalid TerraBase secret references for request proof")
		}
		ref, ok := refs[edgeProofKey]
		if !ok {
			return "", nil
		}
		data, err := json.Marshal(ref)
		return string(data), err
	}
	return "", nil
}

func refreshEdgeRequestProof(ctx context.Context, public *edge.Edge, encoded string,
	read func(context.Context, string, map[string]vaultsecret.Ref) (map[string]string, error),
) error {
	if encoded == "" {
		return public.SetRequestProofSecret("")
	}
	var ref vaultsecret.Ref
	if json.Unmarshal([]byte(encoded), &ref) != nil {
		return errors.New("invalid TerraBase request proof reference")
	}
	values, err := read(ctx, "terrabase", map[string]vaultsecret.Ref{edgeProofKey: ref})
	defer clear(values)
	if err != nil || values[edgeProofKey] == "" {
		return errors.New("TerraBase request proof credential unavailable; the last good credential stays")
	}
	return public.SetRequestProofSecret(values[edgeProofKey])
}
