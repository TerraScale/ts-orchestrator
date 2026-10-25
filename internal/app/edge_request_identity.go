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

// refreshEdgeRequestProof reuses only the peer credential already admitted for
// TerraBase. No extra Vault secret, service reference or environment is needed.
func refreshEdgeRequestProof(ctx context.Context, public *edge.Edge, services []*api.Service,
	read func(context.Context, string, map[string]vaultsecret.Ref) (map[string]string, error),
) (err error) {
	defer func() {
		if err != nil {
			_ = public.SetRequestProofSecret("")
		}
	}()
	const key = "TERRABASE_PEER_SECRET_FILE"
	for _, svc := range services {
		labels := svc.Spec.Annotations.Labels
		if labels[swarmruntime.LabelServiceSpec] != "terrabase" {
			continue
		}
		var refs map[string]vaultsecret.Ref
		if json.Unmarshal([]byte(labels[swarmruntime.LabelSecretRefs]), &refs) != nil {
			return errors.New("invalid TerraBase secret references for request proof")
		}
		if ref, ok := refs[key]; ok {
			values, readErr := read(ctx, "terrabase", map[string]vaultsecret.Ref{key: ref})
			if readErr != nil || values[key] == "" {
				return errors.New("TerraBase request proof credential unavailable")
			}
			defer clear(values)
			return public.SetRequestProofSecret(values[key])
		}
	}
	return public.SetRequestProofSecret("")
}
