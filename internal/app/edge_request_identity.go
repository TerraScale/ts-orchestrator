package app

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

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
	values, err := read(ctx, "terrabase", map[string]vaultsecret.Ref{edge.RequestProofKey: ref})
	defer clear(values)
	if err != nil || values[edge.RequestProofKey] == "" {
		return errors.New("TerraBase request proof credential unavailable; the last good credential stays")
	}
	return public.SetRequestProofSecret(values[edge.RequestProofKey])
}
