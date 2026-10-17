package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func (reader *rootBrokerReader) ProbeNetBirdController(ctx context.Context, target rootBrokerNetBirdProbeRequest) error {
	response, err := reader.invokeRequest(ctx, rootBrokerRequest{Operation: rootBrokerNetBirdProbe, NetBirdProbe: &target}, 8*time.Second)
	if err != nil {
		return err
	}
	proof := response.NetBirdProbe
	if proof == nil || proof.Target != target || naming.Validate(proof.ServerName) != nil ||
		proof.ExpiresAt.IsZero() || !time.Now().Before(proof.ExpiresAt) || ctx == nil || ctx.Err() != nil ||
		reader.ctx.Err() != nil || !reader.transportReady() {
		return rootoci.ErrUnauthorized
	}
	return nil
}
