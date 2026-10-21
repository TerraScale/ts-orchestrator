package rootrelease

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Unverified dates only shorten an operation. Full current release verification
// remains required before the context can authorize any effect.
func containerProofContext(ctx context.Context, bundle release.ContainerBundle) (context.Context, context.CancelFunc, error) {
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		return ctx, func() {}, err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return ctx, func() {}, err
	}
	deadline := envelope.ExpiresAt
	for _, wire := range [][]byte{bundle.Delegation, claim.Production.Qualification, claim.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		finite, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return ctx, func() {}, err
		}
		deadline = earlier(deadline, finite.ExpiresAt)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline.Add(-time.Nanosecond))
	return ctx, cancel, ctx.Err()
}
