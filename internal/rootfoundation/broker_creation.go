package rootfoundation

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// PrepareBrokerCreation keeps the protected writer and root caller checks in
// addition to the lower concrete signed-source capability.
func (b *Backend) PrepareBrokerCreation(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*region.BrokerCreationPermit, error) {
	if b == nil || accepted.Cell != b.cell {
		return nil, ErrScope
	}
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return nil, err
	}
	if err := b.guard(ctx, call); err != nil {
		return nil, err
	}
	return region.PrepareBrokerCreation(ociclient.WithRequestGuard(ctx, call.Guard), b.factory, reader, accepted)
}
