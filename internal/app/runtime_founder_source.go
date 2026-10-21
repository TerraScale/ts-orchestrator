package app

import (
	"bytes"
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func currentControllerFounderReader(ctx context.Context, baked bootstrapstart.BakedInputs, initial bootstrapstart.AcceptedInstall,
	floor *bootstrapstart.FounderSelectionFloorStore,
) (*bootstrapstart.CurrentFounderAuthorityReader, error) {
	local, derived, present, err := installedAutomaticStartup(ctx)
	if err != nil {
		return nil, err
	}
	if present {
		if !bytes.Equal(local.baked.AnchorWire, baked.AnchorWire) {
			return nil, errors.New("installed startup authority differs from the runtime anchor")
		}
		return bootstrapstart.NewDerivedCurrentFounderAuthorityReaderContext(ctx, baked, initial, derived, floor)
	}
	return bootstrapstart.NewOCICurrentFounderAuthorityReader(baked, initial, floor)
}
