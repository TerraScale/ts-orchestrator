package release

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ReadContainerAllocation reads only the immutable reservation named by an
// authenticated retained release. It grants no current execution authority.
func ReadContainerAllocation(ctx context.Context, location SequenceLocation, roots trust.Keyring, retained HistoricalContainer) ([]byte, error) {
	if retained.Fingerprint() == "" {
		return nil, errors.New("container allocation requires authenticated retained release")
	}
	return location.readWorkerFamily(ctx, roots, retained.value)
}
