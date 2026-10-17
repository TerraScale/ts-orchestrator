//go:build fixturetest

package region

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// NewRuntimeHomeIAMAuthorityWithClient preserves the opaque runtime IAM proof,
// actual storage protocol and current signed foundation with its durable floor.
func NewRuntimeHomeIAMAuthorityWithClient(ctx context.Context, proof bootstrapstart.VerifiedRuntimeIAM,
	resolver FoundationResolver, objects *objectstorage.ObjectStorageClient, genesis trust.Keyring,
) (*HomeIAMAuthority, error) {
	if objects == nil || len(genesis) == 0 {
		return nil, bootstrapstart.ErrSourceFounder
	}
	return newRuntimeHomeIAMAuthority(ctx, proof, resolver, objects, genesis)
}
