//go:build fixturetest

package region

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// NewHomeIAMAuthorityWithClient keeps actual signed OCI HTTP, sealed founder,
// current root-chain verification and durable floor checks in offline scenarios.
func NewHomeIAMAuthorityWithClient(ctx context.Context, proof bootstrapstart.VerifiedSourceFounder, resolver FoundationResolver, objects *objectstorage.ObjectStorageClient, genesis trust.Keyring) (*HomeIAMAuthority, error) {
	if objects == nil || len(genesis) == 0 {
		return nil, bootstrapstart.ErrSourceFounder
	}
	return newHomeIAMAuthority(ctx, proof, resolver, objects, genesis)
}

// NewSourceFounderWithClient substitutes only the offline IAM protocol endpoint.
func NewSourceFounderWithClient(ctx context.Context, resolver FoundationResolver, authority *HomeIAMAuthority, iam *identity.IdentityClient) (*SourceFounder, error) {
	if authority == nil || iam == nil {
		return nil, bootstrapstart.ErrSourceFounder
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return nil, bootstrapstart.ErrSourceFounder
	}
	actor := &SourceFounder{authority: authority, resolver: resolver, iam: *iam, cell: entry.Cell}
	if err := actor.Guard(ctx); err != nil {
		return nil, err
	}
	return actor, nil
}
