//go:build fixturetest

package region

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// PrepareRuntimeCreationFixture uses the actual signed-source HomeIAM fixture;
// callers cannot supply a store, resolver, payload or authorization callback.
func PrepareRuntimeCreationFixture(ctx context.Context, home *HomeIAMAuthority, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*RuntimeCreationPermit, error) {
	expires := time.Now().UTC().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	return prepareRuntimeCreation(ctx, home, reader, accepted, expires)
}
