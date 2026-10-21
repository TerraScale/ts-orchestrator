package host

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// ValidateProfileIdentity maps the signed lower-case cell through the catalog;
// it never rewrites the identity or the bytes covered by its signature.
func ValidateProfileIdentity(candidate release.ProductionExpectation, identity cellspec.Identity) error {
	entry, ok := catalog.LookupName(identity.Cell)
	if !ok || identity.Validate() != nil || !release.ValidRegion(candidate.Cell) || !release.ValidEnvironment(candidate.Environment) || entry.Cell != candidate.Cell || identity.Environment != candidate.Environment {
		return errors.New("signed production profile identity differs from candidate")
	}
	return nil
}
