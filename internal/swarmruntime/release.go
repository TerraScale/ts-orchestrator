package swarmruntime

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const labelReleaseBaseline = "terrascale.release-baseline"
const labelReleaseArchitecture = "terrascale.release-architecture"
const labelReleaseMigration = "terrascale.release-migration"
const labelReleaseGenesis = "terrascale.release-genesis"

// The worker artifact floor is shared by functions but independent per qualified architecture.
func releaseFloorName(intent ServiceIntent, verified release.VerifiedContainer) (string, error) {
	claim := verified.Claim()
	region, known := catalog.CellForOCIRegion(intent.Region)
	if !known || !verified.Valid(time.Now().UTC()) || claim.Cell != region.Cell || claim.Role != intent.Role || claim.Environment != intent.Environment || claim.Architecture != intent.Architecture {
		return "", errors.New("release floor requires current proof for admitted target")
	}
	scope := intent.Environment + "/" + intent.Region + "/" + intent.Role
	if claim.Role == "function-worker" {
		scope += "/" + claim.Architecture
	}
	identity := sha256.Sum256([]byte(scope))
	return fmt.Sprintf("ts-release-%x", identity[:16]), nil
}

// Both mutation and task admission reconstruct the same authenticated revision.
func (intent ServiceIntent) withVerifiedRelease(verified release.VerifiedContainer) (ServiceIntent, error) {
	claim := verified.Claim()
	if !verified.Valid(time.Now().UTC()) || intent.Container == nil || claim.Image != intent.Container.Image {
		return ServiceIntent{}, errors.New("service image differs from current signed OCI child manifest")
	}
	intent.releaseSequence = claim.ReleaseSequence
	intent.releaseFingerprint = verified.ReleaseIdentity()
	spec, err := intent.serviceSpec()
	if err != nil {
		return ServiceIntent{}, err
	}
	if intent.Generation != 0 {
		intent.intentFingerprint, err = serviceIntentFingerprint(spec)
		if err != nil {
			return ServiceIntent{}, err
		}
	}
	return intent, nil
}
