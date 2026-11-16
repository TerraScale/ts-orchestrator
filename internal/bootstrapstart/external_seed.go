package bootstrapstart

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

var ErrExternalSeedObservation = errors.New("external seed OCI observation differs from signed authority")

// Regional original identity is data from the sealed template, not a forged anchor.
func externalSeedIdentity(authority bootstrap.StartupAuthority, anchor bootstrap.VerifiedBootstrapAnchor) (bootstrap.BootstrapAnchor, *bootstrap.OriginalLaunchIdentity, error) {
	if derived, ok := authority.(bootstrap.DerivedStartupAuthority); ok {
		if original, err := derived.Template().OriginalLaunch(); err == nil {
			bound, err := derived.OriginalLaunch()
			if err != nil || bound != original || derived.Template().OriginAnchor().Digest() != anchor.Digest() {
				return bootstrap.BootstrapAnchor{}, nil, ErrExternalSeedObservation
			}
			return derived.Template().StartupIdentity(), new(original), nil
		}
	}
	return anchor.Anchor(), nil, nil
}
