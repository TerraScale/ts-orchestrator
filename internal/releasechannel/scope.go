package releasechannel

import (
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// ValidateDeploymentScope validates fresh regional inventory independently of
// release progress. A rolling or failed release still needs the next green build.
func (status Status) ValidateDeploymentScope(cell string, now time.Time) error {
	if status.Schema != StatusSchema || !release.ValidRegion(cell) || status.Cell != cell ||
		!release.ValidEnvironment(status.Environment) || len(status.Architectures) == 0 || len(status.Architectures) > 2 ||
		!slices.IsSorted(status.Architectures) {
		return fmt.Errorf("%w: missing or invalid deployment scope for %s", ErrInvalid, cell)
	}
	for i, architecture := range status.Architectures {
		if architecture != "amd64" && architecture != "arm64" || i > 0 && architecture == status.Architectures[i-1] {
			return fmt.Errorf("%w: unsupported or duplicate architecture for %s", ErrInvalid, cell)
		}
	}
	if status.UpdatedAt.IsZero() || now.Sub(status.UpdatedAt) > MaxPinAge || status.UpdatedAt.Sub(now) > PinRefreshInterval {
		return fmt.Errorf("%w: stale deployment scope for %s", ErrInvalid, cell)
	}
	return nil
}
