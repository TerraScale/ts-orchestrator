package region

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/registry/pullauth"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func netBirdComponentRoles() [3]string {
	return [3]string{"netbird-server", "netbird-dashboard", "netbird-ingress"}
}

// NetBirdComponent contains public release and CURRENT credential metadata.
// It grants no native task, persistent store or process ownership.
type NetBirdComponent struct {
	role      string
	release   release.VerifiedContainer
	pull      pullauth.PullClaim
	authority VerifiedContainerReleaseAuthority
	issuer    VerifiedOCIRIssuer
}

// NetBirdComponents is a finite complete snapshot, never a retained release
// floor. A future native owner must separately enforce ordering and OS custody.
type NetBirdComponents struct{ state *netBirdComponents }

type netBirdComponents struct {
	factory    *ociclient.Factory
	resolver   FoundationResolver
	reader     *SignedFootprint
	manager    VerifiedNetBirdManager
	intent     verifiedNetBirdIntent
	original   bool
	expires    time.Time
	components [3]NetBirdComponent
	// guardID marks this material's guard as passed within one memoized operation.
	guardID, checkID *byte
}
