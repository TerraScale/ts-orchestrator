package fleet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleetregion"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
)

const sourceURL = "https://raw.githubusercontent.com/TerraScale/ts-orchestrator/"

type nodeRelease struct {
	attested releaseattest.Release
	document []byte
}

func newestNodeRelease(ctx context.Context) (nodeRelease, error) {
	newest, err := releaseattest.NewSource().Newest(ctx)
	if err != nil {
		return nodeRelease{}, fmt.Errorf("newest release: %w", err)
	}
	verifier, err := releaseattest.PublicGood()
	if err != nil {
		return nodeRelease{}, err
	}
	client := &http.Client{Timeout: time.Minute}
	attested, err := verifier.Attested(ctx, client, newest)
	if err != nil {
		return nodeRelease{}, fmt.Errorf("attest %s: %w", newest.Tag(), err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL+attested.SHA+"/deploy/fleet/fleet.json", nil)
	if err != nil {
		return nodeRelease{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nodeRelease{}, fmt.Errorf("fleet document of %s: %w", attested.Tag(), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nodeRelease{}, fmt.Errorf("fleet document of %s: %s", attested.Tag(), response.Status)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nodeRelease{}, fmt.Errorf("fleet document of %s: %w", attested.Tag(), err)
	}
	return nodeRelease{attested: attested, document: document}, nil
}

func (r nodeRelease) knows(region Region) error {
	label, err := fleetregion.In(r.document, region.OCIRegion, region.CompartmentID)
	if err != nil {
		return fmt.Errorf("attested release %s does not know region %s: %w", r.attested.Tag(), region.Label, err)
	}
	if label != region.Label {
		return fmt.Errorf("attested release %s calls compartment %s %s, not %s", r.attested.Tag(), region.CompartmentID, label, region.Label)
	}
	return nil
}

func releaseCheck(release nodeRelease, found error, region Region) Check {
	if found != nil {
		return Check{Kind: "release", State: Missing, Details: []string{found.Error()}}
	}
	if err := release.knows(region); err != nil {
		return Check{Kind: "release", State: Differs, Details: []string{err.Error() + "; compute refuses to launch nodes on it"}}
	}
	return Check{Kind: "release", State: Ok, Details: []string{release.attested.Tag() + " knows " + region.Label}}
}
