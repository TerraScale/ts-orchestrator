package bootstrapstart

import (
	"bytes"
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const OriginalStartupMetadataKey = "terrascale-original-startup-v1"
const originalStartupMetadataEndpoint = imdsBaseURL + "metadata/" + OriginalStartupMetadataKey

// This locator selects fixed signed public records; it grants no authority.
type originalStartupLocator struct {
	SchemaVersion    int        `json:"schemaVersion"`
	Cell             oci.Region `json:"cell"`
	GrantSHA256      string     `json:"grantSha256"`
	HomeAnchorSHA256 string     `json:"homeAnchorSha256"`
}

func parseOriginalStartupLocator(wire []byte) (originalStartupLocator, error) {
	var locator originalStartupLocator
	if protocol.DecodeStrict(wire, &locator, maxDescriptorBytes) != nil || locator.SchemaVersion != 1 ||
		!originalBundleDigestRE.MatchString(locator.GrantSHA256) || !originalBundleDigestRE.MatchString(locator.HomeAnchorSHA256) {
		return originalStartupLocator{}, ErrLaunchMaterial
	}
	if _, err := locator.Cell.OCIRegion(); err != nil {
		return originalStartupLocator{}, ErrLaunchMaterial
	}
	canonical, err := protocol.EncodeJSON(locator)
	if err != nil || !bytes.Equal(wire, canonical) {
		return originalStartupLocator{}, ErrLaunchMaterial
	}
	return locator, nil
}

func (imds IMDSClient) fetchOriginalStartup(ctx context.Context) (originalStartupLocator, error) {
	wire, err := imds.fetch(ctx, originalStartupMetadataEndpoint, maxDescriptorBytes)
	if errors.Is(err, errMetadataAbsent) {
		return originalStartupLocator{}, ErrNotOriginalStartup
	}
	if err != nil {
		return originalStartupLocator{}, err
	}
	return parseOriginalStartupLocator(wire)
}
