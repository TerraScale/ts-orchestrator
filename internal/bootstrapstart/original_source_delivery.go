package bootstrapstart

import (
	"context"
	"errors"
)

const (
	OriginalFoundationPublicFilename = "original-foundation-public.json"
	MaxOriginalFoundationPublicBytes = 3 << 20
)

// FetchOriginalBundleSHA256 reads only the existing fixed descriptor. Missing
// metadata follows ordinary startup; a present malformed descriptor fails closed.
func (imds IMDSClient) FetchOriginalBundleSHA256(ctx context.Context) (string, error) {
	wire, err := imds.fetch(ctx, descriptorEndpoint, maxDescriptorBytes)
	if errors.Is(err, errMetadataAbsent) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	descriptor, err := ParseDescriptor(wire)
	if err != nil {
		return "", err
	}
	return descriptor.OriginalBundleSHA256, nil
}
