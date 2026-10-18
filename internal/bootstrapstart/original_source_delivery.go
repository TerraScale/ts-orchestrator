package bootstrapstart

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
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

// InstallOriginalFoundationPublic stores public bytes only. Its caller must
// verify the exact bundle first; this artifact grants no startup authority.
func InstallOriginalFoundationPublic(wire []byte) error {
	return (bakedStore{directory: BakedDirectory, ownerUID: 0, ownerGID: 0}).installOriginalFoundationPublic(wire)
}

func (store bakedStore) installOriginalFoundationPublic(wire []byte) error {
	if len(wire) == 0 || len(wire) > MaxOriginalFoundationPublicBytes {
		return ErrBakedInputs
	}
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return fmt.Errorf("open original public bundle directory: %w", err)
	}
	defer unix.Close(dir)
	if err := store.writeOnce(dir, OriginalFoundationPublicFilename, wire); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
