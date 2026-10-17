package releasechannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// ReadPublishedImageSDK verifies a durable publication at its provider timestamp.
// An empty digest discovers the initial manifest; retries must retain its digest.
func ReadPublishedImageSDK(ctx context.Context, factory *ociclient.Factory, namespace string, roots trust.Keyring, expected CurrentImageExpectation, manifestSHA256 string, now time.Time) (CurrentImage, bool, error) {
	location, err := imageLocationSDK(factory, namespace, expected)
	if err != nil {
		return CurrentImage{}, false, err
	}
	return ReadPublishedImage(ctx, location, roots, expected, manifestSHA256, now)
}

// ReadPublishedImage establishes historical publication only. Its proof retains
// the original expiry; current admission must still verify at the current time.
func ReadPublishedImage(ctx context.Context, location Location, roots trust.Keyring, expected CurrentImageExpectation, manifestSHA256 string, now time.Time) (CurrentImage, bool, error) {
	if err := currentImageLocation(location, expected); err != nil {
		return CurrentImage{}, false, err
	}
	if expected.Role != release.FoundationWriterRole {
		return CurrentImage{}, false, fmt.Errorf("%w: publication replay requires the dedicated writer purpose", ErrInvalid)
	}
	if manifestSHA256 == "" {
		var locator imageCurrentLocator
		found, err := location.read(ctx, CurrentImageObject(expected.Role, expected.Architecture, expected.Environment), trust.MaxEnvelopeBytes, &locator)
		if err != nil || !found {
			return CurrentImage{}, false, err
		}
		if locator.Schema != currentImageSchema {
			return CurrentImage{}, false, fmt.Errorf("%w: current image locator", ErrInvalid)
		}
		manifestSHA256 = locator.ManifestSHA256
	}
	digest, err := hex.DecodeString(manifestSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != manifestSHA256 {
		return CurrentImage{}, false, fmt.Errorf("%w: published image manifest digest", ErrInvalid)
	}
	name := ImageManifestObject(manifestSHA256)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
	})
	if httpStatus(err) == http.StatusNotFound {
		return CurrentImage{}, false, nil
	}
	if err != nil {
		return CurrentImage{}, false, err
	}
	if response.Content == nil {
		return CurrentImage{}, false, fmt.Errorf("%w: published image body missing", ErrInvalid)
	}
	defer response.Content.Close()
	if response.ETag == nil || *response.ETag == "" || response.LastModified == nil {
		return CurrentImage{}, false, fmt.Errorf("%w: published image provider metadata missing", ErrInvalid)
	}
	lower := response.LastModified.Time.UTC()
	upper := lower.Add(time.Second)
	if lower.IsZero() || lower.Nanosecond() != 0 || now.IsZero() || upper.After(now) {
		return CurrentImage{}, false, fmt.Errorf("%w: published image provider timestamp", ErrInvalid)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Content, MaxChannelBytes+1))
	if err != nil {
		return CurrentImage{}, false, err
	}
	sum := sha256.Sum256(wire)
	if len(wire) > MaxChannelBytes || hex.EncodeToString(sum[:]) != manifestSHA256 {
		return CurrentImage{}, false, fmt.Errorf("%w: published image manifest bytes", ErrInvalid)
	}
	var manifest imageCurrentManifest
	if err := protocol.DecodeStrict(wire, &manifest, MaxChannelBytes); err != nil {
		return CurrentImage{}, false, err
	}
	current, found, err := verifyCurrentImageManifest(ctx, location, manifest, roots, expected, lower)
	if err != nil || !found {
		return CurrentImage{}, false, err
	}
	// HTTP Last-Modified loses subsecond precision; authority must cover the
	// entire possible publication interval, without extending its deadline.
	if upper.After(current.ExpiresAt) {
		return CurrentImage{}, false, fmt.Errorf("%w: published image outlived original authority", ErrInvalid)
	}
	current.ManifestSHA256, current.ManifestLastModified = manifestSHA256, lower
	return current, true, nil
}
