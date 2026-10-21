package releasechannel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const currentImageSchema = "terrascale.release.current-image.v1"

// CurrentImageExpectation comes from placement or the independently approved foundation.
type CurrentImageExpectation struct {
	Cell, Environment, Architecture, Role string
}

// CurrentImage retains the exact signed inputs used for a grant or launch recipe.
// A later locator update must never replace these wires in an existing recipe.
type CurrentImage struct {
	Image                                          release.VerifiedImage
	FoundationWriter                               release.VerifiedFoundationWriterImage
	ExpiresAt                                      time.Time
	ManifestSHA256                                 string
	ManifestLastModified                           time.Time
	ReceiptWire, DelegationWire                    []byte
	QualificationWire, QualificationDelegationWire []byte
}

type imageCurrentLocator struct {
	Schema         string `json:"schema"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type imageCurrentManifest struct {
	Receipt    []byte `json:"receipt"`
	Delegation []byte `json:"delegation"`
}

func imageCurrentRole(role string) string {
	switch role {
	case "controller", "manager":
		return "orchestrator"
	default:
		return role
	}
}

// CurrentImageObject is discovery only; its contents authorize neither freshness nor mutation.
func CurrentImageObject(role, architecture, environment string) string {
	return "releases/images/current/" + environment + "/" + imageCurrentRole(role) + "/linux-" + architecture + ".json"
}

// ImageManifestObject retains exact receipt/delegation wires independently of the locator.
func ImageManifestObject(digest string) string {
	return "releases/images/manifests/" + digest + ".json"
}

func (expected CurrentImageExpectation) validate() error {
	if !release.ValidRegion(expected.Cell) || !release.ValidEnvironment(expected.Environment) || expected.Architecture != "amd64" && expected.Architecture != "arm64" {
		return fmt.Errorf("%w: current image target", ErrInvalid)
	}
	switch imageCurrentRole(expected.Role) {
	case "orchestrator", "container", "wasm", release.FoundationWriterRole:
	case "netbird-manager":
		if expected.Cell != "GRU" || expected.Architecture != "arm64" {
			return fmt.Errorf("%w: NetBird image target", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: current image role", ErrInvalid)
	}
	return nil
}

func currentImageLocation(location Location, expected CurrentImageExpectation) error {
	if err := expected.validate(); err != nil {
		return err
	}
	bucket, err := BucketName(expected.Cell)
	if err != nil {
		return err
	}
	if location.Client == nil || location.Namespace == "" || location.Bucket != bucket {
		return fmt.Errorf("%w: current image must use the admitted region's head bucket", ErrInvalid)
	}
	return nil
}

// ReadCurrentImageSDK preserves authenticated OCI identity and derives the source region and bucket in code.
func ReadCurrentImageSDK(ctx context.Context, factory *ociclient.Factory, namespace string, roots trust.Keyring, expected CurrentImageExpectation, now time.Time) (CurrentImage, bool, error) {
	location, err := imageLocationSDK(factory, namespace, expected)
	if err != nil {
		return CurrentImage{}, false, err
	}
	return ReadCurrentImage(ctx, location, roots, expected, now)
}

func imageLocationSDK(factory *ociclient.Factory, namespace string, expected CurrentImageExpectation) (Location, error) {
	if err := expected.validate(); err != nil {
		return Location{}, err
	}
	if factory == nil || namespace == "" {
		return Location{}, fmt.Errorf("%w: current image OCI identity", ErrInvalid)
	}
	region, ok := catalog.Lookup(expected.Cell)
	if !ok {
		return Location{}, fmt.Errorf("%w: current image region", ErrInvalid)
	}
	regional, err := factory.ForRegion(region.OCIRegion)
	if err != nil {
		return Location{}, err
	}
	client, err := regional.ObjectStorage()
	if err != nil {
		return Location{}, err
	}
	bucket, err := BucketName(expected.Cell)
	if err != nil {
		return Location{}, err
	}
	return Location{Client: client, Namespace: namespace, Bucket: bucket}, nil
}

// ReadCurrentImage verifies every authority and retained evidence byte selected by a locator.
// No timestamp or CI run from discovery is used as release ordering authority.
func ReadCurrentImage(ctx context.Context, location Location, roots trust.Keyring, expected CurrentImageExpectation, now time.Time) (CurrentImage, bool, error) {
	if err := currentImageLocation(location, expected); err != nil {
		return CurrentImage{}, false, err
	}
	var locator imageCurrentLocator
	found, err := location.read(ctx, CurrentImageObject(expected.Role, expected.Architecture, expected.Environment), trust.MaxEnvelopeBytes, &locator)
	if err != nil || !found {
		return CurrentImage{}, false, err
	}
	digest, err := hex.DecodeString(locator.ManifestSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != locator.ManifestSHA256 || locator.Schema != currentImageSchema {
		return CurrentImage{}, false, fmt.Errorf("%w: current image locator", ErrInvalid)
	}
	wire, _, found, err := location.get(ctx, ImageManifestObject(locator.ManifestSHA256), MaxChannelBytes)
	if err != nil || !found {
		return CurrentImage{}, false, err
	}
	sum := sha256.Sum256(wire)
	if !bytes.Equal(sum[:], digest) {
		return CurrentImage{}, false, fmt.Errorf("%w: retained image manifest digest", ErrInvalid)
	}
	var manifest imageCurrentManifest
	if err := protocol.DecodeStrict(wire, &manifest, MaxChannelBytes); err != nil {
		return CurrentImage{}, false, err
	}
	current, found, err := verifyCurrentImageManifest(ctx, location, manifest, roots, expected, now)
	if err == nil && found {
		current.ManifestSHA256 = locator.ManifestSHA256
	}
	return current, found, err
}

func verifyCurrentImageManifest(ctx context.Context, location Location, manifest imageCurrentManifest, roots trust.Keyring, expected CurrentImageExpectation, now time.Time) (CurrentImage, bool, error) {
	envelope, err := trust.DecodeEnvelope(manifest.Receipt)
	if err != nil {
		return CurrentImage{}, false, err
	}
	var selectors release.ImageReceipt
	if err := protocol.DecodeStrict(envelope.Payload, &selectors, trust.MaxPayloadBytes); err != nil {
		return CurrentImage{}, false, err
	}
	imageExpected := release.ImageExpectation{Environment: expected.Environment, LogicalRegion: expected.Cell, Architecture: expected.Architecture, OCIImageOCID: selectors.OCIImageOCID}
	var image release.VerifiedImage
	role := imageCurrentRole(expected.Role)
	if role == release.FoundationWriterRole {
		proof, err := release.VerifyFoundationWriterImageCurrent(ctx, release.HostImageQualification{
			Receipt: manifest.Receipt, Delegation: manifest.Delegation, Expected: imageExpected, Role: "manager",
		}, roots, func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return OpenImageProductionEvidence(ctx, location, digest)
		}, now)
		if err != nil {
			return CurrentImage{}, false, err
		}
		production := proof.Image().Receipt().HostProduction[release.FoundationWriterRole]
		return CurrentImage{Image: proof.Image(), FoundationWriter: proof, ExpiresAt: proof.ExpiresAt(),
			ReceiptWire: bytes.Clone(manifest.Receipt), DelegationWire: bytes.Clone(manifest.Delegation),
			QualificationWire: bytes.Clone(production.Qualification), QualificationDelegationWire: bytes.Clone(production.Delegation)}, true, nil
	}
	if role == "netbird-manager" {
		image, err = release.VerifyNetBirdImageCurrent(manifest.Receipt, manifest.Delegation, roots, imageExpected, now)
	} else {
		image, err = release.VerifyImageCurrent(manifest.Receipt, manifest.Delegation, roots, imageExpected, now)
	}
	if err != nil {
		return CurrentImage{}, false, err
	}
	expires := image.ExpiresAt()
	delegation, err := trust.DecodeEnvelope(manifest.Delegation)
	if err != nil {
		return CurrentImage{}, false, err
	}
	if delegation.ExpiresAt.Before(expires) {
		expires = delegation.ExpiresAt
	}
	receipt := image.Receipt()
	var proof release.ProductionProof
	if role == "orchestrator" {
		proof = *receipt.Production
	} else {
		var exists bool
		proof, exists = receipt.HostProduction[role]
		if !exists {
			return CurrentImage{}, false, nil
		}
	}
	candidate := release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256, Cell: expected.Cell, Environment: expected.Environment, Runtime: release.ProductionRuntime, Architecture: expected.Architecture, Role: role}
	if role == "netbird-manager" {
		candidate.Runtime = release.NetBirdProductionRuntime
	}
	open := func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return OpenImageProductionEvidence(ctx, location, digest)
	}
	// Worker admission also retains the ordinary manager proof carried by the image.
	if role == "container" || role == "wasm" {
		baseline := candidate
		baseline.Role = "orchestrator"
		deadline, err := release.VerifyRetainedProductionCurrent(ctx, *receipt.Production, roots, baseline, open, now)
		if err != nil {
			return CurrentImage{}, false, err
		}
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	deadline, err := release.VerifyRetainedProductionCurrent(ctx, proof, roots, candidate, open, now)
	if err != nil {
		return CurrentImage{}, false, err
	}
	if deadline.Before(expires) {
		expires = deadline
	}
	return CurrentImage{Image: image, ExpiresAt: expires, ReceiptWire: bytes.Clone(manifest.Receipt), DelegationWire: bytes.Clone(manifest.Delegation), QualificationWire: bytes.Clone(proof.Qualification), QualificationDelegationWire: bytes.Clone(proof.Delegation)}, true, nil
}

// PublishCurrentImage writes immutable signed inputs before replacing discovery.
// Images have no signed sequence today; existing grants, not locator timestamps, pin launches.
func PublishCurrentImage(ctx context.Context, location Location, receiptWire, delegationWire []byte, roots trust.Keyring, expected CurrentImageExpectation, now time.Time) error {
	if err := currentImageLocation(location, expected); err != nil {
		return err
	}
	manifest := imageCurrentManifest{Receipt: receiptWire, Delegation: delegationWire}
	_, found, err := verifyCurrentImageManifest(ctx, location, manifest, roots, expected, now)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: missing image role qualification", ErrInvalid)
	}
	wire, err := json.Marshal(manifest, json.Deterministic(true))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	digest := hex.EncodeToString(sum[:])
	name := ImageManifestObject(digest)
	putErr := location.put(ctx, name, wire, "")
	retained, _, found, readErr := location.get(ctx, name, MaxChannelBytes)
	if readErr != nil || !found || !bytes.Equal(retained, wire) {
		return errors.Join(putErr, readErr, fmt.Errorf("%w: immutable image manifest read-back", ErrInvalid))
	}
	locator, err := json.Marshal(imageCurrentLocator{Schema: currentImageSchema, ManifestSHA256: digest}, json.Deterministic(true))
	if err != nil {
		return err
	}
	current := CurrentImageObject(expected.Role, expected.Architecture, expected.Environment)
	for range 3 {
		previous, etag, found, err := location.get(ctx, current, trust.MaxEnvelopeBytes)
		if err != nil {
			return err
		}
		if found && bytes.Equal(previous, locator) {
			return nil
		}
		if err := location.put(ctx, current, locator, etag); !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}
