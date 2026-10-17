package imagequalification

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

type imageTransfer struct{ manifestSHA256, imageID, approvalSHA256 string }

// observeImageTransfer consumes the existing authenticated publication checkpoint.
// Neither a local journal, image tags nor a qualification seal alone ends cleanup.
func (c *cloud) observeImageTransfer(ctx context.Context, observer *ociclient.Factory, j journal) (imageTransfer, error) {
	var empty imageTransfer
	if c == nil || ctx == nil || observer == nil || c.now == nil {
		return empty, errors.New("original retained image and authenticated publication reader required")
	}
	p, a := c.prepared, c.prepared.approval
	bucket, err := releasechannel.BucketName(a.Candidate.Cell)
	if err != nil || a.ImagePublicationBucket != bucket || a.Namespace == "" || observer.Region() != a.OCIRegion {
		return empty, errors.New("publication destination differs from original signed authority")
	}
	tenancy, err := observer.Provider().TenancyOCID()
	if err != nil || tenancy != a.Tenancy {
		return empty, errors.New("publication reader tenancy differs from original signed authority")
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := c.retainImage(j); err != nil {
			return err
		}
		if len(j.RetainedReaderProof) == 0 {
			return errors.New("original retained reader proof required")
		}
		// Observation may recover a completed transfer after its create cap.
		// This grants no writes and remains inside original cleanup authority.
		return c.check(ctx, true)
	}
	if err := guard(ctx); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithDeadline(ctx, a.CleanupUntil)
	defer cancel()
	bounded = ociclient.WithAuthority(ociclient.WithRequestGuard(bounded, guard), guard)
	current, found, err := releasechannel.ReadPublishedImageSDK(bounded, observer, a.Namespace, p.roots,
		releasechannel.CurrentImageExpectation{Cell: a.Candidate.Cell, Environment: a.Candidate.Environment,
			Architecture: a.Candidate.Architecture, Role: release.FoundationWriterRole}, j.ImageManifestSHA256, c.now())
	if err != nil || !found {
		return empty, err
	}
	if j.ImageManifestSHA256 != "" && current.ManifestSHA256 != j.ImageManifestSHA256 {
		return empty, errors.New("authenticated image publication substituted the retained immutable reference")
	}
	if current.Image.Receipt().OCIImageOCID != j.ImageID {
		if j.ImageManifestSHA256 != "" {
			return empty, errors.New("recorded image publication differs from the retained image")
		}
		// Discovery may still name another run's fully authenticated image.
		return empty, nil
	}
	publishedAt := current.ManifestLastModified
	publicationUpper := publishedAt.Add(time.Second)
	plan, err := hostadmission.VerifyReaderBinding(j.RetainedReaderProof, p.roots, publishedAt)
	if err != nil {
		return empty, err
	}
	// OCI's Last-Modified has second precision. The entire possible interval
	// must precede every original cap; no local acceptance timestamp authorizes it.
	for _, deadline := range []time.Time{a.ImageTransferUntil, a.ImageRetainUntil, p.expires, plan.ExpiresAt()} {
		if !publicationUpper.Before(deadline) {
			return empty, errors.New("authenticated image publication is outside original transfer authority")
		}
	}
	if !j.RetentionEndedAt.IsZero() && !publicationUpper.Before(j.RetentionEndedAt) {
		return empty, errors.New("authenticated image publication followed retention cancellation")
	}
	expected := release.ImageExpectation{Environment: a.Candidate.Environment, LogicalRegion: a.Candidate.Cell,
		Architecture: a.Candidate.Architecture, OCIImageOCID: j.ImageID}
	if err := current.FoundationWriter.ValidFor(expected, publishedAt); err != nil {
		return empty, err
	}
	receipt := current.FoundationWriter.Image().Receipt()
	if receipt.SourceRevision != a.Candidate.SourceRevision || receipt.ImageSHA256 != a.Candidate.ArtifactSHA256 ||
		receipt.QualificationSHA256 != a.Candidate.QualificationSHA256 || receipt.ImageBytes != a.ImageBytes ||
		receipt.BinarySHA256 != a.BinarySHA256 || receipt.KernelSHA256 != a.KernelSHA256 || receipt.KernelRelease != a.KernelRelease {
		return empty, errors.New("published final image differs from the exact originally approved candidate bytes")
	}
	candidate := a.Candidate
	candidate.Role, candidate.ImageOCID = release.FoundationWriterRole, j.ImageID
	qualification, err := release.VerifyProductionCurrent(current.QualificationWire, current.QualificationDelegationWire, p.roots, candidate, publishedAt)
	if err != nil {
		return empty, err
	}
	// v2 verifies the exact ordered gates; the final gate binds every original
	// reader proof and native host retained by this lifecycle, not another run.
	if qualification.Evidence[len(qualification.Evidence)-1].Gate != release.RootCredentialBoundaryGate ||
		qualification.Evidence[len(qualification.Evidence)-1].SHA256 != j.RootGateSHA256 {
		return empty, errors.New("published writer proof differs from this lifecycle's retained root gate")
	}
	compute, err := observer.Compute()
	if err != nil {
		return empty, err
	}
	image, err := compute.GetImage(ociclient.RequestContext(bounded), core.GetImageRequest{ImageId: new(j.ImageID)})
	if err != nil {
		return empty, err
	}
	if image.Id == nil || *image.Id != j.ImageID || image.CompartmentId == nil || *image.CompartmentId != a.Compartment ||
		image.LifecycleState != core.ImageLifecycleStateAvailable || image.DisplayName == nil || *image.DisplayName != c.name("image") ||
		!c.owns(image.FreeformTags) || image.FreeformTags[imageimport.SHA256Tag] != a.Candidate.ArtifactSHA256 {
		return empty, errors.New("live published image differs from the original exact image and compartment")
	}
	if err := guard(bounded); err != nil {
		return empty, err
	}
	if publicationUpper.After(c.now()) || !validHash(current.ManifestSHA256) {
		return empty, errors.New("authenticated publication interval or immutable reference is invalid")
	}
	return imageTransfer{manifestSHA256: current.ManifestSHA256, imageID: j.ImageID, approvalSHA256: p.approvalSHA256}, nil
}
