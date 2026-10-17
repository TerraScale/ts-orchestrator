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

// observeImageTransfer consumes the existing authenticated publication checkpoint.
// Neither a local journal, image tags nor a qualification seal alone ends cleanup.
func (c *cloud) observeImageTransfer(ctx context.Context, observer *ociclient.Factory, j journal) (bool, error) {
	if c == nil || ctx == nil || observer == nil || c.now == nil {
		return false, errors.New("original retained image and authenticated publication reader required")
	}
	p, a := c.prepared, c.prepared.approval
	bucket, err := releasechannel.BucketName(a.Candidate.Cell)
	if err != nil || a.Bucket != bucket || a.Namespace == "" || observer.Region() != a.OCIRegion {
		return false, errors.New("publication destination differs from original signed authority")
	}
	tenancy, err := observer.Provider().TenancyOCID()
	if err != nil || tenancy != a.Tenancy {
		return false, errors.New("publication reader tenancy differs from original signed authority")
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		retained, err := c.retainImage(j)
		if err != nil {
			return err
		}
		if !retained || !j.RetentionEndedAt.IsZero() || !c.now().Before(a.ImageTransferUntil) {
			return errors.New("original finite image transfer authority expired or ended")
		}
		// This reopens the original preparation, host approval and delegation,
		// including the original signer's exact postlaunch SDK refinement.
		if _, err := hostadmission.VerifyReaderBinding(j.RetainedReaderProof, p.roots, c.now()); err != nil {
			return err
		}
		return c.check(ctx, false)
	}
	if err := guard(ctx); err != nil {
		return false, err
	}
	deadline := a.ImageTransferUntil
	for _, expires := range []time.Time{a.ImageRetainUntil, p.expires} {
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	bounded = ociclient.WithAuthority(ociclient.WithRequestGuard(bounded, guard), guard)
	current, found, err := releasechannel.ReadCurrentImageSDK(bounded, observer, a.Namespace, p.roots,
		releasechannel.CurrentImageExpectation{Cell: a.Candidate.Cell, Environment: a.Candidate.Environment,
			Architecture: a.Candidate.Architecture, Role: release.FoundationWriterRole}, c.now())
	if err != nil || !found {
		return false, err
	}
	expected := release.ImageExpectation{Environment: a.Candidate.Environment, LogicalRegion: a.Candidate.Cell,
		Architecture: a.Candidate.Architecture, OCIImageOCID: j.ImageID}
	if err := current.FoundationWriter.ValidFor(expected, c.now()); err != nil {
		return false, err
	}
	receipt := current.FoundationWriter.Image().Receipt()
	if receipt.SourceRevision != a.Candidate.SourceRevision || receipt.ImageSHA256 != a.Candidate.ArtifactSHA256 ||
		receipt.QualificationSHA256 != a.Candidate.QualificationSHA256 || receipt.ImageBytes != a.ImageBytes ||
		receipt.BinarySHA256 != a.BinarySHA256 || receipt.KernelSHA256 != a.KernelSHA256 || receipt.KernelRelease != a.KernelRelease {
		return false, errors.New("published final image differs from the exact originally approved candidate bytes")
	}
	candidate := a.Candidate
	candidate.Role, candidate.ImageOCID = release.FoundationWriterRole, j.ImageID
	qualification, err := release.VerifyProductionCurrent(current.QualificationWire, current.QualificationDelegationWire, p.roots, candidate, c.now())
	if err != nil {
		return false, err
	}
	// v2 verifies the exact ordered gates; the final gate binds every original
	// reader proof and native host retained by this lifecycle, not another run.
	if qualification.Evidence[len(qualification.Evidence)-1].Gate != release.RootCredentialBoundaryGate ||
		qualification.Evidence[len(qualification.Evidence)-1].SHA256 != j.RootGateSHA256 {
		return false, errors.New("published writer proof differs from this lifecycle's retained root gate")
	}
	compute, err := observer.Compute()
	if err != nil {
		return false, err
	}
	image, err := compute.GetImage(ociclient.RequestContext(bounded), core.GetImageRequest{ImageId: new(j.ImageID)})
	if err != nil {
		return false, err
	}
	if image.Id == nil || *image.Id != j.ImageID || image.CompartmentId == nil || *image.CompartmentId != a.Compartment ||
		image.LifecycleState != core.ImageLifecycleStateAvailable || image.DisplayName == nil || *image.DisplayName != c.name("image") ||
		!c.owns(image.FreeformTags) || image.FreeformTags[imageimport.SHA256Tag] != a.Candidate.ArtifactSHA256 {
		return false, errors.New("live published image differs from the original exact image and compartment")
	}
	if err := current.FoundationWriter.ValidFor(expected, c.now()); err != nil {
		return false, err
	}
	if err := guard(bounded); err != nil {
		return false, err
	}
	return true, nil
}
