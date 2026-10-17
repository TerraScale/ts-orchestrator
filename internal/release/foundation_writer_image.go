package release

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedFoundationWriterImage cannot be manufactured from ordinary image authority.
type VerifiedFoundationWriterImage struct {
	image      VerifiedImage
	expected   ImageExpectation
	verifiedAt time.Time
	expires    time.Time
}

func (proof VerifiedFoundationWriterImage) Image() VerifiedImage { return proof.image }
func (proof VerifiedFoundationWriterImage) ExpiresAt() time.Time { return proof.expires }

func (proof VerifiedFoundationWriterImage) ValidFor(expected ImageExpectation, now time.Time) error {
	if !proof.image.IsVerified() || expected != proof.expected || now.IsZero() ||
		now.Before(proof.verifiedAt) || !now.Before(proof.expires) {
		return fmt.Errorf("%w: current foundation writer image purpose", ErrProductionQualification)
	}
	return nil
}

// VerifyFoundationWriterImageCurrent checks ordinary manager admission and the
// independently qualified root credential boundary on the same final disk.
func VerifyFoundationWriterImageCurrent(ctx context.Context, input HostImageQualification, roots trust.Keyring,
	openEvidence func(context.Context, string) (io.ReadCloser, error), now time.Time,
) (VerifiedFoundationWriterImage, error) {
	if input.Role != "manager" {
		return VerifiedFoundationWriterImage{}, fmt.Errorf("%w: foundation writer requires a manager image", ErrProductionQualification)
	}
	image, expires, err := VerifyHostImageCurrent(ctx, input, roots, openEvidence, now)
	if err != nil {
		return VerifiedFoundationWriterImage{}, err
	}
	receipt := image.Receipt()
	production, exists := receipt.HostProduction[FoundationWriterRole]
	if !exists {
		return VerifiedFoundationWriterImage{}, fmt.Errorf("%w: missing foundation writer qualification", ErrProductionQualification)
	}
	candidate := ProductionExpectation{ImageOCID: receipt.OCIImageOCID, SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: input.Expected.Environment,
		Runtime: ProductionRuntime, Architecture: receipt.Architecture, Role: FoundationWriterRole}
	deadline, err := VerifyRetainedProductionCurrent(ctx, production, roots, candidate, openEvidence, now)
	if err != nil {
		return VerifiedFoundationWriterImage{}, err
	}
	if deadline.Before(expires) {
		expires = deadline
	}
	return VerifiedFoundationWriterImage{image: image, expected: input.Expected, verifiedAt: now, expires: expires}, nil
}
