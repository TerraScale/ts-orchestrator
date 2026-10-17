package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// CurrentGrantDigest identifies verified authority; it grants no SDK access.
func (s *SignedFootprint) CurrentGrantDigest(ctx context.Context) (string, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return "", err
	}
	if _, _, err := s.verifyGrant(wire); err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// VerifyReadImage uses this discovery's terminal roots, so a locally retained
// image receipt cannot silently recover a retired image signer.
func (s *SignedFootprint) VerifyReadImage(ctx context.Context, cell, imageID string, receipt, delegation []byte) (release.VerifiedImage, error) {
	footprint, err := s.AuthorizedRegions(ctx)
	if err != nil {
		return release.VerifiedImage{}, err
	}
	if !slices.ContainsFunc(footprint.Regions, func(intent FoundationIntent) bool { return intent.Plan["cell"] == cell }) {
		return release.VerifiedImage{}, errors.New("image observation is outside current signed regions")
	}
	return release.VerifyImageCurrent(receipt, delegation, s.roots, release.ImageExpectation{
		Environment: s.scope.Environment, LogicalRegion: cell, OCIImageOCID: imageID,
	}, time.Now().UTC())
}
