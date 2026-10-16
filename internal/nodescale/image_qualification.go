package nodescale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ImageQualification contains signed wires and independently pinned launch facts.
// RoleProduction qualifies container or function isolation on these exact disk bytes;
// an orchestrator image proof alone authorizes only a manager host.
type ImageQualification struct {
	Receipt, Delegation []byte
	Expected            release.ImageExpectation
	Role                string
	RoleProduction      *release.ProductionProof
}

// QualifyImage verifies current root authority and retained qualification evidence.
// openEvidence reads an object by its signed SHA-256 through the existing artifact store.
// The caller re-verifies before mutation; an admitted historical image cannot grow a pool.
func QualifyImage(ctx context.Context, input ImageQualification, roots trust.Keyring,
	openEvidence func(context.Context, string) (io.ReadCloser, error), now time.Time,
) (image QualifiedImage, expires time.Time, err error) {
	defer func() {
		if err != nil {
			image, expires = QualifiedImage{}, time.Time{}
			err = fmt.Errorf("%w: host image qualification: %w", ErrCapacityPending, err)
		}
	}()
	if input.Expected.OCIImageOCID == "" || input.Expected.Architecture == "" || now.IsZero() || openEvidence == nil {
		return image, expires, errors.New("exact image, native architecture, current time and retained evidence reader are required")
	}
	if err := (Capacity{Role: input.Role, Architecture: input.Expected.Architecture, Shape: PreferredShape}).Validate(); err != nil {
		return image, expires, err
	}
	verified, err := release.VerifyImageCurrent(input.Receipt, input.Delegation, roots, input.Expected, now)
	if err != nil {
		return image, expires, err
	}
	receipt := verified.Receipt()
	expires, err = currentImageProofDeadline(now, input.Receipt, input.Delegation)
	if err != nil {
		return image, expires, err
	}
	candidate := release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: input.Expected.Environment,
		Runtime: release.ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}
	proofs := []release.ProductionProof{*receipt.Production}
	if input.Role != RoleManager {
		if input.RoleProduction == nil {
			return image, expires, fmt.Errorf("no independent %s worker qualification for the final disk", input.Role)
		}
		proofs = append(proofs, *input.RoleProduction)
	}
	for index, proof := range proofs {
		if index > 0 {
			candidate.Role = input.Role
		}
		qualification, err := release.VerifyProductionCurrent(proof.Qualification, proof.Delegation, roots, candidate, now)
		if err != nil {
			return image, expires, err
		}
		deadline, err := currentImageProofDeadline(now, proof.Qualification, proof.Delegation)
		if err != nil {
			return image, expires, err
		}
		if deadline.Before(expires) {
			expires = deadline
		}
		for _, evidence := range qualification.Evidence {
			if err := verifyImageEvidence(ctx, openEvidence, evidence); err != nil {
				return image, expires, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return image, expires, err
	}
	// The current signed final disk pins the installed runtime; no additional manifest is inferred.
	return QualifiedImage{ID: receipt.OCIImageOCID, Architecture: receipt.Architecture, Role: input.Role,
		RuntimeManifestDigest: receipt.ImageSHA256}, expires, nil
}

func currentImageProofDeadline(now time.Time, wires ...[]byte) (time.Time, error) {
	var expires time.Time
	for _, wire := range wires {
		if len(wire) == 0 {
			continue
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return time.Time{}, err
		}
		if envelope.IssuedAt.After(now) || !now.Before(envelope.ExpiresAt) {
			return time.Time{}, errors.New("image or qualification authority is not currently valid")
		}
		if expires.IsZero() || envelope.ExpiresAt.Before(expires) {
			expires = envelope.ExpiresAt
		}
	}
	return expires, nil
}

func verifyImageEvidence(ctx context.Context, open func(context.Context, string) (io.ReadCloser, error), evidence release.ProductionGateEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reader, err := open(ctx, evidence.SHA256)
	if err != nil {
		return fmt.Errorf("read retained %s evidence: %w", evidence.Gate, err)
	}
	if reader == nil {
		return fmt.Errorf("retained %s evidence reader is missing", evidence.Gate)
	}
	digest := sha256.New()
	count, readErr := io.Copy(digest, io.LimitReader(reader, evidence.Bytes+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return fmt.Errorf("read retained %s evidence: %w", evidence.Gate, err)
	}
	if count != evidence.Bytes || hex.EncodeToString(digest.Sum(nil)) != evidence.SHA256 {
		return fmt.Errorf("retained %s evidence differs from the signed size or SHA-256", evidence.Gate)
	}
	return nil
}
