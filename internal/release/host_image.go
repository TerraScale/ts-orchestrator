package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// HostImageQualification contains signed wires and independently pinned launch facts.
// RoleProduction qualifies container or function isolation on these exact disk bytes;
// an orchestrator image proof alone authorizes only a manager host.
type HostImageQualification struct {
	Receipt, Delegation []byte
	Expected            ImageExpectation
	Role                string
	RoleProduction      *ProductionProof
}

// VerifyHostImageCurrent verifies the exact disk and retained evidence for a manager or isolated worker.
func VerifyHostImageCurrent(ctx context.Context, input HostImageQualification, roots trust.Keyring,
	openEvidence func(context.Context, string) (io.ReadCloser, error), now time.Time,
) (image VerifiedImage, expires time.Time, err error) {
	defer func() {
		if err != nil {
			image, expires = VerifiedImage{}, time.Time{}
		}
	}()
	if input.Expected.OCIImageOCID == "" || input.Expected.Architecture == "" || now.IsZero() || openEvidence == nil {
		return image, expires, errors.New("exact image, native architecture, current time and retained evidence reader are required")
	}
	switch input.Role {
	case "manager", "container", "wasm":
	default:
		return image, expires, fmt.Errorf("unknown host image role %q", input.Role)
	}
	verified, err := VerifyImageCurrent(input.Receipt, input.Delegation, roots, input.Expected, now)
	if err != nil {
		return image, expires, err
	}
	receipt := verified.Receipt()
	expires, err = currentImageProofDeadline(now, input.Receipt, input.Delegation)
	if err != nil {
		return image, expires, err
	}
	candidate := ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: input.Expected.Environment,
		Runtime: ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}
	proofs := []ProductionProof{*receipt.Production}
	if input.Role != "manager" {
		if input.RoleProduction == nil {
			return image, expires, fmt.Errorf("no independent %s worker qualification for the final disk", input.Role)
		}
		proofs = append(proofs, *input.RoleProduction)
	}
	for index, proof := range proofs {
		if index > 0 {
			candidate.Role = input.Role
		}
		deadline, err := VerifyRetainedProductionCurrent(ctx, proof, roots, candidate, openEvidence, now)
		if err != nil {
			return image, expires, err
		}
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	if err := ctx.Err(); err != nil {
		return image, expires, err
	}
	return verified, expires, nil
}

// VerifyRetainedProductionCurrent verifies current proof authority and every signed evidence object.
func VerifyRetainedProductionCurrent(ctx context.Context, proof ProductionProof, roots trust.Keyring,
	expected ProductionExpectation, openEvidence func(context.Context, string) (io.ReadCloser, error), now time.Time,
) (time.Time, error) {
	if openEvidence == nil {
		return time.Time{}, errors.New("retained evidence reader is required")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	qualification, err := VerifyProductionCurrent(proof.Qualification, proof.Delegation, roots, expected, now)
	if err != nil {
		return time.Time{}, err
	}
	deadline, err := currentImageProofDeadline(now, proof.Qualification, proof.Delegation)
	if err != nil {
		return time.Time{}, err
	}
	for _, evidence := range qualification.Evidence {
		if err := verifyImageEvidence(ctx, openEvidence, evidence, expected); err != nil {
			return time.Time{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return deadline, nil
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

func verifyImageEvidence(ctx context.Context, open func(context.Context, string) (io.ReadCloser, error), evidence ProductionGateEvidence, expected ProductionExpectation) error {
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
	if err := errors.Join(VerifyProductionEvidence(ctx, reader, evidence, expected), reader.Close()); err != nil {
		return fmt.Errorf("read retained %s evidence: %w", evidence.Gate, err)
	}
	return nil
}
