package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// VerifyProductionEvidence checks bytes against authenticated gate metadata.
// The privileged gate additionally requires the exact native boundary observations.
func VerifyProductionEvidence(ctx context.Context, reader io.Reader, evidence ProductionGateEvidence, expected ProductionExpectation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if reader == nil || evidence.Bytes <= 0 || evidence.Bytes > MaxProductionEvidenceBytes || !digestPattern.MatchString(evidence.SHA256) {
		return fmt.Errorf("%w: retained %s evidence metadata", ErrProductionQualification, evidence.Gate)
	}
	digest := sha256.New()
	var body bytes.Buffer
	var destination io.Writer = digest
	if evidence.Gate == RootCredentialBoundaryGate {
		destination = io.MultiWriter(digest, &body)
	}
	count, err := io.Copy(destination, io.LimitReader(reader, evidence.Bytes+1))
	if err != nil {
		return fmt.Errorf("read retained %s evidence: %w", evidence.Gate, err)
	}
	if count != evidence.Bytes || hex.EncodeToString(digest.Sum(nil)) != evidence.SHA256 {
		return fmt.Errorf("%w: retained %s evidence differs from the signed size or SHA-256", ErrProductionQualification, evidence.Gate)
	}
	if evidence.Gate == RootCredentialBoundaryGate {
		var boundary RootCredentialBoundaryEvidence
		if err := protocol.DecodeStrict(body.Bytes(), &boundary, MaxProductionEvidenceBytes); err != nil {
			return fmt.Errorf("%w: root credential boundary evidence: %w", ErrProductionQualification, err)
		}
		if err := boundary.Validate(expected); err != nil {
			return err
		}
		if !boundary.CompletedAt.Equal(evidence.CompletedAt) {
			return fmt.Errorf("%w: root credential boundary completion time", ErrProductionQualification)
		}
	}
	return ctx.Err()
}
