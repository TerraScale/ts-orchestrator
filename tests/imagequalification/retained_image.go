package imagequalification

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
)

// retainImage never accepts a journal deadline in place of original authority.
// The same signed postlaunch refinement binds the exact tested SDK image ID.
func (c *cloud) retainImage(j journal) (bool, error) {
	if len(j.RetainedReaderProof) == 0 {
		return false, nil
	}
	a, p := c.prepared.approval, c.prepared
	if a.Purpose != qualification.RootCredentialBoundaryPurpose || qualification.ValidateDisposition(a.Purpose, a.ArtifactDisposition, a.ReaderIAMAuthority, a.ImageRetainUntil, a.ImageTransferUntil, a.CleanupUntil) != nil ||
		j.ImageDeleted || j.ImageID == "" || !validHash(j.RootGateSHA256) || j.RetainedAt.IsZero() || c.now().Before(j.RetainedAt) {
		return false, errors.New("retained image lacks original purpose, exact image or retained gate binding")
	}
	var proof hostadmission.Proof
	if protocol.DecodeStrict(j.RetainedReaderProof, &proof, hostadmission.MaxProofBytes) != nil || !bytes.Equal(proof.Preparation, p.principalWire) || !bytes.Equal(proof.Approval, p.approvalWire) || !bytes.Equal(proof.Delegation, p.delegationWire) {
		return false, errors.New("retained image refinement differs from original authority")
	}
	plan, err := hostadmission.VerifyReaderBinding(j.RetainedReaderProof, p.roots, j.RetainedAt)
	if err != nil {
		return false, err
	}
	for _, h := range plan.Hosts() {
		if h.ImageID != j.ImageID || j.Hosts[h.Name] != h.InstanceID {
			return false, errors.New("retained image differs from exact SDK host lineage")
		}
	}
	if !j.RetentionEndedAt.IsZero() {
		if j.RetentionEndedAt.Before(j.RetainedAt) || c.now().Before(j.RetentionEndedAt) {
			return false, errors.New("retention cleanup checkpoint is outside original interval")
		}
		return false, nil
	}
	return c.now().Before(a.ImageRetainUntil), nil
}

// superviseRetainedImage retains an active cleanup owner until the original
// deadline. Cancellation ends retention and uses independent cleanup authority.
// A typed root gate alone never relinquishes image ownership for promotion.
func (c *cloud) superviseRetainedImage(ctx context.Context, path string) error {
	j, err := c.load(path)
	if err != nil {
		return err
	}
	retained, err := c.retainImage(j)
	if err != nil {
		return err
	}
	if retained {
		timer := time.NewTimer(time.Until(c.prepared.approval.ImageRetainUntil))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			j.RetentionEndedAt = c.now().UTC()
			if err := checkpoint(path, j); err != nil {
				return err
			}
		case <-timer.C:
		}
	}
	cleanup, cancel := context.WithDeadline(context.Background(), c.prepared.approval.CleanupUntil)
	defer cancel()
	return c.cleanup(cleanup, path)
}
