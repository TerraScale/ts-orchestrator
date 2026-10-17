package imagequalification

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
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
		j.ImageID == "" || !validHash(j.RootGateSHA256) || j.RetainedAt.IsZero() || c.now().Before(j.RetainedAt) {
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
	return !j.ImageDeleted && c.now().Before(a.ImageRetainUntil), nil
}

// superviseRetainedImage retains an active cleanup owner until the original
// deadline. Cancellation ends retention and uses independent cleanup authority.
// A typed root gate alone never relinquishes image ownership for promotion.
func (c *cloud) superviseRetainedImage(ctx context.Context, path string, observer *ociclient.Factory) error {
	cleanup, cancel := context.WithDeadline(context.Background(), c.prepared.approval.CleanupUntil)
	defer cancel()
	j, err := c.load(path)
	if err != nil {
		return err
	}
	// Host cleanup cannot wait for a publication read or inherit image retention.
	hostErr := c.cleanupHosts(cleanup, path, &j)
	objectErr := c.cleanupObject(cleanup, path, &j)
	if err := errors.Join(hostErr, objectErr); err != nil {
		return err
	}
	if len(j.RetainedReaderProof) == 0 {
		return c.cleanup(cleanup, path)
	}
	var lastErr error
	resourcesCleaned := false
	for {
		if err := cleanup.Err(); err != nil {
			return errors.Join(lastErr, err)
		}
		observation, stop := context.WithTimeout(cleanup, 30*time.Second)
		transfer, observeErr := c.observeImageTransfer(observation, observer, j)
		stop()
		if observeErr == nil && transfer.manifestSHA256 != "" {
			j.ImageManifestSHA256 = transfer.manifestSHA256
			if err := checkpoint(path, j); err != nil {
				return err
			}
			c.imageTransfer = transfer
			return c.cleanup(cleanup, path)
		}
		lastErr = observeErr
		// Cancellation permits early cleanup, but an earlier completed transfer must
		// still be authenticated before any exact-image deletion.
		if ctx.Err() != nil && j.RetentionEndedAt.IsZero() {
			j.RetentionEndedAt = c.now().UTC()
			if err := checkpoint(path, j); err != nil {
				return err
			}
		}
		retained, err := c.retainImage(j)
		if err != nil {
			return err
		}
		if observeErr == nil && !retained {
			return c.cleanup(cleanup, path)
		}
		if retained && !resourcesCleaned {
			if err := c.cleanup(cleanup, path); err != nil {
				return err
			}
			j, err = c.load(path)
			if err != nil {
				return err
			}
			resourcesCleaned = true
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-cleanup.Done():
			timer.Stop()
			return errors.Join(lastErr, cleanup.Err())
		case <-timer.C:
		}
	}
}
