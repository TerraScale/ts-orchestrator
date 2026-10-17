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
	lastLive := c.now().UTC()
	cleanup, cancel := context.WithDeadline(context.Background(), c.prepared.approval.CleanupUntil)
	defer cancel()
	j, err := c.loadExisting(path)
	if err != nil {
		return err
	}
	// Every blocking interval starts with a known-live cutoff. When cancellation
	// first becomes visible, no transfer after that cutoff can establish ownership.
	checkpointCancellation := func() (bool, error) {
		observedAt := c.now().UTC()
		if ctx.Err() == nil {
			lastLive = observedAt
			return false, nil
		}
		if !j.RetentionEndedAt.IsZero() {
			return false, nil
		}
		j.RetentionEndedAt = lastLive
		return true, checkpoint(path, j)
	}
	if _, err := checkpointCancellation(); err != nil {
		return err
	}
	// Host cleanup cannot wait for a publication read or inherit image retention.
	hostErr := c.cleanupHosts(cleanup, path, &j)
	objectErr := c.cleanupObject(cleanup, path, &j)
	_, cancellationErr := checkpointCancellation()
	if err := errors.Join(hostErr, objectErr, cancellationErr); err != nil {
		return err
	}
	if len(j.RetainedReaderProof) == 0 {
		return c.cleanup(cleanup, path)
	}
	var lastErr error
	resourcesCleaned := false
	for {
		if _, err := checkpointCancellation(); err != nil {
			return err
		}
		if err := cleanup.Err(); err != nil {
			return errors.Join(lastErr, err)
		}
		observation, stop := context.WithTimeout(cleanup, 30*time.Second)
		transfer, observeErr := c.observeImageTransfer(observation, observer, j)
		stop()
		// A read overlapping cancellation cannot establish a later transfer cap.
		if canceled, err := checkpointCancellation(); err != nil {
			return err
		} else if canceled {
			continue
		}
		if observeErr == nil && transfer.manifestSHA256 != "" {
			j.ImageManifestSHA256 = transfer.manifestSHA256
			if err := checkpoint(path, j); err != nil {
				return err
			}
			c.imageTransfer = transfer
			return c.cleanup(cleanup, path)
		}
		lastErr = observeErr
		retained, err := c.retainImage(j)
		if err != nil {
			return err
		}
		if observeErr == nil && !retained {
			return c.cleanup(cleanup, path)
		}
		if retained && !resourcesCleaned {
			resourceErr := c.cleanup(cleanup, path)
			_, cancellationErr := checkpointCancellation()
			if err := errors.Join(resourceErr, cancellationErr); err != nil {
				return err
			}
			j, err = c.loadExisting(path)
			if err != nil {
				return err
			}
			resourcesCleaned = true
		}
		if _, err := checkpointCancellation(); err != nil {
			return err
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-cleanup.Done():
			timer.Stop()
			_, cancellationErr := checkpointCancellation()
			return errors.Join(lastErr, cleanup.Err(), cancellationErr)
		case <-timer.C:
		}
	}
}
