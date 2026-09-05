package nodeauthority

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const storageTransitionReceiptName = "storage-transition-pin-receipt.json"

// AcknowledgeStorageTransitionPlan signs and durably retains an acknowledgement
// of the existing private pin. The caller must be the trusted host receiver.
// It does not publish externally or acknowledge storage preparation. A retry
// returns the original bytes without invoking the signer, which may then be nil.
func (s *EpochStore) AcknowledgeStorageTransitionPlan(ctx context.Context, expectedDigest string, signer *security.CommandSignatureSigner) ([]byte, error) {
	return s.acknowledgeStorageTransitionPlan(ctx, expectedDigest, signer, 0, nil)
}

func (s *EpochStore) acknowledgeStorageTransitionPlan(ctx context.Context, expectedDigest string, signer *security.CommandSignatureSigner, uid uint32, afterRename func() error) ([]byte, error) {
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid || !authorityDigest(expectedDigest) {
		return nil, errors.New("nodeauthority: trusted transition acknowledgement required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return nil, errors.New("nodeauthority: transition receiver ownership closed")
	}
	directory := filepath.Dir(s.path)
	r, v, err := readStorageTransitionRecord(filepath.Join(directory, storageTransitionRecordName), uid)
	if err != nil {
		return nil, err
	}
	// Includes directory fsync, recovering an interrupted pin rename before
	// that pin can be represented as durable evidence outside this journal.
	if err = s.validateStorageTransitionResumeLocked(ctx, r, v, expectedDigest); err != nil {
		return nil, err
	}
	pinRaw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	wanted := controltransition.PinReceipt{Version: 1, Phase: "plan-pinned", PlanSHA256: v.Digest(), NodeID: s.node, Role: "destination", PinSHA256: controltransition.Digest(pinRaw), BootstrapGrantSHA256: r.BootstrapGrantSHA256, ManifestSHA256: r.ManifestSHA256, CommandID: r.CommandID, CommandSHA256: r.CommandSHA256, AuthorityID: r.Authority.AuthorityID, Epoch: r.Authority.Epoch, CandidateID: r.Authority.CandidateID, LeaseID: r.Authority.LeaseID, AdmittedAt: r.AdmittedAt}
	if s.node == p.Source.NodeID {
		wanted.Role = "source"
	}
	path := filepath.Join(directory, storageTransitionReceiptName)
	prior, err := readStorageTransitionReceipt(path, uid)
	if err == nil {
		receipt, err := controltransition.VerifyPinReceipt(v, prior)
		if err != nil {
			return nil, err
		}
		wanted.PublishedAt = receipt.PublishedAt
		if receipt != wanted || receipt.PublishedAt.After(time.Now()) {
			return nil, errors.New("nodeauthority: transition acknowledgement conflicts with private pin")
		}
		if err = syncEpochDirectory(directory); err != nil {
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = v.Check(time.Now()); err != nil {
			return nil, err
		}
		return prior, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	wanted.PublishedAt = time.Now().UTC()
	raw, err := controltransition.SignPinReceipt(signer, v, wanted)
	if err != nil {
		return nil, err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return v.Check(time.Now())
	}
	if err = writeStorageTransitionBytes(path, raw, check, afterRename); err != nil {
		return nil, err
	}
	return raw, nil
}

func readStorageTransitionReceipt(path string, uid uint32) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uid || st.Nlink != 1 || info.Size() > controltransition.PinReceiptMaximumBytes {
		return nil, errors.New("nodeauthority: unsafe transition acknowledgement")
	}
	raw, err := io.ReadAll(io.LimitReader(f, controltransition.PinReceiptMaximumBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > controltransition.PinReceiptMaximumBytes {
		return nil, errors.New("nodeauthority: oversized transition acknowledgement")
	}
	return raw, nil
}
