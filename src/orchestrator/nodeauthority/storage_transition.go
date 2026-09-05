package nodeauthority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

const storageTransitionRecordName = "storage-transition-plan.json"
const storageTransitionMaximumBytes = 2 * controltransition.MaximumBytes

type storageTransitionRecord struct {
	Version              int        `json:"version"`
	NodeID               string     `json:"nodeId"`
	PublicKey            []byte     `json:"publicKey"`
	SignedPlan           []byte     `json:"signedPlan"`
	PlanSHA256           string     `json:"planSha256"`
	BootstrapGrantSHA256 string     `json:"bootstrapGrantSha256"`
	ManifestSHA256       string     `json:"manifestSha256"`
	CommandID            string     `json:"commandId"`
	CommandSHA256        string     `json:"commandSha256"`
	Authority            epochFloor `json:"authority"`
	AdmittedAt           time.Time  `json:"admittedAt"`
}

// AdmitStorageTransitionPlan pins the owner's plan in the existing private
// receiver journal. The trusted caller must obtain public from the ORIGINAL
// verified bootstrap proof, never from transition-controlled configuration.
// A source pin additionally consumes an already authenticated live ApplyManifest
// command; destinations require their exact initial bootstrap admission.
// This records agreement only. It does not retire the source, apply a manifest,
// publish a preparation receipt, or authorize any storage/election mutation.
func (s *EpochStore) AdmitStorageTransitionPlan(ctx context.Context, public, signed []byte, command *CommandAuthorization) (controltransition.VerifiedPlan, error) {
	return s.admitStorageTransitionPlan(ctx, public, signed, command, 0, nil)
}

func (s *EpochStore) admitStorageTransitionPlan(ctx context.Context, public, signed []byte, command *CommandAuthorization, uid uint32, afterRename func() error) (controltransition.VerifiedPlan, error) {
	var zero controltransition.VerifiedPlan
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid {
		return zero, errors.New("nodeauthority: transition pin requires trusted host receiver")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return zero, errors.New("nodeauthority: transition receiver ownership closed")
	}
	v, err := controltransition.VerifyPlan(public, signed)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	if err = v.Check(now); err != nil {
		return zero, err
	}
	p, err := v.Plan()
	if err != nil {
		return zero, err
	}
	floor, err := s.load()
	if err != nil {
		return zero, err
	}
	a, found, err := s.loadManifestAdmission()
	if err != nil {
		return zero, err
	}
	if !found {
		return zero, errors.New("nodeauthority: transition host lacks manifest admission")
	}
	r := storageTransitionRecord{Version: 1, NodeID: s.node, PublicKey: bytes.Clone(public), SignedPlan: bytes.Clone(signed), PlanSHA256: v.Digest(), Authority: floor, AdmittedAt: now}
	if s.node == p.Source.NodeID {
		if command == nil || command.NodeID != s.node || command.BootstrapGrantSHA256 != "" || !command.ExpiresAt.After(now) || floor.Epoch <= 0 || floor.AuthorityID != "gru-regional" || command.AuthorityID != floor.AuthorityID || command.Epoch != floor.Epoch || command.CandidateID != floor.CandidateID || command.LeaseID != floor.LeaseID {
			return zero, errors.New("nodeauthority: source transition requires live admitted regional command")
		}
		handoff, e := hostmanifest.ParseApplyManifestCommand(command.Command)
		if e != nil {
			return zero, e
		}
		digest, e := hostmanifest.HostManifestSha256(handoff.Manifest)
		if e != nil {
			return zero, e
		}
		if handoff.ExpectedManifestSha256 != p.Source.InitialManifestSHA256 || digest != p.Source.CaptureManifestSHA256 || a.GrantSHA256 != p.Source.BootstrapGrantSHA256 || a.ManifestSHA256 != p.Source.InitialManifestSHA256 {
			return zero, errors.New("nodeauthority: source transition differs from manifest command or predecessor")
		}
		publication, published, e := s.readInitialR1Publication()
		if e != nil {
			return zero, e
		}
		i := publication.Identity
		if !published || !publication.Committed || i.Role != "seed" || i.NodeID != s.node || i.GrantSHA256 != p.Source.BootstrapGrantSHA256 || i.ManifestSHA256 != p.Source.InitialManifestSHA256 || i.LaunchSHA256 != p.Source.LaunchSHA256 || i.StoreScopeSHA256 != p.Source.StoreScopeSHA256 {
			return zero, errors.New("nodeauthority: source plan lacks original committed R1 publication")
		}
		guard, e := newInitialR1Guard(publication.Directory, i, uid)
		if e != nil {
			return zero, e
		}
		if e = guard.Check(ctx); e != nil {
			return zero, e
		}
		r.BootstrapGrantSHA256, r.ManifestSHA256 = p.Source.BootstrapGrantSHA256, p.Source.InitialManifestSHA256
		r.CommandID, r.CommandSHA256 = handoff.CommandId, controltransition.Digest(command.Command)
	} else {
		if command != nil || floor.Epoch != 0 || a.PreviousSHA256 != "" {
			return zero, errors.New("nodeauthority: destination transition requires initial local bootstrap")
		}
		for _, d := range p.Destinations {
			if d.NodeID == s.node {
				r.BootstrapGrantSHA256, r.ManifestSHA256 = d.BootstrapGrantSHA256, d.PreparedManifestSHA256
			}
		}
		if r.ManifestSHA256 == "" || a.GrantSHA256 != r.BootstrapGrantSHA256 || a.ManifestSHA256 != r.ManifestSHA256 {
			return zero, errors.New("nodeauthority: destination not admitted by transition plan")
		}
	}
	path := filepath.Join(filepath.Dir(s.path), storageTransitionRecordName)
	prior, priorVerified, e := readStorageTransitionRecord(path, uid)
	if e == nil {
		if prior.NodeID != s.node || prior.PlanSHA256 != r.PlanSHA256 || !bytes.Equal(prior.PublicKey, r.PublicKey) || prior.ManifestSHA256 != r.ManifestSHA256 || prior.BootstrapGrantSHA256 != r.BootstrapGrantSHA256 || prior.CommandID != r.CommandID || prior.CommandSHA256 != r.CommandSHA256 {
			return zero, errors.New("nodeauthority: conflicting immutable transition pin")
		}
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		if err = syncEpochDirectory(filepath.Dir(s.path)); err != nil {
			return zero, err
		}
		return priorVerified, nil
	}
	if !os.IsNotExist(e) {
		return zero, e
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.Check(time.Now()); err != nil {
			return err
		}
		if command != nil && !command.ExpiresAt.After(time.Now()) {
			return errors.New("nodeauthority: transition command expired before pin publication")
		}
		return nil
	}
	if err = writeStorageTransitionRecord(path, r, check, afterRename); err != nil {
		return zero, err
	}
	return v, nil
}

// ResumeStorageTransitionPlan reads only the pinned agreement. It neither
// re-admits bootstrap nor refreshes the original command lease. Callers must
// separately prove every phase's authority and predecessor effects.
func (s *EpochStore) ResumeStorageTransitionPlan(ctx context.Context, expectedDigest string) (controltransition.VerifiedPlan, error) {
	return s.resumeStorageTransitionPlan(ctx, expectedDigest, 0)
}

func (s *EpochStore) resumeStorageTransitionPlan(ctx context.Context, expectedDigest string, uid uint32) (controltransition.VerifiedPlan, error) {
	var zero controltransition.VerifiedPlan
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid || !authorityDigest(expectedDigest) {
		return zero, errors.New("nodeauthority: trusted transition resume required")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return zero, errors.New("nodeauthority: transition receiver ownership closed")
	}
	r, v, err := readStorageTransitionRecord(filepath.Join(filepath.Dir(s.path), storageTransitionRecordName), uid)
	if err != nil {
		return zero, err
	}
	if err := s.validateStorageTransitionResumeLocked(ctx, r, v, expectedDigest); err != nil {
		return zero, err
	}
	return v, nil
}

func (s *EpochStore) validateStorageTransitionResumeLocked(ctx context.Context, r storageTransitionRecord, v controltransition.VerifiedPlan, expectedDigest string) error {
	var err error
	if r.NodeID != s.node || v.Digest() != expectedDigest {
		return errors.New("nodeauthority: transition resume scope differs")
	}
	if err = v.Check(time.Now()); err != nil {
		return err
	}
	a, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	p, err := v.Plan()
	if err != nil {
		return err
	}
	allowedManifest := a.ManifestSHA256 == r.ManifestSHA256 || s.node == p.Source.NodeID && a.ManifestSHA256 == p.Source.CaptureManifestSHA256
	if !found || a.GrantSHA256 != r.BootstrapGrantSHA256 || !allowedManifest {
		return errors.New("nodeauthority: transition manifest admission changed")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if r.Authority.Epoch == 0 && floor.Epoch != 0 || r.Authority.Epoch > 0 && (floor.AuthorityID != r.Authority.AuthorityID || floor.Epoch < r.Authority.Epoch || floor.Epoch == r.Authority.Epoch && (floor.CandidateID != r.Authority.CandidateID || floor.LeaseID != r.Authority.LeaseID)) {
		return errors.New("nodeauthority: transition authority floor changed or regressed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = syncEpochDirectory(filepath.Dir(s.path)); err != nil {
		return err
	}
	if err = v.Check(time.Now()); err != nil {
		return err
	}
	return nil
}

func readStorageTransitionRecord(path string, uid uint32) (storageTransitionRecord, controltransition.VerifiedPlan, error) {
	var r storageTransitionRecord
	var zero controltransition.VerifiedPlan
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return r, zero, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return r, zero, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uid || st.Nlink != 1 || info.Size() > storageTransitionMaximumBytes {
		return r, zero, errors.New("nodeauthority: unsafe transition pin file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, storageTransitionMaximumBytes+1))
	if err != nil {
		return r, zero, err
	}
	if len(raw) > storageTransitionMaximumBytes || json.Unmarshal(raw, &r, json.RejectUnknownMembers(true)) != nil {
		return r, zero, errors.New("nodeauthority: malformed transition pin")
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, zero, errors.New("nodeauthority: noncanonical transition pin")
	}
	v, err := controltransition.VerifyPlan(r.PublicKey, r.SignedPlan)
	if err != nil {
		return r, zero, err
	}
	p, err := v.Plan()
	if err != nil {
		return r, zero, err
	}
	if r.Version != 1 || r.PlanSHA256 != v.Digest() || v.Check(r.AdmittedAt) != nil {
		return r, zero, errors.New("nodeauthority: transition pin binding differs")
	}
	if r.NodeID == p.Source.NodeID {
		if r.BootstrapGrantSHA256 != p.Source.BootstrapGrantSHA256 || r.ManifestSHA256 != p.Source.InitialManifestSHA256 || !validInitialR1Token(r.CommandID) || !authorityDigest(r.CommandSHA256) || r.Authority.Version != 1 || r.Authority.NodeID != r.NodeID || r.Authority.AuthorityID != "gru-regional" || r.Authority.Epoch <= 0 || !validInitialR1Token(r.Authority.CandidateID) || !validInitialR1Token(r.Authority.LeaseID) {
			return r, zero, errors.New("nodeauthority: source transition pin differs")
		}
	} else {
		found := false
		for _, d := range p.Destinations {
			if r.NodeID == d.NodeID && r.BootstrapGrantSHA256 == d.BootstrapGrantSHA256 && r.ManifestSHA256 == d.PreparedManifestSHA256 {
				found = true
			}
		}
		if !found || r.Authority != (epochFloor{}) || r.CommandID != "" || r.CommandSHA256 != "" {
			return r, zero, errors.New("nodeauthority: destination transition pin differs")
		}
	}
	return r, v, nil
}

func writeStorageTransitionRecord(path string, r storageTransitionRecord, check, afterRename func() error) error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > storageTransitionMaximumBytes {
		return errors.New("nodeauthority: transition pin exceeds bound")
	}
	return writeStorageTransitionBytes(path, raw, check, afterRename)
}

func writeStorageTransitionBytes(path string, raw []byte, check, afterRename func() error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".storage-transition-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = check(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if afterRename != nil {
		if err = afterRename(); err != nil {
			return err
		}
	}
	return syncEpochDirectory(filepath.Dir(path))
}
