package nodeauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

const CandidatePreparationDirectory = "/var/lib/terrascale/host-admission/control-candidate"
const candidateRecordName = "candidate-preparation.json"

type CandidatePreparationReceipt struct {
	Phase                string    `json:"phase"`
	TransitionID         string    `json:"transitionId"`
	NodeID               string    `json:"nodeId"`
	GrantSHA256          string    `json:"grantSha256"`
	ManifestSHA256       string    `json:"manifestSha256"`
	BootstrapGrantSHA256 string    `json:"bootstrapGrantSha256"`
	ConfigSHA256         string    `json:"configSha256"`
	AdmittedAt           time.Time `json:"admittedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
}
type candidatePreparationRecord struct {
	Version     int                         `json:"version"`
	PublicKey   []byte                      `json:"publicKey"`
	SignedGrant []byte                      `json:"signedGrant"`
	Config      transitiongrant.Config      `json:"config"`
	Receipt     CandidatePreparationReceipt `json:"receipt"`
}

func candidateConfigDigest(c transitiongrant.Config) string {
	raw, _ := json.Marshal(c)
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}
func validateCandidateRecord(r candidatePreparationRecord, now time.Time) error {
	v, e := transitiongrant.VerifyGrant(r.PublicKey, r.SignedGrant)
	if e != nil {
		return e
	}
	p := r.Receipt
	if r.Version != 1 || p.Phase != "admitted" || p.TransitionID != r.Config.TransitionID || p.NodeID != r.Config.NodeID || p.GrantSHA256 != v.Digest || p.ConfigSHA256 != candidateConfigDigest(r.Config) || p.AdmittedAt.IsZero() || p.AdmittedAt.Before(v.Grant.IssuedAt) || !p.AdmittedAt.Before(v.Grant.ExpiresAt) || !p.ExpiresAt.Equal(v.Grant.ExpiresAt) {
		return errors.New("nodeauthority: candidate preparation evidence differs")
	}
	return v.CheckCandidate(now, r.Config, p.BootstrapGrantSHA256, p.ManifestSHA256)
}

// AdmitCandidatePreparation pins one separately signed preparation grant under
// existing host ownership. The caller supplies the bootstrap owner's key only
// after verifying the original bootstrap proof. The pinned initial manifest
// and grant must already match the ordinary bootstrap admission.
func (s *EpochStore) AdmitCandidatePreparation(ctx context.Context, public, signed []byte, c transitiongrant.Config, bootstrapDigest, manifestDigest string) (CandidatePreparationReceipt, error) {
	return s.admitCandidatePreparation(ctx, public, signed, c, bootstrapDigest, manifestDigest, CandidatePreparationDirectory, 0)
}
func (s *EpochStore) admitCandidatePreparation(ctx context.Context, public, signed []byte, c transitiongrant.Config, bootstrapDigest, manifestDigest, directory string, uid uint32) (CandidatePreparationReceipt, error) {
	var zero CandidatePreparationReceipt
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid {
		return zero, errors.New("nodeauthority: candidate admission requires trusted host writer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || s.node != c.NodeID {
		return zero, errors.New("nodeauthority: candidate host ownership differs")
	}
	floor, e := s.load()
	if e != nil {
		return zero, e
	}
	if floor.Epoch != 0 {
		return zero, errors.New("nodeauthority: ordinary runtime permanently retired candidate preparation")
	}
	a, found, e := s.loadManifestAdmission()
	if e != nil {
		return zero, e
	}
	if !found || a.GrantSHA256 != bootstrapDigest || a.ManifestSHA256 != manifestDigest || a.PreviousSHA256 != "" {
		return zero, errors.New("nodeauthority: candidate lacks exact initial manifest admission")
	}
	verified, e := transitiongrant.VerifyGrant(public, signed)
	if e != nil {
		return zero, e
	}
	now := time.Now().UTC()
	if e = verified.CheckCandidate(now, c, bootstrapDigest, manifestDigest); e != nil {
		return zero, e
	}
	r := candidatePreparationRecord{Version: 1, PublicKey: append([]byte(nil), public...), SignedGrant: append([]byte(nil), signed...), Config: c, Receipt: CandidatePreparationReceipt{Phase: "admitted", TransitionID: c.TransitionID, NodeID: c.NodeID, GrantSHA256: verified.Digest, ManifestSHA256: manifestDigest, BootstrapGrantSHA256: bootstrapDigest, ConfigSHA256: candidateConfigDigest(c), AdmittedAt: now, ExpiresAt: verified.Grant.ExpiresAt}}
	private := filepath.Join(filepath.Dir(s.path), candidateRecordName)
	prior, e := readCandidateRecord(private, 0600, uid)
	if e == nil {
		if validateCandidateRecord(prior, now) != nil || prior.Config != c || !bytes.Equal(prior.PublicKey, public) || !bytes.Equal(prior.SignedGrant, signed) || prior.Receipt.ManifestSHA256 != manifestDigest || prior.Receipt.BootstrapGrantSHA256 != bootstrapDigest {
			return zero, errors.New("nodeauthority: conflicting candidate preparation")
		}
		r = prior
	} else if !os.IsNotExist(e) {
		return zero, e
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	if e = writeCandidateRecord(private, r, 0600); e != nil {
		return zero, e
	}
	if e = prepareCandidatePublication(directory, uid); e != nil {
		return zero, e
	}
	published := filepath.Join(directory, "preparation.json")
	if previous, readErr := readCandidateRecord(published, 0644, uid); readErr == nil {
		left, _ := json.Marshal(previous)
		right, _ := json.Marshal(r)
		if !bytes.Equal(left, right) {
			return zero, errors.New("nodeauthority: conflicting candidate publication")
		}
	} else if !os.IsNotExist(readErr) {
		return zero, readErr
	}
	if e = writeCandidateRecord(published, r, 0644); e != nil {
		return zero, e
	}
	return r.Receipt, ctx.Err()
}

// ResumeCandidatePreparation authorizes only an already pinned preparation.
// It does not re-admit bootstrap or accept a caller-supplied replacement grant.
func (s *EpochStore) ResumeCandidatePreparation(ctx context.Context, c transitiongrant.Config, bootstrapDigest, manifestDigest string) (CandidatePreparationReceipt, error) {
	if s == nil {
		return CandidatePreparationReceipt{}, errors.New("nodeauthority: candidate receiver required")
	}
	r, e := readCandidateRecord(filepath.Join(filepath.Dir(s.path), candidateRecordName), 0600, 0)
	if e != nil {
		return CandidatePreparationReceipt{}, e
	}
	return s.AdmitCandidatePreparation(ctx, r.PublicKey, r.SignedGrant, c, bootstrapDigest, manifestDigest)
}

// ValidatePublishedPreparation is the service launch/runtime gate. The fixed
// root-owned publication supplies trust; configuration key paths never do.
func ValidatePublishedPreparation(ctx context.Context, c transitiongrant.Config) (CandidatePreparationReceipt, error) {
	return validatePublishedPreparation(ctx, c, CandidatePreparationDirectory, 0)
}
func validatePublishedPreparation(ctx context.Context, c transitiongrant.Config, directory string, uid uint32) (CandidatePreparationReceipt, error) {
	if ctx == nil {
		return CandidatePreparationReceipt{}, errors.New("nodeauthority: candidate context required")
	}
	if e := ctx.Err(); e != nil {
		return CandidatePreparationReceipt{}, e
	}
	if e := checkCandidateParents(directory, uid); e != nil {
		return CandidatePreparationReceipt{}, e
	}
	r, e := readCandidateRecord(filepath.Join(directory, "preparation.json"), 0644, uid)
	if e != nil {
		return CandidatePreparationReceipt{}, e
	}
	if r.Config != c {
		return CandidatePreparationReceipt{}, errors.New("nodeauthority: published candidate configuration differs")
	}
	if e = validateCandidateRecord(r, time.Now()); e != nil {
		return CandidatePreparationReceipt{}, e
	}
	return r.Receipt, nil
}
func checkCandidateParents(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("nodeauthority: invalid candidate path")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (st.Uid != 0 && st.Uid != uid) || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return errors.New("nodeauthority: unsafe candidate ancestry")
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
func prepareCandidatePublication(directory string, uid uint32) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("nodeauthority: invalid candidate directory")
	}
	parent := filepath.Dir(directory)
	if _, e := os.Lstat(parent); os.IsNotExist(e) {
		if e = prepareCandidatePublication(parent, uid); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e := checkCandidateParents(parent, uid); e != nil {
		return e
	}
	if e := os.Mkdir(directory, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	if e := checkCandidateParents(directory, uid); e != nil {
		return e
	}
	info, e := os.Stat(directory)
	if e != nil {
		return e
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != uid || info.Mode().Perm() != 0755 {
		return errors.New("nodeauthority: candidate directory ownership differs")
	}
	return syncEpochDirectory(parent)
}
func readCandidateRecord(path string, mode os.FileMode, uid uint32) (candidatePreparationRecord, error) {
	var r candidatePreparationRecord
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return r, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return r, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || st.Uid != uid || st.Nlink != 1 || info.Size() > 4*transitiongrant.MaximumBytes {
		return r, errors.New("nodeauthority: unsafe candidate preparation record")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4*transitiongrant.MaximumBytes+1))
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(&struct{}{}) != io.EOF {
		return r, errors.New("nodeauthority: invalid candidate record")
	}
	encoded, _ := json.Marshal(r)
	if !bytes.Equal(raw, encoded) {
		return r, errors.New("nodeauthority: noncanonical candidate record")
	}
	return r, nil
}
func writeCandidateRecord(path string, r candidatePreparationRecord, mode os.FileMode) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".candidate-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncEpochDirectory(filepath.Dir(path))
}

// Called under the epoch mutex before accepting ordinary authority. Removing
// publication first makes an interrupted floor write fail closed for the inert
// preparer; a still-zero floor can resume the same pinned preparation later.
func (s *EpochStore) retireCandidatePreparationLocked() error {
	r, e := readCandidateRecord(filepath.Join(filepath.Dir(s.path), candidateRecordName), 0600, uint32(os.Geteuid()))
	if os.IsNotExist(e) {
		if _, publicErr := os.Lstat(filepath.Join(CandidatePreparationDirectory, "preparation.json")); !os.IsNotExist(publicErr) {
			return errors.New("nodeauthority: candidate publication lacks private admission")
		}
		return nil
	}
	if e != nil {
		return e
	}
	if r.Config.NodeID != s.node {
		return errors.New("nodeauthority: candidate retirement host differs")
	}
	path := filepath.Join(CandidatePreparationDirectory, "preparation.json")
	current, e := readCandidateRecord(path, 0644, 0)
	if os.IsNotExist(e) {
		if _, err := os.Stat(CandidatePreparationDirectory); err == nil {
			return syncEpochDirectory(CandidatePreparationDirectory)
		}
		return nil
	}
	if e != nil {
		return e
	}
	if current.Receipt.GrantSHA256 != r.Receipt.GrantSHA256 || current.Config != r.Config {
		return errors.New("nodeauthority: candidate retirement publication differs")
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	return syncEpochDirectory(CandidatePreparationDirectory)
}
