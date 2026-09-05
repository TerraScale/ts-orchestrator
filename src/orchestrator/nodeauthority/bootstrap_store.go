package nodeauthority

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type manifestAdmission struct {
	Version        int    `json:"version"`
	NodeID         string `json:"nodeId"`
	GrantSHA256    string `json:"grantSha256"`
	ManifestSHA256 string `json:"manifestSha256"`
	PreviousSHA256 string `json:"previousSha256"`
}

func authorityDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
func (s *EpochStore) loadManifestAdmission() (manifestAdmission, bool, error) {
	var admission manifestAdmission
	file, err := os.OpenFile(filepath.Join(filepath.Dir(s.path), "manifest-admission.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return admission, false, nil
	}
	if err != nil {
		return admission, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return admission, false, errors.New("nodeauthority: unsafe manifest admission file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return admission, false, errors.New("nodeauthority: manifest admission ownership differs")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return admission, false, err
	}
	if _, err = decodeObject(data, "version", "nodeId", "grantSha256", "manifestSha256", "previousSha256"); err != nil {
		return admission, false, err
	}
	if json.Unmarshal(data, &admission) != nil || admission.Version != 1 || admission.NodeID != s.node || !authorityDigest(admission.ManifestSHA256) || admission.PreviousSHA256 != "" && !authorityDigest(admission.PreviousSHA256) || admission.GrantSHA256 != "" && !authorityDigest(admission.GrantSHA256) {
		return admission, false, errors.New("nodeauthority: corrupt manifest admission")
	}
	return admission, true, nil
}
func (s *EpochStore) writeManifestAdmission(admission manifestAdmission) error {
	data, err := json.Marshal(admission)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	file, err := os.CreateTemp(directory, ".manifest-admission-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filepath.Join(directory, "manifest-admission.json")); err != nil {
		return err
	}
	return syncEpochDirectory(directory)
}

// AdmitBootstrap pins one immutable initial grant and manifest. A real runtime
// epoch permanently closes this path. Call while holding the receiver's command
// mutex; failed persistence never permits the subsequent mutation.
func (s *EpochStore) AdmitBootstrap(grantDigest, manifestDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || !authorityDigest(grantDigest) || !authorityDigest(manifestDigest) {
		return errors.New("nodeauthority: invalid bootstrap admission")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if floor.Epoch != 0 {
		return errors.New("nodeauthority: bootstrap authority is permanently retired")
	}
	admission, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	if found {
		if admission.GrantSHA256 != grantDigest || admission.ManifestSHA256 != manifestDigest {
			return errors.New("nodeauthority: bootstrap grant conflicts with durable admission")
		}
		return syncEpochDirectory(filepath.Dir(s.path))
	}
	return s.writeManifestAdmission(manifestAdmission{Version: 1, NodeID: s.node, GrantSHA256: grantDigest, ManifestSHA256: manifestDigest})
}

// AdmittedManifest checks the full current desired-state digest. The returned
// runtime flag means a real regional epoch has been durably accepted. Repeating
// directory fsync covers a prior rename whose directory sync failed.
func (s *EpochStore) AdmittedManifest(digest string) (runtime bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || !authorityDigest(digest) {
		return false, errors.New("nodeauthority: invalid manifest admission read")
	}
	admission, found, err := s.loadManifestAdmission()
	if err != nil {
		return false, err
	}
	if !found || admission.ManifestSHA256 != digest && admission.PreviousSHA256 != digest {
		return false, errors.New("nodeauthority: desired manifest has no matching signed admission")
	}
	floor, err := s.load()
	if err != nil {
		return false, err
	}
	if err = syncEpochDirectory(filepath.Dir(s.path)); err != nil {
		return false, err
	}
	return floor.Epoch > 0, nil
}

// AdmitRuntimeManifest records only a manifest supplied by a freshly verified
// regional command. Its epoch must already be persisted through Admit. The
// caller writes the manifest and journals completion under the same mutex.
func (s *EpochStore) AdmitRuntimeManifest(digest, currentDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || !authorityDigest(digest) || !authorityDigest(currentDigest) {
		return errors.New("nodeauthority: invalid runtime manifest admission")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if floor.Epoch <= 0 {
		return errors.New("nodeauthority: runtime manifest lacks admitted regional authority")
	}
	admission, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	if found && currentDigest != admission.ManifestSHA256 && currentDigest != admission.PreviousSHA256 {
		return errors.New("nodeauthority: runtime manifest current digest was not admitted")
	}
	admission.PreviousSHA256 = ""
	if found && currentDigest != digest {
		admission.PreviousSHA256 = currentDigest
	}
	admission.Version = 1
	admission.NodeID = s.node
	admission.ManifestSHA256 = digest
	return s.writeManifestAdmission(admission)
}

// CommitRuntimeManifest drops the previous admission only after the canonical
// new manifest was durably written. A crash between these two files therefore
// leaves either admitted version restartable, and a fresh command can resume.
func (s *EpochStore) CommitRuntimeManifest(digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return errors.New("nodeauthority: receiver is closed")
	}
	admission, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	if !found || admission.ManifestSHA256 != digest {
		return errors.New("nodeauthority: runtime manifest commit differs")
	}
	admission.PreviousSHA256 = ""
	return s.writeManifestAdmission(admission)
}
