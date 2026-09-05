package nodeauthority

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type epochFloor struct {
	Version     int    `json:"version"`
	NodeID      string `json:"nodeId"`
	AuthorityID string `json:"authorityId"`
	Epoch       int64  `json:"epoch"`
	CandidateID string `json:"candidateId"`
	LeaseID     string `json:"leaseId"`
}

// EpochStore retains the highest accepted authority even when command receipts
// are replayed. The caller holds its command execution lock around Admit and
// the subsequent journal intent, so an older request cannot slip past a newer one.
type EpochStore struct {
	path, node string
	mu         sync.Mutex
	ownerLock  *os.File
}

func NewEpochStore(directory, node string) (*EpochStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || node == "" {
		return nil, errors.New("nodeauthority: invalid epoch store scope")
	}
	for path := directory; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("nodeauthority: epoch parent path is unsafe")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("nodeauthority: epoch directory must be a private regular directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("nodeauthority: epoch directory ownership differs")
	}
	lock, err := os.OpenFile(filepath.Join(directory, "authority-owner.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("nodeauthority: another receiver owns this host journal")
	}
	s := &EpochStore{path: filepath.Join(directory, "authority-epoch.json"), node: node, ownerLock: lock}
	if _, err := s.load(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *EpochStore) load() (epochFloor, error) {
	file, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return epochFloor{}, nil
	}
	if err != nil {
		return epochFloor{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return epochFloor{}, errors.New("nodeauthority: invalid epoch file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return epochFloor{}, errors.New("nodeauthority: epoch file ownership or link count differs")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return epochFloor{}, err
	}
	if _, err := decodeObject(data, "version", "nodeId", "authorityId", "epoch", "candidateId", "leaseId"); err != nil {
		return epochFloor{}, err
	}
	var floor epochFloor
	if json.Unmarshal(data, &floor) != nil || floor.Version != 1 || floor.NodeID != s.node || floor.AuthorityID == "" || floor.Epoch <= 0 || floor.CandidateID == "" || floor.LeaseID == "" {
		return epochFloor{}, errors.New("nodeauthority: invalid persisted authority epoch")
	}
	return floor, nil
}
func (s *EpochStore) Admit(command CommandAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return errors.New("nodeauthority: receiver ownership was closed")
	}
	if command.NodeID != s.node || command.AuthorityID == "" || command.Epoch <= 0 || command.CandidateID == "" || command.LeaseID == "" {
		return errors.New("nodeauthority: invalid epoch authorization")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if floor.Epoch > command.Epoch || (floor.Epoch != 0 && floor.AuthorityID != command.AuthorityID) || (floor.Epoch == command.Epoch && (floor.CandidateID != command.CandidateID || floor.LeaseID != command.LeaseID)) {
		return errors.New("nodeauthority: stale or conflicting authority epoch")
	}
	if err := s.retireCandidatePreparationLocked(); err != nil {
		return err
	}
	if floor.Epoch == command.Epoch {
		return syncEpochDirectory(filepath.Dir(s.path))
	}
	floor = epochFloor{Version: 1, NodeID: command.NodeID, AuthorityID: command.AuthorityID, Epoch: command.Epoch, CandidateID: command.CandidateID, LeaseID: command.LeaseID}
	data, err := json.Marshal(floor)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".authority-epoch-")
	if err != nil {
		return err
	}
	staged := file.Name()
	defer os.Remove(staged)
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
	if err = os.Rename(staged, s.path); err != nil {
		return err
	}
	return syncEpochDirectory(filepath.Dir(s.path))
}
func syncEpochDirectory(path string) error {
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *EpochStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil {
		return nil
	}
	err := s.ownerLock.Close()
	s.ownerLock = nil
	return err
}
