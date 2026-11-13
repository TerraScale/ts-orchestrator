package releasepush

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type releaseID struct {
	SHA    string `json:"sha"`
	SHA256 string `json:"sha256"`
}

type fileStamp struct {
	size  int64
	mtime time.Time
	inode uint64
}

type cachedIdentity struct {
	stamp fileStamp
	id    releaseID
}

var identities sync.Map

func buildRevision(info *debug.BuildInfo) string {
	revision, modified := "unknown", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}

func binaryIdentity(path string) (releaseID, error) {
	file, err := os.Open(path)
	if err != nil {
		return releaseID{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return releaseID{}, err
	}
	stamp := fileStamp{size: info.Size(), mtime: info.ModTime()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp.inode = sys.Ino
	}
	if cached, ok := identities.Load(path); ok && cached.(cachedIdentity).stamp == stamp {
		return cached.(cachedIdentity).id, nil
	}
	build, err := buildinfo.Read(file)
	if err != nil {
		return releaseID{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, info.Size())); err != nil {
		return releaseID{}, err
	}
	id := releaseID{buildRevision(build), hex.EncodeToString(hash.Sum(nil))}
	identities.Store(path, cachedIdentity{stamp, id})
	return id, nil
}

func readRecord(path string, into any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, json.Unmarshal(data, into)
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeState(path, data)
}

func writeState(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".release-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func removeDurable(path string) error {
	if err := removeIfExists(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func archiveDamaged(path string) error {
	for n := range 1000 {
		archive := path + ".damaged"
		if n > 0 {
			archive += "." + strconv.Itoa(n)
		}
		err := os.Link(path, archive)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	return errors.New("no free name to archive the damaged release trial")
}

func (h *Handler) unstage() error {
	return errors.Join(removeIfExists(stagedPrevious(h.Binary)), removeDurable(stagedTrial(h.TrialFile)))
}

func (h *Handler) stage(candidate releaseID, run string) error {
	installed, err := binaryIdentity(h.Binary)
	if err != nil {
		return err
	}
	record := trial{SHA: candidate.SHA, SHA256: candidate.SHA256, RunID: run, Installed: time.Now(), RecoverAfter: h.recoverAfter, Previous: &installed}
	if err := writeJSON(stagedTrial(h.TrialFile), record); err != nil {
		return err
	}
	if err := writeState(h.RunIDFile, []byte(run)); err != nil {
		return err
	}
	previous := stagedPrevious(h.Binary)
	err = removeIfExists(previous)
	if err == nil {
		err = os.Link(h.Binary, previous)
	}
	if err == nil {
		err = syncDirectory(filepath.Dir(h.Binary))
	}
	if errors.Is(err, os.ErrPermission) {
		err = fmt.Errorf("%w (an immutable binary refuses replacement: run `chattr -i %s %s.prev` on the host)", err, h.Binary, h.Binary)
	}
	return err
}
