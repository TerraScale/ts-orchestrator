package releasepush

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
)

type preparedRelease struct {
	Run      string `json:"run"`
	Trial    string `json:"trial"`
	Rollback string `json:"rollback"`
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func cleanupRelease(path string) {
	if err := os.RemoveAll(path); err != nil {
		slog.Warn("release preparation cleanup failed", "error", err)
	}
}

func prepareRelease(h *Handler, next, sha, run string) (path string, err error) {
	path = h.Binary + ".release"
	if _, err := os.Stat(path); err == nil {
		return "", errors.New("previous release state publication incomplete")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			cleanupRelease(path)
		}
	}()
	if err = os.Link(h.Binary, filepath.Join(path, "previous")); err != nil {
		return path, err
	}
	if err = os.Link(next, filepath.Join(path, "candidate")); err != nil {
		return path, err
	}
	if err = writeState(filepath.Join(path, "run"), []byte(run)); err != nil {
		return path, err
	}
	if err = writeJSON(filepath.Join(path, "trial"), trial{SHA: sha, RunID: run}); err != nil {
		return path, err
	}
	if err = writeJSON(filepath.Join(path, "manifest"), preparedRelease{h.RunIDFile, h.TrialFile, h.RollbackFile}); err != nil {
		return path, err
	}
	err = syncDirectory(filepath.Dir(path))
	return path, err
}

func publishFile(source, target string) error {
	next := target + ".publish"
	if err := removeIfExists(next); err != nil {
		return err
	}
	defer os.Remove(next)
	if err := os.Link(source, next); err != nil {
		return err
	}
	if err := os.Rename(next, target); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(target))
}

func releaseState(binary, run, trialPath, rollback string) (string, string, string, string) {
	path := binary + ".release"
	candidate, err := os.Stat(filepath.Join(path, "candidate"))
	if errors.Is(err, os.ErrNotExist) {
		return run, trialPath, rollback, binary + ".prev"
	}
	installed, installedErr := os.Stat(binary)
	if err != nil || installedErr != nil {
		stateWarning(path, "release state recovery unavailable")
		return run, trialPath, rollback, binary + ".prev"
	}
	if !os.SameFile(candidate, installed) {
		cleanupRelease(path)
		return run, trialPath, rollback, binary + ".prev"
	}
	data, err := os.ReadFile(filepath.Join(path, "manifest"))
	var record preparedRelease
	if err == nil {
		err = json.Unmarshal(data, &record)
	}
	if err == nil && (record.Run == "" || record.Trial == "" || record.Rollback == "") {
		err = errors.New("incomplete release manifest")
	}
	if err == nil {
		return publishRelease(binary, record)
	}
	if err != nil {
		slog.Warn("release installed; state publication incomplete; prepared state retained", "error", err)
		return filepath.Join(path, "run"), filepath.Join(path, "trial"), filepath.Join(path, "rollback"), filepath.Join(path, "previous")
	}
	return run, trialPath, rollback, binary + ".prev"
}

func publishRelease(binary string, record preparedRelease) (string, string, string, string) {
	path := binary + ".release"
	err := errors.Join(publishFile(filepath.Join(path, "previous"), binary+".prev"), publishFile(filepath.Join(path, "run"), record.Run), publishFile(filepath.Join(path, "trial"), record.Trial), removeIfExists(record.Rollback))
	if err == nil {
		err = syncDirectory(filepath.Dir(record.Rollback))
	}
	if err != nil {
		slog.Warn("release installed; state publication incomplete; prepared state retained", "error", err)
		return filepath.Join(path, "run"), filepath.Join(path, "trial"), filepath.Join(path, "rollback"), filepath.Join(path, "previous")
	}
	done := path + ".done"
	err = os.RemoveAll(done)
	if err == nil {
		err = os.Rename(path, done)
	}
	if err != nil {
		slog.Warn("release installed; state cleanup deferred", "error", err)
		return filepath.Join(path, "run"), filepath.Join(path, "trial"), filepath.Join(path, "rollback"), filepath.Join(path, "previous")
	}
	cleanupRelease(done)
	return record.Run, record.Trial, record.Rollback, binary + ".prev"
}
