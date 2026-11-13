package releasepush

import (
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
)

type releaseID struct {
	SHA    string `json:"sha"`
	SHA256 string `json:"sha256"`
}

type releaseRecord interface{ identity() releaseID }

type runFence struct {
	SHA    string `json:"sha"`
	SHA256 string `json:"sha256"`
	RunID  string `json:"run_id"`
}

func (r runFence) identity() releaseID { return releaseID{r.SHA, r.SHA256} }
func (r trial) identity() releaseID    { return releaseID{r.SHA, r.SHA256} }
func (r Rollback) identity() releaseID { return releaseID{r.SHA, r.SHA256} }
func (r Refusal) identity() releaseID  { return releaseID{r.SHA, r.SHA256} }

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
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return releaseID{}, err
	}
	digest, err := fileSHA256(path)
	return releaseID{buildRevision(info), digest}, err
}

func records[T releaseRecord](path string) ([]T, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("release record too large")
	}
	var rows []T
	err = json.Unmarshal(data, &rows)
	return rows, err
}

func selected[T releaseRecord](path string, id releaseID) (T, bool) {
	rows, err := records[T](path)
	if err != nil {
		stateWarning(path, "release record unavailable")
	}
	for _, row := range rows {
		if row.identity() == id {
			return row, true
		}
	}
	var zero T
	return zero, false
}

func storeRecord[T releaseRecord](path string, row T, installed releaseID) error {
	rows, err := records[T](path)
	if err != nil {
		stateWarning(path, "damaged release record replaced")
	}
	next := []T{}
	for _, previous := range rows {
		if previous.identity() == installed && previous.identity() != row.identity() {
			next = append(next, previous)
		}
	}
	return writeJSON(path, append(next, row))
}

func dropRecord[T releaseRecord](path string, id releaseID) error {
	rows, err := records[T](path)
	if err != nil {
		return err
	}
	next := []T{}
	for _, row := range rows {
		if row.identity() != id {
			next = append(next, row)
		}
	}
	if len(next) == 0 {
		return removeIfExists(path)
	}
	return writeJSON(path, next)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func previousBinary(binary string, id releaseID) string {
	return binary + ".prev-" + id.SHA + "-" + id.SHA256
}

func prepareRecords(h *Handler, candidate releaseID, run string) error {
	installed, err := binaryIdentity(h.Binary)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(h.Binary)
	if err != nil {
		return err
	}
	previous := previousBinary(h.Binary, installed)
	if err := writeSynced(previous, data); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(h.Binary)); err != nil {
		return err
	}
	fence := runFence{candidate.SHA, candidate.SHA256, run}
	if existing, ok := selected[runFence](h.RunIDFile, installed); ok && installed == candidate {
		old, _ := strconv.ParseUint(existing.RunID, 10, 64)
		next, _ := strconv.ParseUint(run, 10, 64)
		if next <= old {
			return fmt.Errorf("run %s already installed", run)
		}
	}
	if err := storeRecord(h.RunIDFile, fence, installed); err != nil {
		return err
	}
	record := trial{SHA: candidate.SHA, SHA256: candidate.SHA256, RunID: run, Previous: installed}
	if err := storeRecord(h.TrialFile, record, installed); err != nil {
		return err
	}
	rollback := Rollback{SHA: candidate.SHA, SHA256: candidate.SHA256, RunID: run, Previous: installed}
	if err := storeRecord(h.RollbackFile, rollback, installed); err != nil {
		return err
	}
	return storeRecord(h.RefusalFile, Refusal{Kind: RefusalHost, SHA: candidate.SHA, SHA256: candidate.SHA256, RunID: run}, installed)
}
