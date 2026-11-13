package releasepush

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var stateWarnings sync.Map

func stateWarning(path string) {
	if _, loaded := stateWarnings.LoadOrStore(path, struct{}{}); !loaded {
		slog.Warn("release state unavailable; continuing without record", "file", filepath.Base(path))
	}
}

func readState(path string, value any) bool {
	file, err := os.Open(path)
	if err != nil {
		stateWarning(path)
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) > 64<<10 || json.Unmarshal(data, value) != nil {
		stateWarning(path)
		return false
	}
	return true
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
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
