package releasepush

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var stateWarnings sync.Map

func stateWarning(path, loss string) {
	if _, loaded := stateWarnings.LoadOrStore(path, struct{}{}); !loaded {
		slog.Warn(loss, "file", filepath.Base(path))
	}
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
