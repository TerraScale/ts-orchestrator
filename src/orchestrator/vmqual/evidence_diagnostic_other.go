//go:build !linux

package vmqual

import (
	"errors"
	"os"
	"path/filepath"
)

func openFailureDiagnosticAt(root, path string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || filepath.Dir(filepath.Clean(path)) != filepath.Clean(root) {
		return nil, nil, errors.New("diagnostic path is outside its exact VM state directory")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !safeFailureDiagnosticInfo(before) {
		return nil, nil, errors.New("unsafe diagnostic source metadata")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !safeFailureDiagnosticInfo(opened) || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("diagnostic source changed while opening")
	}
	return file, opened, nil
}
