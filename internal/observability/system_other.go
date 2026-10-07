//go:build !linux

package observability

import "errors"

func statFilesystem(string) (FilesystemView, error) {
	return FilesystemView{}, errors.New("filesystem statistics require Linux")
}

func readClock() *ClockView { return nil }
