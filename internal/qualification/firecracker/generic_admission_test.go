package firecracker

import (
	"os"
	"os/exec"
	"path/filepath"

	"syscall"

	"time"
)

func fixtureProcess() *Process {
	return &Process{Cmd: &exec.Cmd{Process: &os.Process{Pid: 1234}}, hooks: &processHooks{
		group:     func(pid int) (int, error) { return pid, nil },
		signal:    func(int, syscall.Signal) error { return nil },
		exited:    func() (bool, error) { return false, nil },
		wait:      func(time.Duration) (bool, error) { return true, nil },
		quiescent: func(int, time.Duration) error { return nil },
		reap:      func() error { return nil },
	}}
}

type chronyDirectoryInfo struct {
	name string
	mode os.FileMode
	uid  uint32
}

func (s chronyDirectoryInfo) Name() string       { return filepath.Base(s.name) }
func (s chronyDirectoryInfo) Size() int64        { return 0 }
func (s chronyDirectoryInfo) Mode() os.FileMode  { return s.mode }
func (s chronyDirectoryInfo) ModTime() time.Time { return time.Time{} }
func (s chronyDirectoryInfo) IsDir() bool        { return s.mode.IsDir() }
func (s chronyDirectoryInfo) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }
