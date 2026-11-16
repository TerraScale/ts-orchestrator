package runtimepriority

import (
	"context"
	"time"
)

// Remote executes the fixed guest actions. Root paths and hooks are dependencies
// of the Go library; they are never accepted from the wire request.
type Remote struct {
	CgroupRoot, ProcRoot, ProbeBase, RunRoot string
	Witness                                  func(int64) (Object, error)
	Signal                                   func(int64) error
	BeforeOpenFile                           func(string, bool)
	WriteLimit                               func(int, int64) error
	ScopeLauncher                            func([]string) (func(context.Context) error, <-chan error, error)
	Command                                  func(context.Context, []string, []byte, time.Duration, int) ([]byte, error)
}
