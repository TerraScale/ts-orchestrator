package functions

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
)

// Worker retains compiled code, never a guest instance or a disk/native cache.
type Worker struct {
	manifest  Manifest
	runtime   wazero.Runtime
	compiled  wazero.CompiledModule
	ctx       context.Context
	cancel    context.CancelFunc
	slots     chan struct{}
	succeeded atomic.Uint64
	failed    atomic.Uint64
	rejected  atomic.Uint64
}

// Snapshot contains worker counters and artifact identity, never invocation data.
type Snapshot struct {
	SchemaVersion  int       `json:"schema_version"`
	ObservedAt     time.Time `json:"observed_at"`
	Manifest       Manifest
	RuntimeVersion string
	Architecture   string
	Active         int
	Succeeded      uint64
	Failed         uint64
	Rejected       uint64
}
