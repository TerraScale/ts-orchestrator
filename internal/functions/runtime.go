package functions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
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
	Manifest       Manifest
	RuntimeVersion string
	Architecture   string
	Active         int
	Succeeded      uint64
	Failed         uint64
	Rejected       uint64
}

func newWorker(ctx context.Context, artifact Artifact) (*Worker, error) {
	if err := artifact.Validate(); err != nil {
		return nil, err
	}
	if err := validateModuleResources(artifact.Module); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(MaxMemoryPages).WithCloseOnContextDone(true))
	fail := func(err error) (*Worker, error) {
		cancel()
		return nil, errors.Join(err, r.Close(context.Background()))
	}
	_, err := wasi_snapshot_preview1.Instantiate(ctx, r)
	if err != nil {
		return fail(fmt.Errorf("instantiate WASI: %w", err))
	}
	compiled, err := r.CompileModule(ctx, artifact.Module)
	if err != nil {
		return fail(fmt.Errorf("%w: compile module: %v", ErrInvalid, err))
	}
	start := compiled.ExportedFunctions()["_start"]
	if start == nil || len(start.ParamTypes()) != 0 || len(start.ResultTypes()) != 0 {
		return fail(fmt.Errorf("%w: command requires _start() with no results", ErrInvalid))
	}
	if len(compiled.ImportedMemories()) != 0 {
		return fail(fmt.Errorf("%w: imported memory", ErrInvalid))
	}
	for _, imported := range compiled.ImportedFunctions() {
		module, name, _ := imported.Import()
		host := r.Module(wasi_snapshot_preview1.ModuleName).ExportedFunctionDefinitions()[name]
		if module != wasi_snapshot_preview1.ModuleName || strings.HasPrefix(name, "sock_") || host == nil || !slices.Equal(imported.ParamTypes(), host.ParamTypes()) || !slices.Equal(imported.ResultTypes(), host.ResultTypes()) {
			return fail(fmt.Errorf("%w: unsupported import %s.%s", ErrInvalid, module, name))
		}
	}
	manifest := artifact.Manifest
	manifest.Capabilities = nil
	return &Worker{manifest: manifest, runtime: r, compiled: compiled, ctx: ctx, cancel: cancel, slots: make(chan struct{}, MaxConcurrent)}, nil
}

func (w *Worker) Manifest() Manifest { return w.manifest }

func (w *Worker) Snapshot() Snapshot {
	return Snapshot{Manifest: w.Manifest(), RuntimeVersion: RuntimeVersion, Architecture: runtime.GOARCH, Active: len(w.slots), Succeeded: w.succeeded.Load(), Failed: w.failed.Load(), Rejected: w.rejected.Load()}
}

func (w *Worker) Invoke(ctx context.Context, in Invocation) (result Result, err error) {
	if err = in.Validate(w.manifest); err != nil {
		w.rejected.Add(1)
		return result, err
	}
	if w.ctx.Err() != nil {
		w.rejected.Add(1)
		return result, ErrClosed
	}
	select {
	case w.slots <- struct{}{}:
	default:
		w.rejected.Add(1)
		return result, ErrBusy
	}
	defer func() {
		<-w.slots
		if err != nil {
			w.failed.Add(1)
		} else {
			w.succeeded.Add(1)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, InvocationTimeout)
	defer cancel()
	stop := context.AfterFunc(w.ctx, cancel)
	defer stop()
	input, err := json.Marshal(in)
	if err != nil {
		return result, fmt.Errorf("encode invocation: %w", err)
	}
	stdout := &boundedOutput{cancel: cancel}
	stderr := &boundedOutput{cancel: cancel}
	config := wazero.NewModuleConfig().WithName("").WithStdin(bytes.NewReader(input)).WithStdout(stdout).WithStderr(stderr).
		WithRandSource(rand.Reader).WithSysWalltime().WithSysNanotime().WithNanosleep(func(ns int64) {
		timer := time.NewTimer(time.Duration(ns))
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
	})
	module, callErr := w.runtime.InstantiateModule(ctx, w.compiled, config)
	if module != nil {
		defer module.Close(context.Background())
	}
	if stdout.exceeded || stderr.exceeded {
		return result, ErrOutputLimit
	}
	if w.ctx.Err() != nil {
		return result, ErrClosed
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if callErr != nil {
		if exit, ok := errors.AsType[*sys.ExitError](callErr); !ok || exit.ExitCode() != 0 {
			return result, fmt.Errorf("execute function: %w", callErr)
		}
	}
	return Result{InvocationID: in.ID, Revision: w.manifest.Revision, Output: stdout.Bytes()}, nil
}

// Close cancels active calls before releasing the runtime and compiled artifact.
func (w *Worker) Close(ctx context.Context) error {
	w.cancel()
	return w.runtime.Close(ctx)
}

type boundedOutput struct {
	bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > MaxOutputBytes-b.Len() {
		b.exceeded = true
		b.cancel()
		return 0, ErrOutputLimit
	}
	return b.Buffer.Write(p)
}
