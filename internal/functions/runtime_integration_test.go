package functions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestWorkerGuestExecutionAndIsolation(t *testing.T) {
	artifact := integrationArtifact(t, "echo")
	w := integrationWorker(t, artifact)
	in := integrationInvocation(artifact.Manifest)
	in.Payload = []byte("tenant payload")
	for range 2 {
		result, err := w.Invoke(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		var got Invocation
		if err := json.Unmarshal(result.Output, &got); err != nil {
			t.Fatal(err)
		}
		if got.ID != in.ID || !bytes.Equal(got.Payload, in.Payload) || result.InvocationID != in.ID || result.Revision != in.Revision {
			t.Fatalf("guest round trip: %+v / %+v", result, got)
		}
	}
	wrong := in
	wrong.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	if _, err := w.Invoke(t.Context(), wrong); !errors.Is(err, ErrScope) {
		t.Fatalf("scope error: %v", err)
	}
	snapshot := w.Snapshot()
	if snapshot.Succeeded != 2 || snapshot.Rejected != 1 || snapshot.Active != 0 || snapshot.RuntimeVersion != RuntimeVersion || snapshot.Architecture != runtime.GOARCH {
		t.Fatalf("snapshot: %+v", snapshot)
	}
	stateArtifact := integrationArtifact(t, "state")
	state := integrationWorker(t, stateArtifact)
	for range 2 {
		result, err := state.Invoke(t.Context(), integrationInvocation(stateArtifact.Manifest))
		if err != nil || string(result.Output) != "1" {
			t.Fatalf("guest state persisted: %q, %v", result.Output, err)
		}
	}
}

func TestWorkerCancellationAndCapacity(t *testing.T) {
	artifact := integrationArtifact(t, "loop")
	w := integrationWorker(t, artifact)
	ctx, cancel := context.WithCancel(t.Context())
	results := make(chan error, MaxConcurrent)
	var wg sync.WaitGroup
	for range MaxConcurrent {
		wg.Go(func() { _, err := w.Invoke(ctx, integrationInvocation(artifact.Manifest)); results <- err })
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for w.Snapshot().Active != MaxConcurrent {
		select {
		case <-deadline.C:
			t.Fatal("workers did not enter guests")
		default:
			runtime.Gosched()
		}
	}
	if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrency admission: %v", err)
	}
	cancel()
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled loop: %v", err)
		}
	}
	if w.Snapshot().Active != 0 {
		t.Fatal("cancellation leaked concurrency tokens")
	}
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := w.Invoke(ctx, integrationInvocation(artifact.Manifest)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline loop: %v", err)
	}
}

func TestWorkerFixedDeadlineAndConcurrentClose(t *testing.T) {
	artifact := integrationArtifact(t, "loop")
	w := integrationWorker(t, artifact)
	started := time.Now()
	if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fixed deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed < InvocationTimeout || elapsed > InvocationTimeout+time.Second {
		t.Fatalf("deadline took %s", elapsed)
	}
	result := make(chan error, 1)
	go func() { _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); result <- err }()
	for w.Snapshot().Active == 0 {
		runtime.Gosched()
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := w.Close(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := <-result; !errors.Is(err, ErrClosed) {
		t.Fatalf("close active guest: %v", err)
	}
	if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); !errors.Is(err, ErrClosed) {
		t.Fatalf("invoke closed worker: %v", err)
	}
}

func TestWorkerResourceAndImportBoundaries(t *testing.T) {
	for _, kind := range []string{"output-limit", "stderr-limit"} {
		t.Run(kind, func(t *testing.T) {
			artifact := integrationArtifact(t, kind)
			w := integrationWorker(t, artifact)
			if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("stream bound: %v", err)
			}
			if w.Snapshot().Active != 0 {
				t.Fatal("stream limit leaked token")
			}
		})
	}
	artifact := integrationArtifact(t, "memory-limit")
	w := integrationWorker(t, artifact)
	if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); err != nil {
		t.Fatalf("memory.grow exceeded configured maximum: %v", err)
	}
	for _, kind := range []string{"ambient", "exit-zero"} {
		t.Run(kind, func(t *testing.T) {
			artifact := integrationArtifact(t, kind)
			w := integrationWorker(t, artifact)
			if _, err := w.Invoke(t.Context(), integrationInvocation(artifact.Manifest)); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("host-sleep-cancellation", func(t *testing.T) {
		artifact := integrationArtifact(t, "sleep")
		w := integrationWorker(t, artifact)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := w.Invoke(ctx, integrationInvocation(artifact.Manifest)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("sleep deadline: %v", err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("WASI host sleep did not honor cancellation")
		}
	})
	for _, kind := range []string{"unauthorized", "socket", "bad-start"} {
		t.Run(kind, func(t *testing.T) {
			if worker, err := newWorker(t.Context(), integrationArtifact(t, kind)); !errors.Is(err, ErrInvalid) {
				if worker != nil {
					worker.Close(t.Context())
				}
				t.Fatalf("module admission: %v", err)
			}
		})
	}
}

func integrationWorker(t *testing.T, artifact Artifact) *Worker {
	t.Helper()
	admitted, _, _ := signedFunctionFixture(t, artifact)
	w, err := NewWorker(t.Context(), admitted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return w
}

func integrationInvocation(m Manifest) Invocation {
	return Invocation{TenantID: m.TenantID, FunctionID: m.FunctionID, Revision: m.Revision, ID: "invocation-1", Trigger: "http"}
}

// integrationArtifact emits real Wasm binaries; opcodes remain beside the exercised boundary.
func integrationArtifact(t *testing.T, kind string) Artifact {
	t.Helper()
	module := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	section := func(id byte, data []byte) {
		module = append(module, id)
		module = append(module, wasmU32(uint32(len(data)))...)
		module = append(module, data...)
	}
	text := func(value string) []byte { return append(wasmU32(uint32(len(value))), value...) }
	// fd_read/write/poll_oneoff, _start, size/preopen queries, proc_exit.
	section(1, []byte{4, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 0})
	imports := uint32(0)
	if kind != "loop" && kind != "memory-limit" && kind != "bad-start" {
		names := []string{"fd_write"}
		if kind == "echo" {
			names = []string{"fd_read", "fd_write"}
		}
		if kind == "unauthorized" {
			names = []string{"metadata_fetch"}
		}
		if kind == "socket" {
			names = []string{"sock_send"}
		}
		if kind == "ambient" {
			names = []string{"args_sizes_get", "environ_sizes_get", "fd_prestat_get"}
		}
		if kind == "sleep" {
			names = []string{"poll_oneoff"}
		}
		if kind == "exit-zero" {
			names = []string{"proc_exit"}
		}
		data := wasmU32(uint32(len(names)))
		for _, name := range names {
			mod := "wasi_snapshot_preview1"
			if kind == "unauthorized" {
				mod = "terrascale"
			}
			data = append(data, text(mod)...)
			data = append(data, text(name)...)
			functionType := byte(0)
			if kind == "ambient" {
				functionType = 2
			}
			if kind == "exit-zero" {
				functionType = 3
			}
			data = append(data, 0, functionType)
		}
		imports = uint32(len(names))
		section(2, data)
	}
	functionType := byte(1)
	if kind == "bad-start" {
		functionType = 0
	}
	section(3, []byte{1, functionType})
	if kind == "bounded-table" {
		section(4, []byte{1, 0x70, 1, 1, 1})
	}
	section(5, []byte{1, 0, 32})
	if kind == "state" {
		section(6, []byte{1, 0x7f, 1, 0x41, 0, 0x0b})
	}
	exports := []byte{2}
	exports = append(exports, text("memory")...)
	exports = append(exports, 2, 0)
	exports = append(exports, text("_start")...)
	exports = append(exports, 0)
	exports = append(exports, wasmU32(imports)...)
	section(7, exports)
	code := []byte{0}
	constant := func(value int32) { code = append(code, 0x41); code = append(code, wasmI32(value)...) }
	store := func(address, value int32) { constant(address); constant(value); code = append(code, 0x36, 2, 0) }
	write := func(fd int32, index byte) {
		constant(fd)
		constant(0)
		constant(1)
		constant(12)
		code = append(code, 0x10, index, 0x1a)
	}
	switch kind {
	case "loop":
		code = append(code, 0x03, 0x40, 0x0c, 0, 0x0b)
	case "memory-limit":
		constant(MaxMemoryPages)
		code = append(code, 0x40, 0)
		constant(-1)
		code = append(code, 0x47, 0x04, 0x40, 0, 0x0b)
	case "echo":
		store(0, 32)
		store(4, (32<<16)-32)
		constant(0)
		constant(0)
		constant(1)
		constant(8)
		code = append(code, 0x10, 0, 0x1a)
		constant(4)
		constant(8)
		code = append(code, 0x28, 2, 0, 0x36, 2, 0)
		write(1, 1)
	case "state":
		code = append(code, 0x23, 0)
		constant(1)
		code = append(code, 0x6a, 0x24, 0)
		constant(32)
		code = append(code, 0x23, 0)
		constant('0')
		code = append(code, 0x6a, 0x3a, 0, 0)
		store(0, 32)
		store(4, 1)
		write(1, 0)
	case "ambient":
		for _, index := range []byte{0, 1} {
			constant(16)
			constant(20)
			code = append(code, 0x10, index, 0x1a)
			for _, address := range []int32{16, 20} {
				constant(address)
				code = append(code, 0x28, 2, 0, 0x04, 0x40, 0, 0x0b)
			}
		}
		constant(3)
		constant(32)
		code = append(code, 0x10, 2)
		constant(8)
		code = append(code, 0x47, 0x04, 0x40, 0, 0x0b)
	case "sleep":
		store(80, 1)
		store(88, 1_000_000_000)
		constant(64)
		constant(128)
		constant(1)
		constant(16)
		code = append(code, 0x10, 0, 0x1a)
	case "exit-zero":
		constant(0)
		code = append(code, 0x10, 0)
	case "output-limit", "stderr-limit":
		store(0, 32)
		store(4, 65536)
		code = append(code, 0x03, 0x40)
		fd := int32(1)
		if kind == "stderr-limit" {
			fd = 2
		}
		write(fd, 0)
		code = append(code, 0x0c, 0, 0x0b)
	case "bad-start":
		constant(0)
	}
	code = append(code, 0x0b)
	body := append(wasmU32(uint32(len(code))), code...)
	section(10, append([]byte{1}, body...))
	sum := sha256.Sum256(module)
	return Artifact{Manifest: Manifest{ABI: ABI, TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", FunctionID: "test-function", Revision: "r-one", Digest: hex.EncodeToString(sum[:])}, Module: module}
}

func wasmU32(value uint32) []byte {
	var encoded []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
		if value == 0 {
			return encoded
		}
	}
}

func wasmI32(value int32) []byte {
	var encoded []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		done := value == 0 && b&0x40 == 0 || value == -1 && b&0x40 != 0
		if !done {
			b |= 0x80
		}
		encoded = append(encoded, b)
		if done {
			return encoded
		}
	}
}
