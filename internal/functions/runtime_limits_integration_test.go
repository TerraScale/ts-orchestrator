package functions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestWorkerRejectsUnboundedDecoderResources(t *testing.T) {
	header := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	section := func(id byte, data []byte) []byte {
		result := append([]byte{}, header...)
		result = append(result, id)
		result = append(result, wasmU32(uint32(len(data)))...)
		return append(result, data...)
	}
	count := wasmU32(^uint32(0))
	for _, tc := range []struct {
		name   string
		module []byte
	}{
		{"type-count", section(1, count)},
		{"import-count", section(2, count)},
		{"function-count", section(3, count)},
		{"table-large-minimum", section(4, append([]byte{1, 0x70, 1}, append(wasmU32(1<<27), wasmU32(1<<27)...)...))},
		{"table-without-maximum", section(4, []byte{1, 0x70, 0, 1})},
		{"global-count", section(6, count)},
		{"export-count", section(7, count)},
		{"data-count", section(12, count)},
		{"element-section", section(9, []byte{0})},
		{"custom-section", section(0, []byte{0})},
		{"huge-locals", section(10, append([]byte{1, 8, 1}, append(count, 0x7f, 0x0b)...))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := integrationArtifact(t, "echo")
			artifact.Module = tc.module
			digest := sha256.Sum256(tc.module)
			artifact.Manifest.Digest = hex.EncodeToString(digest[:])
			worker, err := newWorker(t.Context(), artifact)
			if worker != nil {
				_ = worker.Close(context.Background())
				t.Fatal("unbounded module admitted")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("resource admission error: %v", err)
			}
		})
	}
	worker := integrationWorker(t, integrationArtifact(t, "bounded-table"))
	if _, err := worker.Invoke(t.Context(), integrationInvocation(worker.Manifest())); err != nil {
		t.Fatalf("bounded table guest: %v", err)
	}
}
