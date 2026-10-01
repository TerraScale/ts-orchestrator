package commandio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type outputFailure struct {
	writes int
	err    error
}

func (output *outputFailure) Write([]byte) (int, error) {
	output.writes++
	return 0, output.err
}

func TestWriterPreservesFailureAndRejectsShortWrites(t *testing.T) {
	for _, failure := range []error{io.ErrClosedPipe, nil} {
		destination := &outputFailure{err: failure}
		writer := NewWriter(destination)
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if _, err := writer.Write([]byte("verified receipt\n")); !errors.Is(err, want) {
			t.Fatalf("first write error = %v, want %v", err, want)
		}
		if _, err := writer.Write([]byte("another status\n")); !errors.Is(err, want) {
			t.Fatalf("subsequent write error = %v, want %v", err, want)
		}
		if !errors.Is(writer.Err(), want) || destination.writes != 1 {
			t.Fatalf("failure lost or destination reused: err=%v writes=%d", writer.Err(), destination.writes)
		}
	}
}

type cancelOnRead struct {
	cancel context.CancelFunc
	reads  int
}

func (source *cancelOnRead) Read(contents []byte) (int, error) {
	source.reads++
	source.cancel()
	return copy(contents, "artifact"), io.EOF
}

func TestCopyCannotSucceedWhenFinalReadCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := &cancelOnRead{cancel: cancel}
	var destination bytes.Buffer
	if _, err := io.Copy(&destination, Reader(ctx, source)); !errors.Is(err, context.Canceled) {
		t.Fatalf("copy error = %v, want cancellation", err)
	}
	if source.reads != 1 {
		t.Fatalf("reads = %d, want one read", source.reads)
	}
	if _, err := Reader(ctx, source).Read(make([]byte, 32)); !errors.Is(err, context.Canceled) || source.reads != 1 {
		t.Fatalf("canceled reader consumed more input: error=%v reads=%d", err, source.reads)
	}
}
