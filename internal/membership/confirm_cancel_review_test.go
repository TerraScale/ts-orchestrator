package membership

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The first Ctrl-C cancels the command context; the prompt must abort rather
// than stay blocked on a terminal that never answers (#127 11999).
func TestConfirmAbortsWhenTheContextIsCancelled(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Confirm(ctx, reader, new(bytes.Buffer), "w", "re-found gru/b") }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Confirm = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm stayed blocked after cancellation")
	}
	err = Confirm(ctx, strings.NewReader("re-found gru/b\n"), new(bytes.Buffer), "w", "re-found gru/b")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Confirm on a cancelled context = %v", err)
	}
}
