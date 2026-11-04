package globalcontrol

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestDocumentsRelayExactBytesAsNextGenerations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startAuthority(ctx, t, js, protocol.GlobalScope)
	writer, err := OpenHome(ctx, js, "gru", []string{"sjc"}, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	epoch := global.Current().Epoch
	for name, put := range map[string]func() error{
		"roster kind": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindRoster, "sjc", []byte("x"), nil)
			return err
		},
		"global cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "global", []byte("x"), nil)
			return err
		},
		"budget regional cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindBudget, "sjc", []byte("x"), nil)
			return err
		},
		"capacity regional cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCapacity, "sjc", []byte("x"), nil)
			return err
		},
		"bad cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "S.FO", []byte("x"), nil)
			return err
		},
		"empty": func() error { _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", nil, nil); return err },
		"oversized": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", make([]byte, maxRecordBytes+1), nil)
			return err
		},
		"foreign epoch": func() error {
			_, err := writer.PutDocument(ctx, epoch+1, KindCellSpec, "sjc", []byte("x"), nil)
			return err
		},
		"zero epoch": func() error { _, err := writer.PutDocument(ctx, 0, KindCellSpec, "sjc", []byte("x"), nil); return err },
	} {
		if err := put(); err == nil {
			t.Errorf("%s document was written", name)
		}
	}
	if _, err := writer.Document(ctx, KindCellSpec, "sjc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing document = %v", err)
	}

	first := []byte(`{"spec":"g1"}`)
	sequence, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", first, nil); err != nil || again != sequence {
		t.Fatalf("idempotent retry = %d, %v; want %d", again, err, sequence)
	}
	document, err := writer.Document(ctx, KindCellSpec, "sjc")
	if err != nil || !bytes.Equal(document.Payload, first) || document.Generation != 1 ||
		document.Epoch != epoch || document.Sequence != sequence {
		t.Fatalf("document = %+v, %v", document, err)
	}
	// The largest payload fits the stream's message bound once base64'd.
	largest := bytes.Repeat([]byte("s"), maxRecordBytes)
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", largest, nil); err != nil {
		t.Fatalf("largest document: %v", err)
	}
	// Republishing an older payload is a new generation: ordering a
	// document is the verifier's job, never the relay's.
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", first, nil); err != nil {
		t.Fatal(err)
	}
	document, err = writer.Document(ctx, KindCellSpec, "sjc")
	if err != nil || !bytes.Equal(document.Payload, first) || document.Generation != 3 {
		t.Fatalf("republished document = %+v, %v", document, err)
	}
	if _, err := writer.Document(ctx, KindCellSpec, "fra"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another cell's document = %v", err)
	}
	// The global writer's own documents live under the global cell only.
	for _, kind := range []Kind{KindBudget, KindCapacity} {
		if _, err := writer.PutDocument(ctx, epoch, kind, protocol.GlobalScope, first, nil); err != nil {
			t.Fatalf("%s document: %v", kind, err)
		}
		if document, err := writer.Document(ctx, kind, protocol.GlobalScope); err != nil || !bytes.Equal(document.Payload, first) {
			t.Fatalf("%s document = %+v, %v", kind, document, err)
		}
		if _, err := writer.Document(ctx, kind, "sjc"); err == nil {
			t.Fatalf("%s document read for a regional cell", kind)
		}
	}
	// admit sees the exact stored payload, or nil, and may refuse the write.
	refused := errors.New("refused")
	var seen [][]byte
	admit := func(prior []byte) error {
		seen = append(seen, prior)
		return refused
	}
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sjc", []byte("refused"), admit); !errors.Is(err, refused) {
		t.Fatalf("refused document = %v", err)
	}
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "iad", []byte("refused"), admit); !errors.Is(err, refused) {
		t.Fatalf("refused first document = %v", err)
	}
	if len(seen) != 2 || !bytes.Equal(seen[0], first) || seen[1] != nil {
		t.Fatalf("admit saw %q", seen)
	}
	if document, err := writer.Document(ctx, KindCellSpec, "sjc"); err != nil || !bytes.Equal(document.Payload, first) {
		t.Fatalf("a refused document was written: %+v, %v", document, err)
	}
	// A record appended outside the writer has no epoch header.
	if _, err := js.Publish(ctx, protocol.GlobalState(string(KindCellSpec), "fra"),
		[]byte(`{"version":1,"kind":"cellspec","key":"fra","generation":1,"epoch":1,"payload":"eA=="}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Document(ctx, KindCellSpec, "fra"); !errors.Is(err, ErrRecordCorrupt) {
		t.Fatalf("forged document = %v", err)
	}
}
