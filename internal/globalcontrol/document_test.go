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
	writer, err := OpenHome(ctx, js, "gru", []string{"sfo"}, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	epoch := global.Current().Epoch
	for name, put := range map[string]func() error{
		"roster kind": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindRoster, "sfo", []byte("x"), nil)
			return err
		},
		"global cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "global", []byte("x"), nil)
			return err
		},
		"budget regional cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindBudget, "sfo", []byte("x"), nil)
			return err
		},
		"capacity regional cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCapacity, "sfo", []byte("x"), nil)
			return err
		},
		"bad cell": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "S.FO", []byte("x"), nil)
			return err
		},
		"empty": func() error { _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", nil, nil); return err },
		"oversized": func() error {
			_, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", make([]byte, maxRecordBytes+1), nil)
			return err
		},
		"foreign epoch": func() error {
			_, err := writer.PutDocument(ctx, epoch+1, KindCellSpec, "sfo", []byte("x"), nil)
			return err
		},
		"zero epoch": func() error { _, err := writer.PutDocument(ctx, 0, KindCellSpec, "sfo", []byte("x"), nil); return err },
	} {
		if err := put(); err == nil {
			t.Errorf("%s document was written", name)
		}
	}
	if _, err := writer.Document(ctx, KindCellSpec, "sfo"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing document = %v", err)
	}

	first := []byte(`{"spec":"g1"}`)
	sequence, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", first, nil); err != nil || again != sequence {
		t.Fatalf("idempotent retry = %d, %v; want %d", again, err, sequence)
	}
	document, err := writer.Document(ctx, KindCellSpec, "sfo")
	if err != nil || !bytes.Equal(document.Payload, first) || document.Generation != 1 ||
		document.Epoch != epoch || document.Sequence != sequence {
		t.Fatalf("document = %+v, %v", document, err)
	}
	// The largest payload fits the stream's message bound once base64'd.
	largest := bytes.Repeat([]byte("s"), maxRecordBytes)
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", largest, nil); err != nil {
		t.Fatalf("largest document: %v", err)
	}
	// Republishing an older payload is a new generation: ordering a
	// document is the verifier's job, never the relay's.
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", first, nil); err != nil {
		t.Fatal(err)
	}
	document, err = writer.Document(ctx, KindCellSpec, "sfo")
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
		if _, err := writer.Document(ctx, kind, "sfo"); err == nil {
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
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "sfo", []byte("refused"), admit); !errors.Is(err, refused) {
		t.Fatalf("refused document = %v", err)
	}
	if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, "iad", []byte("refused"), admit); !errors.Is(err, refused) {
		t.Fatalf("refused first document = %v", err)
	}
	if len(seen) != 2 || !bytes.Equal(seen[0], first) || seen[1] != nil {
		t.Fatalf("admit saw %q", seen)
	}
	if document, err := writer.Document(ctx, KindCellSpec, "sfo"); err != nil || !bytes.Equal(document.Payload, first) {
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

func TestFollowOffersTheDocumentOnEveryChangeAndRecheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startAuthority(ctx, t, js, protocol.GlobalScope)
	writer, err := OpenHome(ctx, js, "gru", nil, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	epoch := global.Current().Epoch
	if err := writer.Follow(ctx, KindRoster, "sfo", time.Hour, nil); err == nil {
		t.Fatal("followed a non-document kind")
	}
	if err := writer.Follow(ctx, KindCellSpec, "sfo", 0, nil); err == nil {
		t.Fatal("followed without a recheck interval")
	}
	put := func(cell, payload string) {
		t.Helper()
		if _, err := writer.PutDocument(ctx, epoch, KindCellSpec, cell, []byte(payload), nil); err != nil {
			t.Fatal(err)
		}
	}
	put("sfo", "g1")
	offered := make(chan string, 64)
	follow := func(recheck time.Duration) (context.CancelFunc, chan error) {
		followCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- writer.Follow(followCtx, KindCellSpec, "sfo", recheck, func(_ context.Context, document Document) {
				offered <- string(document.Payload)
			})
		}()
		return stop, done
	}
	expectOffer := func(want string) {
		t.Helper()
		select {
		case got := <-offered:
			if got != want {
				t.Fatalf("offered %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q was not offered", want)
		}
	}

	// Without rechecks only the watch offers documents: each change arrives
	// as soon as it is stored, and another cell's change offers nothing.
	stop, done := follow(time.Hour)
	expectOffer("g1")
	put("fra", "0000000000V4MRM46HP1SNGDYW")
	put("sfo", "g2")
	// The start may race the watch's first delivery; both offer g1.
	for got := ""; got != "g2"; {
		select {
		case got = <-offered:
			if got != "g1" && got != "g2" {
				t.Fatalf("offered %q", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("g2 was not offered")
		}
	}
	select {
	case got := <-offered:
		t.Fatalf("offered %q without a change", got)
	case <-time.After(300 * time.Millisecond):
	}
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("follow ended with %v", err)
	}

	// Every recheck offers the current document again, so a caller that
	// could not act on it (a follower) acts once it can.
	stop, _ = follow(20 * time.Millisecond)
	defer stop()
	for range 5 {
		expectOffer("g2")
	}
}

func TestOpenHomeRaisesAnOldMessageBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startAuthority(ctx, t, js, protocol.GlobalScope)
	old := HomeStreamConfig(1)
	old.MaxMsgSize = 64 << 10
	if _, err := js.CreateStream(ctx, old); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenHome(ctx, js, "gru", nil, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	info, err := writer.stream.Info(ctx)
	if err != nil || info.Config.MaxMsgSize != maxMessageBytes {
		t.Fatalf("message bound = %+v, %v", info, err)
	}
	if _, err := writer.PutDocument(ctx, global.Current().Epoch, KindCellSpec, "sfo",
		bytes.Repeat([]byte("s"), maxRecordBytes), nil); err != nil {
		t.Fatalf("largest document after the raise: %v", err)
	}
}
