package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestArtifactChunksReadBackendWithoutConsumer(t *testing.T) {
	c, conn, store, _, _ := testController(t)
	defer c.closeCache()
	data := bytes.Repeat([]byte("terrascale-binary"), artifactChunkBytes/16*3)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	var copied []byte
	for offset := int64(0); offset < int64(len(data)); {
		part, total, err := c.readArtifactChunk(t.Context(), digest, offset, artifactChunkBytes)
		if errors.Is(err, errArtifactPreparing) {
			select {
			case <-time.After(10 * time.Millisecond):
				continue
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		if total != int64(len(data)) {
			t.Fatalf("total %d", total)
		}
		copied = append(copied, part...)
		offset += int64(len(part))
	}
	if !bytes.Equal(copied, data) {
		t.Fatal("cached chunks changed artifact bytes")
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(t.Context(), "OBJ_HOST_TEST_ARTIFACTS")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Consumers != 0 {
		t.Fatalf("artifact read created %d consumers", info.State.Consumers)
	}
}
