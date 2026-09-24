package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type countingArtifactStore struct {
	data      []byte
	mu        sync.Mutex
	gets      int
	readBytes int
}

func (s *countingArtifactStore) Get(_ context.Context, _ string, _ ...jetstream.GetObjectOpt) (jetstream.ObjectResult, error) {
	s.mu.Lock()
	s.gets++
	s.mu.Unlock()
	return &countingObject{Reader: bytes.NewReader(s.data), store: s, info: &jetstream.ObjectInfo{Size: uint64(len(s.data))}}, nil
}

func (s *countingArtifactStore) GetInfo(_ context.Context, _ string, _ ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	return &jetstream.ObjectInfo{Size: uint64(len(s.data))}, nil
}

type countingObject struct {
	*bytes.Reader
	store *countingArtifactStore
	info  *jetstream.ObjectInfo
}

func (r *countingObject) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.store.mu.Lock()
	r.store.readBytes += n
	r.store.mu.Unlock()
	return n, err
}
func (r *countingObject) Close() error                         { return nil }
func (r *countingObject) Info() (*jetstream.ObjectInfo, error) { return r.info, nil }
func (r *countingObject) Error() error                         { return nil }

func TestArtifactChunksReadBackendOnce(t *testing.T) {
	data := bytes.Repeat([]byte("terrascale-binary"), artifactChunkBytes/16*3)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	store := &countingArtifactStore{data: data}
	ctx, cancel := context.WithCancel(t.Context())
	c := &Controller{artifacts: store, cacheContext: ctx, cacheCancel: cancel}
	defer c.closeCache()
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
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.gets != 1 || store.readBytes != len(data) {
		t.Fatalf("backend reads: gets=%d bytes=%d want one pass of %d", store.gets, store.readBytes, len(data))
	}
}

var _ io.ReadCloser = (*countingObject)(nil)
