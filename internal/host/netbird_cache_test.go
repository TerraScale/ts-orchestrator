package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNetBirdAndWorkloadArtifactSpoolsDoNotEvictEachOther(t *testing.T) {
	c, _, store, _, _ := testController(t)
	defer c.closeCache()
	workload := bytes.Repeat([]byte("w"), artifactChunkBytes*2)
	netbird := bytes.Repeat([]byte("n"), artifactChunkBytes*2)
	put := func(body []byte) string {
		t.Helper()
		hash := sha256.Sum256(body)
		digest := hex.EncodeToString(hash[:])
		if _, err := store.PutBytes(t.Context(), "sha256-"+digest, body); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	workloadDigest, netbirdDigest := put(workload), put(netbird)
	sink := &networkSinkFake{allowedDigest: netbirdDigest}
	c.SetNetBirdSink(sink)
	readNetBird := func(ctx context.Context, offset int64) ([]byte, int64, error) {
		wire, err := json.Marshal(RolloutBinaryQuery{Digest: netbirdDigest, Offset: offset})
		if err != nil {
			return nil, 0, err
		}
		reply, err := c.serveNetBird(ctx, request{Operation: "netbird-binary", Payload: wire}, Registration{})
		if err != nil {
			return nil, 0, err
		}
		chunk := reply.(RolloutChunk)
		return chunk.Data, chunk.Size, nil
	}
	readWorkload := func(ctx context.Context, offset int64) ([]byte, int64, error) {
		return c.readArtifactChunk(ctx, workloadDigest, offset, artifactChunkBytes)
	}
	warm := func(read func(context.Context, int64) ([]byte, int64, error)) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		for {
			_, _, err := read(ctx, 0)
			if !errors.Is(err, errArtifactPreparing) {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	warm(readWorkload)
	warm(readNetBird)
	for range 3 {
		for _, offset := range []int64{0, artifactChunkBytes} {
			for _, item := range []struct {
				read func(context.Context, int64) ([]byte, int64, error)
				body []byte
			}{{readWorkload, workload}, {readNetBird, netbird}} {
				data, total, err := item.read(t.Context(), offset)
				if err != nil || total != int64(len(item.body)) || !bytes.Equal(data, item.body[offset:offset+artifactChunkBytes]) {
					t.Fatalf("interleaved request lost its verified spool: total=%d err=%v", total, err)
				}
			}
		}
	}
	sink.allowedDigest = ""
	if _, _, err := readNetBird(t.Context(), 0); err == nil {
		t.Fatal("cached NetBird binary bypassed current pin authorization")
	}
	sink.allowedDigest = netbirdDigest
	c.cacheMu.Lock()
	files := []*os.File{c.workloadCache.file, c.netbirdCache.file}
	c.cacheMu.Unlock()
	c.closeCache()
	for _, file := range files {
		if _, err := file.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("cache close left a spool open: %v", err)
		}
	}
	for _, read := range []func(context.Context, int64) ([]byte, int64, error){readWorkload, readNetBird} {
		if _, _, err := read(t.Context(), 0); err == nil || errors.Is(err, errArtifactPreparing) {
			t.Fatalf("closed cache accepted a read or new download: %v", err)
		}
	}
}

func TestNetBirdArtifactSpoolRejectsOversizeMetadata(t *testing.T) {
	c, conn, store, _, _ := testController(t)
	defer c.closeCache()
	body := []byte("oversize metadata fixture")
	hash := sha256.Sum256(body)
	digest := hex.EncodeToString(hash[:])
	info, err := store.PutBytes(t.Context(), "sha256-"+digest, body)
	if err != nil {
		t.Fatal(err)
	}
	info.Size = client.MaxBinaryBytes + 1
	wire, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Publish("$O."+info.Bucket+".M."+base64.URLEncoding.EncodeToString([]byte(info.Name)), wire); err != nil {
		t.Fatal(err)
	}
	var chunkReads atomic.Int64
	if _, err := conn.Subscribe("$JS.API.>", func(msg *nats.Msg) {
		var request struct {
			Subject string `json:"next_by_subj"`
		}
		if json.Unmarshal(msg.Data, &request) == nil && request.Subject != "" {
			chunkReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	c.downloadArtifact(&c.netbirdCache, client.MaxBinaryBytes, digest)
	if c.netbirdCache.file != nil || c.netbirdCache.digest != "" || !time.Now().Before(c.netbirdCache.retryAfter) {
		t.Fatal("oversize NetBird object populated its bounded spool")
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	if err := conn.Barrier(func() { close(finished) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if chunkReads.Load() != 0 {
		t.Fatal("oversize NetBird metadata was allowed to fetch artifact chunks")
	}
}

type canceledCacheStore struct {
	ArtifactStore
	started  chan string
	canceled chan string
}

func (s canceledCacheStore) GetInfo(ctx context.Context, name string, _ ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.started <- name
	<-ctx.Done()
	s.canceled <- name
	return nil, ctx.Err()
}

func TestArtifactCacheCloseCancelsBothDownloads(t *testing.T) {
	c, _, _, _, _ := testController(t)
	defer c.closeCache()
	store := canceledCacheStore{ArtifactStore: c.artifacts, started: make(chan string, 2), canceled: make(chan string, 2)}
	c.artifacts = store
	if _, _, err := c.readArtifactChunk(t.Context(), "workload", 0, artifactChunkBytes); !errors.Is(err, errArtifactPreparing) {
		t.Fatalf("workload download did not start: %v", err)
	}
	if _, _, err := c.readCachedArtifact(t.Context(), &c.netbirdCache, client.MaxBinaryBytes, "netbird", 0, artifactChunkBytes); !errors.Is(err, errArtifactPreparing) {
		t.Fatalf("NetBird download did not start: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 2 {
		select {
		case <-store.started:
		case <-ctx.Done():
			t.Fatal("both bounded downloads did not start")
		}
	}
	c.closeCache()
	for range 2 {
		select {
		case <-store.canceled:
		case <-ctx.Done():
			t.Fatal("cache close did not cancel both in-flight downloads")
		}
	}
}
