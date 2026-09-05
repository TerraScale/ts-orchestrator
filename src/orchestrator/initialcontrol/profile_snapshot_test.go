package initialcontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

type profileSnapshotStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (s *profileSnapshotStore) Put(_ context.Context, region, bucket, key string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	location := region + "/" + bucket + "/" + key
	if existing, ok := s.objects[location]; ok && !bytes.Equal(existing, body) {
		return errors.New("snapshot object is immutable")
	}
	s.objects[location] = append([]byte(nil), body...)
	return nil
}
func (s *profileSnapshotStore) GetSnapshot(_ context.Context, region, bucket, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.objects[region+"/"+bucket+"/"+key]
	return append([]byte(nil), body...), ok, nil
}
func (s *profileSnapshotStore) Head(ctx context.Context, region, bucket, key string) (delivery.ObjectIdentity, bool, error) {
	body, ok, err := s.GetSnapshot(ctx, region, bucket, key)
	if err != nil || !ok {
		return delivery.ObjectIdentity{}, ok, err
	}
	return delivery.ObjectIdentity{Digest: delivery.SHA256Digest(body), Size: int64(len(body)), ETag: "profile-snapshot"}, true, nil
}

func profilePromotionBackup(t *testing.T, ctx context.Context, nc *nats.Conn, name string) profilePromotionArchive {
	t.Helper()
	const maximum = 16 << 20
	store := &profileSnapshotStore{objects: map[string][]byte{}}
	snapshotter, err := restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{Connection: nc, Stream: name, Store: store, Region: "gru", Bucket: "control-snapshots", MaxBytes: maximum, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := restoredrill.SnapshotRequest{RunID: "profile-promotion", IdempotencyKey: "profile-promotion", ObjectKey: "jetstream/control/profile-promotion." + name + ".epoch-1.snapshot", ControlEpoch: 1}
	identity, err := snapshotter.Snapshot(ctx, request)
	if err != nil {
		t.Fatalf("production snapshot %s: %v", name, err)
	}
	if retry, err := snapshotter.Snapshot(ctx, request); err != nil || retry != identity {
		t.Fatalf("production snapshot retry %s: %+v %v", name, retry, err)
	}
	envelope, found, err := store.GetSnapshot(ctx, "gru", "control-snapshots", request.ObjectKey)
	if err != nil || !found || int64(len(envelope)) != identity.Size || delivery.SHA256Digest(envelope) != identity.Checksum || len(envelope) > maximum {
		t.Fatalf("snapshot object identity %s: %+v %v", name, identity, err)
	}
	// Decode the documented storage format only in this integration fixture.
	// The production snapshotter has already validated and read back the object;
	// these checks independently bind exactly what the restore protocol receives.
	var manifest struct {
		Version       int                          `json:"version"`
		Stream        string                       `json:"stream"`
		Request       restoredrill.SnapshotRequest `json:"request"`
		CreatedAt     time.Time                    `json:"createdAt"`
		Config        json.RawMessage              `json:"config"`
		State         json.RawMessage              `json:"state"`
		Consumers     json.RawMessage              `json:"consumers"`
		ArchiveSHA256 string                       `json:"archiveSha256"`
		ArchiveSize   int64                        `json:"archiveSize"`
	}
	reader := tar.NewReader(bytes.NewReader(envelope))
	var canonical bytes.Buffer
	writer := tar.NewWriter(&canonical)
	var inner []byte
	for _, entry := range []string{"manifest.json", "stream.snapshot"} {
		header, err := reader.Next()
		if err != nil || header.Name != entry || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maximum {
			t.Fatalf("snapshot envelope entry %s: %+v %v", entry, header, err)
		}
		raw, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(raw)) != header.Size {
			t.Fatalf("snapshot entry body: %v", err)
		}
		if entry == "manifest.json" {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				t.Fatal("invalid snapshot manifest")
			}
			encoded, err := json.Marshal(manifest)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatal("noncanonical snapshot manifest")
			}
		} else {
			inner = raw
		}
		if err := writer.WriteHeader(&tar.Header{Name: entry, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("extra snapshot envelope entry: %v", err)
	}
	if err := writer.Close(); err != nil || !bytes.Equal(canonical.Bytes(), envelope) {
		t.Fatal("noncanonical or trailing snapshot envelope data")
	}
	if manifest.Version != 2 || manifest.Stream != name || manifest.Request != request || !manifest.CreatedAt.Equal(identity.CreatedAt) || manifest.ArchiveSize != int64(len(inner)) || manifest.ArchiveSHA256 != delivery.SHA256Digest(inner) {
		t.Fatalf("snapshot manifest differs from receipt: %+v", manifest)
	}
	var config server.StreamConfig
	var state server.StreamState
	for _, field := range []struct {
		raw    []byte
		target any
	}{{manifest.Config, &config}, {manifest.State, &state}} {
		decoder := json.NewDecoder(bytes.NewReader(field.raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(field.target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			t.Fatal("invalid snapshot restore configuration/state")
		}
	}
	if config.Name != name {
		t.Fatal("snapshot stream identity changed")
	}
	return profilePromotionArchive{config: config, state: state, data: inner, envelope: envelope}
}
