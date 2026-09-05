package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func TestSnapshotEnvelopeConfigPreservesLargeIntegerAndRejectsNestedDuplicates(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// This valid retention limit is above float64's exact integer range. The
	// snapshot's restore configuration must retain the server's precise value.
	const maxMessages int64 = 9007199254740993
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage, MaxMsgs: maxMessages, Metadata: map[string]string{"audit": "retained"}}); err != nil {
		t.Fatal(err)
	}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: &snapshotCaptureStore{objects: map[string][]byte{}}, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	inner, response, err := snapshotter.streamSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest := jetStreamSnapshotManifest{Version: 3, Stream: "STATE", Request: SnapshotRequest{RunID: "json", IdempotencyKey: "json", ObjectKey: "json.epoch-1.snapshot", ControlEpoch: 1}, CreatedAt: time.Now().UTC(), Config: response.Config, State: response.State, Consumers: response.Consumers, ArchiveSize: int64(len(inner)), ArchiveSHA256: delivery.SHA256Digest(inner)}
	envelope, err := encodeJetStreamSnapshotEnvelope(manifest, inner, defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, restored, err := decodeJetStreamSnapshotEnvelope(envelope, "STATE", defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	var configuration struct {
		MaxMessages int64 `json:"max_msgs"`
	}
	if err := json.Unmarshal(decoded.Config, &configuration); err != nil || configuration.MaxMessages != maxMessages || !bytes.Equal(restored, inner) {
		t.Fatalf("restore configuration or archive changed: max_msgs=%d error=%v", configuration.MaxMessages, err)
	}
	if !bytes.Contains(decoded.Config, []byte(`"max_msgs":9007199254740993`)) {
		t.Fatalf("integer lost precision: %s", decoded.Config)
	}

	// Rebuild only the outer manifest so duplicate nested fields actually reach
	// the decoder; the production encoder intentionally canonicalizes them.
	for _, first := range []string{"retained", "conflicting"} {
		t.Run(first, func(t *testing.T) {
			var config map[string]json.RawMessage
			if err := json.Unmarshal(decoded.Config, &config); err != nil {
				t.Fatal(err)
			}
			metadata := config["metadata"]
			if len(metadata) == 0 || metadata[0] != '{' {
				t.Fatalf("missing fixture metadata: %s", metadata)
			}
			prefix, err := json.Marshal(map[string]string{"audit": first})
			if err != nil {
				t.Fatal(err)
			}
			config["metadata"] = append(append(append([]byte(nil), prefix[:len(prefix)-1]...), ','), metadata[1:]...)
			changed := decoded
			changed.Config, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(raw, []byte(`"audit":`)) != 2 {
				t.Fatalf("fixture omitted duplicate field: %s", raw)
			}
			var output bytes.Buffer
			writer := tar.NewWriter(&output)
			reader := tar.NewReader(bytes.NewReader(envelope))
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if header.Name == "manifest.json" {
					data = raw
					header.Size = int64(len(data))
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := decodeJetStreamSnapshotEnvelope(output.Bytes(), "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
				t.Fatalf("nested duplicate accepted: %v", err)
			}
		})
	}
}
