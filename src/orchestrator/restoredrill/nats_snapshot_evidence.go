package restoredrill

import (
	"archive/tar"
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"strings"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/nats-io/nats.go"
)

// SnapshotEnvelopeEvidence exposes only metadata from a fully verified v4
// envelope. It is content evidence, not authorization or proof of source fencing.
type SnapshotEnvelopeEvidence struct {
	Request       SnapshotRequest
	CreatedAt     time.Time
	Stream        string
	StreamCreated time.Time
	Config        jsontext.Value
	State         nats.StreamState
	Consumers     []SnapshotConsumerIdentity
	RecordsSHA256 string
	Archive       []byte
	ArchiveSHA256 string
}

type SnapshotConsumerIdentity struct {
	Name          string
	Created       time.Time
	Durable       string
	MemoryStorage bool
	Config        jsontext.Value
	Checkpoint    *SnapshotConsumerEvidence
}

// InspectSnapshotEnvelope does not restore or open a broker. Returned slices
// are owned by the caller; no mutable validation state is shared with a store.
func InspectSnapshotEnvelope(raw []byte, stream string, maximum int64) (SnapshotEnvelopeEvidence, error) {
	manifest, archive, err := decodeJetStreamSnapshotEnvelope(raw, stream, maximum)
	if err != nil {
		return SnapshotEnvelopeEvidence{}, err
	}
	result := SnapshotEnvelopeEvidence{Request: manifest.Request, CreatedAt: manifest.CreatedAt, Stream: manifest.Stream,
		Config: jsontext.Value(manifest.Config), State: *manifest.State, RecordsSHA256: manifest.RecordsSHA256,
		Archive: archive, ArchiveSHA256: manifest.ArchiveSHA256, Consumers: []SnapshotConsumerIdentity{}}
	indices := map[string]int{}
	for _, c := range manifest.Consumers {
		indices[c.Name] = len(result.Consumers)
		result.Consumers = append(result.Consumers, SnapshotConsumerIdentity{Name: c.Name, Created: c.Created,
			Durable: c.Durable, MemoryStorage: c.MemoryStorage, Checkpoint: c.Checkpoint})
	}
	reader := tar.NewReader(io.LimitReader(s2.NewReader(bytes.NewReader(archive)), maximum*8+1))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
		}
		if header.Name != "meta.inf" && !(strings.HasPrefix(header.Name, "obs/") && strings.HasSuffix(header.Name, "/meta.inf")) {
			continue
		}
		metadata, err := io.ReadAll(io.LimitReader(reader, snapshotManifestMaxBytes+1))
		if err != nil || len(metadata) > snapshotManifestMaxBytes {
			return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
		}
		var fields map[string]jsontext.Value
		if json.Unmarshal(metadata, &fields) != nil {
			return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
		}
		if header.Name == "meta.inf" {
			if json.Unmarshal(fields["Created"], &result.StreamCreated) != nil || result.StreamCreated.IsZero() {
				return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
			}
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(header.Name, "obs/"), "/meta.inf")
		index, found := indices[name]
		if !found {
			return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
		}
		delete(fields, "Name")
		delete(fields, "Created")
		result.Consumers[index].Config, err = json.Marshal(fields)
		if err != nil {
			return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
		}
	}
	if result.StreamCreated.IsZero() {
		return SnapshotEnvelopeEvidence{}, ErrSnapshotVerification
	}
	return result, nil
}
