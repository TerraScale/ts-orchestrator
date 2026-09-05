package restoredrill

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// Object Storage contains this versioned envelope, not a bare NATS archive.
// Restore clients must validate the manifest, then send Config/State to
// STREAM.RESTORE and stream the exact inner stream.snapshot bytes. The outer
// object digest binds the original request, creation time and restore metadata.
type jetStreamSnapshotManifest struct {
	RecordsSHA256 string                 `json:"recordsSha256"`
	Version       int                    `json:"version"`
	Stream        string                 `json:"stream"`
	Request       SnapshotRequest        `json:"request"`
	CreatedAt     time.Time              `json:"createdAt"`
	Config        json.RawMessage        `json:"config"`
	State         *natsSnapshotState     `json:"state"`
	Consumers     []natsSnapshotConsumer `json:"consumers"`
	ArchiveSHA256 string                 `json:"archiveSha256"`
	ArchiveSize   int64                  `json:"archiveSize"`
}

const snapshotManifestMaxBytes = 1 << 20

func encodeJetStreamSnapshotEnvelope(manifest jetStreamSnapshotManifest, archive []byte, maximum int64) ([]byte, error) {
	config, err := canonicalSnapshotJSON(manifest.Config)
	if err != nil {
		return nil, ErrSnapshotVerification
	}
	manifest.Config = config
	metadata, err := json.Marshal(manifest)
	if err != nil || len(metadata) > snapshotManifestMaxBytes || int64(len(metadata))+int64(len(archive))+2048 > maximum {
		return nil, ErrSnapshotVerification
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", metadata}, {"stream.snapshot", archive}} {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return nil, ErrSnapshotVerification
		}
		if _, err := writer.Write(entry.data); err != nil {
			return nil, ErrSnapshotVerification
		}
	}
	if writer.Close() != nil || int64(buffer.Len()) > maximum {
		return nil, ErrSnapshotVerification
	}
	return buffer.Bytes(), nil
}

func decodeJetStreamSnapshotEnvelope(data []byte, stream string, maximum int64) (jetStreamSnapshotManifest, []byte, error) {
	fail := func() (jetStreamSnapshotManifest, []byte, error) {
		return jetStreamSnapshotManifest{}, nil, ErrSnapshotVerification
	}
	if len(data) == 0 || int64(len(data)) > maximum {
		return fail()
	}
	archive := tar.NewReader(bytes.NewReader(data))
	var manifest jetStreamSnapshotManifest
	var body []byte
	for index, name := range []string{"manifest.json", "stream.snapshot"} {
		header, err := archive.Next()
		if err != nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maximum || (index == 0 && header.Size > snapshotManifestMaxBytes) {
			return fail()
		}
		entry, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(entry)) != header.Size {
			return fail()
		}
		if index == 0 {
			decoder := json.NewDecoder(bytes.NewReader(entry))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				return fail()
			}
		} else {
			body = entry
		}
	}
	if _, err := archive.Next(); err != io.EOF {
		return fail()
	}
	if manifest.Version != 4 || !snapshotRecordDigestValid(manifest.RecordsSHA256) || manifest.Stream != stream || manifest.CreatedAt.IsZero() || manifest.State == nil || manifest.ArchiveSize != int64(len(body)) || !snapshotSHA256Pattern.MatchString(manifest.ArchiveSHA256) || !delivery.SameDigest(manifest.ArchiveSHA256, delivery.SHA256Digest(body)) {
		return fail()
	}
	// Comparing the canonical envelope also rejects duplicate JSON fields,
	// alternate tar headers, extra entries, padding and trailing bytes.
	canonical, err := encodeJetStreamSnapshotEnvelope(manifest, body, maximum)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	if err := validateJetStreamSnapshot(body, stream, maximum, manifest.Config, manifest.State, manifest.Consumers); err != nil {
		return fail()
	}
	return manifest, body, nil
}

func canonicalSnapshotJSON(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrSnapshotVerification
	}
	return json.Marshal(value)
}
