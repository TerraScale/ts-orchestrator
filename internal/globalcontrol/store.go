package globalcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var (
	ErrNotFound       = errors.New("global record not found")
	ErrConflict       = errors.New("global record compare-and-set conflict")
	ErrStaleRecord    = errors.New("global record generation does not advance")
	ErrNotHomeRegion  = errors.New("global state is writable only in the home region")
	ErrRecordCorrupt  = errors.New("global record is corrupt")
	ErrRosterRequired = errors.New("global directory writes require a region roster")
)

// record is the stored envelope. Epoch is the global authority epoch that
// guarded the write; readers reject a record whose epoch regresses relative
// to the record it replaced.
type record struct {
	Version    int    `json:"version"`
	Kind       Kind   `json:"kind"`
	Key        string `json:"key"`
	Generation uint64 `json:"generation"`
	Epoch      uint64 `json:"epoch"`
	Payload    []byte `json:"payload"`
}

func subject(kind Kind, key string) string { return protocol.GlobalState(string(kind), key) }

// Reader serves global records from the home stream or a regional mirror.
type Reader struct {
	stream jetstream.Stream
}

// Roster returns the current region roster and its stream sequence.
func (r *Reader) Roster(ctx context.Context) (Roster, uint64, error) {
	var roster Roster
	entry, sequence, err := r.read(ctx, KindRoster, RosterKey)
	if err != nil {
		return Roster{}, 0, err
	}
	if err := protocol.DecodeStrict(entry.Payload, &roster, maxRecordBytes); err != nil ||
		roster.Validate() != nil || roster.Generation != entry.Generation {
		return Roster{}, 0, ErrRecordCorrupt
	}
	return roster, sequence, nil
}

// Directory returns a database partition's directory entry.
func (r *Reader) Directory(ctx context.Context, databaseID, partitionID string) (DirectoryEntry, uint64, error) {
	var directory DirectoryEntry
	if !idToken.MatchString(databaseID) || !idToken.MatchString(partitionID) {
		return DirectoryEntry{}, 0, errors.New("directory database and partition must be lowercase tokens")
	}
	key := DirectoryKey(databaseID, partitionID)
	entry, sequence, err := r.read(ctx, KindDirectory, key)
	if err != nil {
		return DirectoryEntry{}, 0, err
	}
	if err := protocol.DecodeStrict(entry.Payload, &directory, maxRecordBytes); err != nil ||
		directory.Validate() != nil || directory.Generation != entry.Generation ||
		directory.DatabaseID != databaseID || directory.PartitionID != partitionID {
		return DirectoryEntry{}, 0, ErrRecordCorrupt
	}
	return directory, sequence, nil
}

func (r *Reader) read(ctx context.Context, kind Kind, key string) (record, uint64, error) {
	if r == nil || r.stream == nil {
		return record{}, 0, errors.New("global control reader is not open")
	}
	readCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	message, err := r.stream.GetLastMsgForSubject(readCtx, subject(kind, key))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return record{}, 0, ErrNotFound
	}
	if err != nil {
		return record{}, 0, err
	}
	var stored record
	if err := protocol.DecodeStrict(message.Data, &stored, maxRecordBytes+4096); err != nil ||
		stored.Version != recordVersion || stored.Kind != kind || stored.Key != key ||
		stored.Generation == 0 || stored.Epoch == 0 {
		return record{}, 0, ErrRecordCorrupt
	}
	return stored, message.Sequence, nil
}

// Writer appends global records in the home region. Every write is guarded
// by the global-scope authority lease immediately before a per-subject
// compare-and-set publish, so a fenced leader cannot overwrite a newer record.
type Writer struct {
	Reader
	home   string
	fencer authority.Fencer
	js     jetstream.JetStream
}

// OpenHome creates or verifies the writable home stream. cell must equal the
// roster home; fencer must be the global-scope authority runtime.
func OpenHome(ctx context.Context, js jetstream.JetStream, cell string, replicas int, fencer authority.Fencer) (*Writer, error) {
	if !cellToken.MatchString(cell) {
		return nil, errors.New("global home cell is invalid")
	}
	if fencer == nil || fencer.Current().Scope != protocol.GlobalScope {
		return nil, errors.New("global writes require the global-scope authority")
	}
	stream, err := openStream(ctx, js, HomeStreamConfig(replicas), func(actual jetstream.StreamConfig) error {
		return verifyHome(actual, replicas)
	})
	if err != nil {
		return nil, err
	}
	return &Writer{Reader: Reader{stream: stream}, home: cell, fencer: fencer, js: js}, nil
}

// PutRoster writes the next roster generation. The home region cannot be
// moved through this path; a home transfer needs an operator-signed envelope.
func (w *Writer) PutRoster(ctx context.Context, epoch uint64, roster Roster) (uint64, error) {
	if err := roster.Validate(); err != nil {
		return 0, err
	}
	if roster.HomeRegion != w.home {
		return 0, ErrNotHomeRegion
	}
	return w.put(ctx, epoch, KindRoster, RosterKey, roster.Generation, roster)
}

// PutDirectory writes the next generation of a partition's directory entry.
// Every active region must be Active in the current roster.
func (w *Writer) PutDirectory(ctx context.Context, epoch uint64, entry DirectoryEntry) (uint64, error) {
	roster, _, err := w.Roster(ctx)
	if errors.Is(err, ErrNotFound) {
		return 0, ErrRosterRequired
	}
	if err != nil {
		return 0, err
	}
	if err := entry.ValidateAgainst(roster); err != nil {
		return 0, err
	}
	return w.put(ctx, epoch, KindDirectory, entry.Key(), entry.Generation, entry)
}

func (w *Writer) put(ctx context.Context, epoch uint64, kind Kind, key string, generation uint64, value any) (uint64, error) {
	if epoch == 0 {
		return 0, authority.ErrFenced
	}
	payload, err := protocol.EncodeJSON(value)
	if err != nil {
		return 0, err
	}
	prior, priorSequence, err := w.read(ctx, kind, key)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return 0, err
	case prior.Generation == generation && bytes.Equal(prior.Payload, payload):
		// An identical retry after an unknown publish outcome is idempotent.
		return priorSequence, nil
	case generation <= prior.Generation:
		return 0, ErrStaleRecord
	case epoch < prior.Epoch:
		return 0, authority.ErrFenced
	}
	data, err := protocol.EncodeJSON(record{
		Version: recordVersion, Kind: kind, Key: key, Generation: generation, Epoch: epoch, Payload: payload,
	})
	if err != nil {
		return 0, err
	}
	if err := w.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	message := nats.NewMsg(subject(kind, key))
	message.Data = data
	publishCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	ack, err := w.js.PublishMsg(publishCtx, message,
		jetstream.WithExpectStream(StreamName),
		jetstream.WithExpectLastSequenceForSubject(priorSequence, subject(kind, key)),
		jetstream.WithMsgID(string(kind)+"."+key+"."+strconv.FormatUint(generation, 10)),
	)
	if err != nil {
		if apiErr, ok := errors.AsType[*jetstream.APIError](err); ok &&
			apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence {
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("publish global %s record: %w", kind, err)
	}
	if ack.Duplicate {
		// The message ID was seen; only an identical stored record is success.
		stored, sequence, readErr := w.read(ctx, kind, key)
		if readErr != nil || stored.Generation != generation || !bytes.Equal(stored.Payload, payload) {
			return 0, ErrConflict
		}
		return sequence, nil
	}
	return ack.Sequence, nil
}
