package globalcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

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
	// ErrMirrorGap means a regional mirror is missing home records. The home
	// stream never loses a record (no deletes, purges or limits), so a gap
	// means the mirror's durable consumer was reset past records the mirror
	// had not stored, for example by a compromised leaf credential of that
	// region sending a forward reset. The mirror fails closed rather than serve a record that
	// a skipped one may have superseded; recreate the mirror to recover.
	ErrMirrorGap = errors.New("global mirror is missing home records")
	// ErrMirrorNotCaughtUp means an empty regional mirror has not yet
	// confirmed with the home stream that there is nothing to copy.
	ErrMirrorNotCaughtUp = errors.New("global mirror has not caught up with the home stream")
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
	// mirror makes every read prove that the mirror holds a gap-free prefix
	// of the home stream (see ErrMirrorGap).
	mirror bool
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
	if !entityid.Valid(databaseID) || !entityid.Valid(partitionID) {
		return DirectoryEntry{}, 0, errors.New("directory database and partition must be canonical ULIDs")
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
	if r.mirror && (err == nil || errors.Is(err, jetstream.ErrMsgNotFound)) {
		// Checked after the read: no gap up to the mirror's last sequence
		// now means no newer record for this subject was skipped before it.
		if gapErr := r.checkMirrorGapFree(readCtx); gapErr != nil {
			return record{}, 0, gapErr
		}
	}
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return record{}, 0, ErrNotFound
	}
	if err != nil {
		return record{}, 0, err
	}
	var stored record
	if err := protocol.DecodeStrict(message.Data, &stored, maxMessageBytes); err != nil ||
		stored.Version != recordVersion || stored.Kind != kind || stored.Key != key ||
		stored.Generation == 0 || stored.Epoch == 0 {
		return record{}, 0, ErrRecordCorrupt
	}
	if !epochHeaderMatches(message.Header, stored.Epoch) {
		return record{}, 0, ErrRecordCorrupt
	}
	return stored, message.Sequence, nil
}

// checkMirrorGapFree requires the mirror to hold every home sequence from 1
// to its last one. Skipped sequences show up as deleted messages or as a
// first sequence beyond 1.
func (r *Reader) checkMirrorGapFree(ctx context.Context) error {
	info, err := r.stream.Info(ctx)
	if err != nil {
		return fmt.Errorf("inspect global mirror: %w", err)
	}
	state := info.State
	if state.LastSeq == 0 {
		// An empty mirror proves nothing until it has heard from the home
		// stream and has nothing left to copy: before its first contact
		// (initial catch-up, or a home that never created this region's
		// mirror consumer) "not found" would be a guess.
		if mirror := info.Mirror; mirror == nil || mirror.Active < 0 || mirror.Lag != 0 {
			return ErrMirrorNotCaughtUp
		}
		return nil
	}
	if state.NumDeleted != 0 || state.FirstSeq != 1 || state.Msgs != state.LastSeq {
		return ErrMirrorGap
	}
	return nil
}

// EpochHeader carries the global authority epoch of every record the writer
// appends, term barriers included. It must equal the epoch in the record
// body; a reader treats a mismatch as corruption.
const EpochHeader = "Ts-Global-Epoch"

// termKey is the single key of the term barrier record.
const termKey = "current"

// maxAppendAttempts bounds compare-and-set retries against concurrent appends.
const maxAppendAttempts = 8

// epochHeaderMatches accepts a record whose epoch header equals its body. A
// record without the header was not appended by a Writer.
func epochHeaderMatches(header nats.Header, epoch uint64) bool {
	return header.Get(EpochHeader) == strconv.FormatUint(epoch, 10)
}

// term is the payload of the barrier record a new global leader appends to
// TS_GLOBAL_CONTROL before its first write.
type term struct {
	Epoch uint64 `json:"epoch"`
}

// Writer appends global records in the home region.
//
// Fencing is enforced by the server, not only by the pre-publish lease
// Guard: the global stream and the authority lease live in different streams,
// so a Guard alone cannot order a write against a newer term. The writer
// therefore keeps a term barrier inside TS_GLOBAL_CONTROL itself
// (ts.global.v1.term.current). A writer whose lease epoch is newer than the
// stored term first appends a barrier for its epoch (per-subject CAS on the
// term subject, and only right after a successful lease Guard), and every
// record append is a whole-stream compare-and-set on the last sequence at
// which the writer saw its own epoch as the current term, plus the
// per-subject CAS on the record. Once a new leader appends its barrier, every
// in-flight append of an older leader fails with a wrong-last-sequence error,
// and its retry observes the newer term and returns authority.ErrFenced. An
// old leader that commits before the new barrier is ordered before the new
// term, which reads every record after its own barrier.
type Writer struct {
	Reader
	home   string
	fencer authority.Fencer
	js     jetstream.JetStream
	// replicas is the replica count OpenHome verified; every append
	// re-verifies the stream against it, so later drift is detected.
	replicas int
	mu       sync.Mutex
	// beforePublish runs between the fenced reads and the conditional
	// append; tests use it to interleave a new term.
	beforePublish func()
}

// OpenHome creates or verifies the writable home stream and the durable
// mirror consumer of every peer that mirrors it. cell must equal the roster
// home; fencer must be the global-scope authority runtime. Mirror consumers of
// regions that are no longer peers are deleted.
func OpenHome(ctx context.Context, js jetstream.JetStream, cell string, peers []string, replicas int,
	fencer authority.Fencer,
) (*Writer, error) {
	if !cellToken.MatchString(cell) {
		return nil, errors.New("global home cell is invalid")
	}
	for _, peer := range peers {
		if !cellToken.MatchString(peer) || peer == protocol.GlobalScope || peer == cell {
			return nil, fmt.Errorf("global mirror peer %q is invalid", peer)
		}
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
	if err := ensureMirrorConsumers(ctx, stream, peers, replicas); err != nil {
		return nil, err
	}
	if err := removeStaleMirrorConsumers(ctx, stream, peers); err != nil {
		return nil, err
	}
	return &Writer{Reader: Reader{stream: stream}, home: cell, fencer: fencer, js: js, replicas: replicas}, nil
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
	payload, err := protocol.EncodeJSON(roster)
	if err != nil {
		return 0, err
	}
	return w.put(ctx, epoch, KindRoster, RosterKey, roster.Generation, payload, nil)
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
	payload, err := protocol.EncodeJSON(entry)
	if err != nil {
		return 0, err
	}
	return w.put(ctx, epoch, KindDirectory, entry.Key(), entry.Generation, payload, nil)
}

// Fence appends the term barrier for epoch unless the stream already holds
// it. A new global leader calls it eagerly so that no older leader can append
// once it returns; every write also establishes the term first.
func (w *Writer) Fence(ctx context.Context, epoch uint64) error {
	if epoch == 0 {
		return authority.ErrFenced
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err := w.establishTerm(ctx, epoch)
	return err
}

// Term returns the epoch of the latest term barrier, or 0 before the first.
func (r *Reader) Term(ctx context.Context) (uint64, error) {
	if r == nil || r.stream == nil {
		return 0, errors.New("global control reader is not open")
	}
	readCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	epoch, _, err := readTerm(readCtx, r.stream)
	if err == nil && r.mirror {
		// Like every mirror read: a mirror missing home records may also
		// miss a newer barrier, so it fails closed.
		if gapErr := r.checkMirrorGapFree(readCtx); gapErr != nil {
			return 0, gapErr
		}
	}
	return epoch, err
}

func readTerm(ctx context.Context, stream jetstream.Stream) (uint64, uint64, error) {
	message, err := stream.GetLastMsgForSubject(ctx, subject(KindTerm, termKey))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	var stored record
	var barrier term
	if err := protocol.DecodeStrict(message.Data, &stored, maxMessageBytes); err != nil ||
		stored.Version != recordVersion || stored.Kind != KindTerm || stored.Key != termKey ||
		stored.Epoch == 0 || stored.Generation != stored.Epoch || !epochHeaderMatches(message.Header, stored.Epoch) ||
		protocol.DecodeStrict(stored.Payload, &barrier, 1024) != nil || barrier.Epoch != stored.Epoch {
		return 0, 0, ErrRecordCorrupt
	}
	return stored.Epoch, message.Sequence, nil
}

// establishTerm makes epoch the stored term and returns a stream last
// sequence at which it was current. The caller holds w.mu and has just
// guarded epoch against the authority lease.
func (w *Writer) establishTerm(ctx context.Context, epoch uint64) (uint64, error) {
	for range maxAppendAttempts {
		readCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		info, err := w.stream.Info(readCtx)
		if err != nil {
			cancel()
			return 0, fmt.Errorf("read global stream sequence: %w", err)
		}
		if err := verifyHome(info.Config, w.replicas); err != nil {
			cancel()
			return 0, err
		}
		current, termSequence, err := readTerm(readCtx, w.stream)
		cancel()
		if err != nil {
			return 0, fmt.Errorf("read global term: %w", err)
		}
		if termSequence > info.State.LastSeq {
			continue
		}
		switch {
		case current == epoch:
			return info.State.LastSeq, nil
		case current > epoch:
			return 0, authority.ErrFenced
		}
		payload, err := protocol.EncodeJSON(term{Epoch: epoch})
		if err != nil {
			return 0, err
		}
		data, err := protocol.EncodeJSON(record{
			Version: recordVersion, Kind: KindTerm, Key: termKey, Generation: epoch, Epoch: epoch, Payload: payload,
		})
		if err != nil {
			return 0, err
		}
		message := nats.NewMsg(subject(KindTerm, termKey))
		message.Data = data
		message.Header.Set(EpochHeader, strconv.FormatUint(epoch, 10))
		publishCtx, publishCancel := context.WithTimeout(ctx, apiTimeout)
		_, err = w.js.PublishMsg(publishCtx, message,
			jetstream.WithExpectStream(StreamName),
			jetstream.WithExpectLastSequenceForSubject(termSequence, subject(KindTerm, termKey)),
		)
		publishCancel()
		if err != nil && !wrongLastSequence(err) {
			return 0, fmt.Errorf("publish global term barrier: %w", err)
		}
		// Re-read: our barrier or a concurrent newer one is now current.
	}
	return 0, ErrConflict
}

// wrongLastSequence reports a failed sequence expectation. The server also
// answers the per-subject expectation with the "constant" variant when the
// subject is in flight in a batch, which is the same concurrent-writer race.
func wrongLastSequence(err error) bool {
	apiErr, ok := errors.AsType[*jetstream.APIError](err)
	return ok && (apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
		apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant)
}

// put appends payload as the record's next generation. Generation 0 means
// the stored generation plus one: an identical payload is then a retry, and
// any other payload is the next generation. admit, when set, may refuse
// the write after seeing the stored payload the append is conditional on.
func (w *Writer) put(ctx context.Context, epoch uint64, kind Kind, key string, generation uint64, payload []byte,
	admit func(prior []byte) error,
) (uint64, error) {
	if epoch == 0 {
		return 0, authority.ErrFenced
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	for range maxAppendAttempts {
		lastSequence, err := w.establishTerm(ctx, epoch)
		if err != nil {
			return 0, err
		}
		next := max(generation, 1)
		prior, priorSequence, err := w.read(ctx, kind, key)
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return 0, err
		case priorSequence > lastSequence:
			continue
		case (generation == 0 || prior.Generation == generation) && bytes.Equal(prior.Payload, payload):
			// An identical retry after an unknown publish outcome is idempotent.
			return priorSequence, nil
		case generation == 0:
			next = prior.Generation + 1
		case generation <= prior.Generation:
			return 0, ErrStaleRecord
		}
		if epoch < prior.Epoch {
			return 0, authority.ErrFenced
		}
		if admit != nil {
			if err := admit(prior.Payload); err != nil {
				return 0, err
			}
		}
		data, err := protocol.EncodeJSON(record{
			Version: recordVersion, Kind: kind, Key: key, Generation: next, Epoch: epoch, Payload: payload,
		})
		if err != nil {
			return 0, err
		}
		if w.beforePublish != nil {
			w.beforePublish()
		}
		message := nats.NewMsg(subject(kind, key))
		message.Data = data
		message.Header.Set(EpochHeader, strconv.FormatUint(epoch, 10))
		publishCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		ack, err := w.js.PublishMsg(publishCtx, message,
			jetstream.WithExpectStream(StreamName),
			jetstream.WithExpectLastSequence(lastSequence),
			jetstream.WithExpectLastSequenceForSubject(priorSequence, subject(kind, key)),
			jetstream.WithMsgID(string(kind)+"."+key+"."+strconv.FormatUint(next, 10)),
		)
		cancel()
		if wrongLastSequence(err) {
			// Another append won: a newer term barrier or a concurrent write.
			// The next attempt observes it and fences or re-checks the CAS.
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("publish global %s record: %w", kind, err)
		}
		if ack.Duplicate {
			// The message ID was seen; only an identical stored record is success.
			stored, sequence, readErr := w.read(ctx, kind, key)
			if readErr != nil || stored.Generation != next || !bytes.Equal(stored.Payload, payload) {
				return 0, ErrConflict
			}
			return sequence, nil
		}
		return ack.Sequence, nil
	}
	return 0, ErrConflict
}
