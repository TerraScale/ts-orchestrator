package globalcontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var (
	ErrNotFound = errors.New("global record not found")

	ErrRecordCorrupt = errors.New("global record is corrupt")

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

// Reader serves global records from the home stream or a regional mirror.
type Reader struct {
	stream jetstream.Stream
	// js reads the stream's info through a fresh handle: Info on stream
	// would rewrite the handle's cached info, which concurrent reads use.
	js jetstream.JetStream
	// mirror makes every read prove that the mirror holds a gap-free prefix
	// of the home stream (see ErrMirrorGap).
	mirror bool
}

const EpochHeader = "Ts-Global-Epoch"

type Writer struct {
	Reader
	home          string
	fencer        authority.Fencer
	replicas      int
	mu            sync.Mutex
	beforePublish func()
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

func subject(kind Kind, key string) string { return protocol.GlobalState(string(kind), key) }

// checkMirrorGapFree requires the mirror to hold every home sequence from 1
// to its last one. Skipped sequences show up as deleted messages or as a
// first sequence beyond 1.
func (r *Reader) checkMirrorGapFree(ctx context.Context) error {
	info, err := r.info(ctx)
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

// epochHeaderMatches accepts a record whose epoch header equals its body. A
// record without the header was not appended by a Writer.
func epochHeaderMatches(header nats.Header, epoch uint64) bool {
	return header.Get(EpochHeader) == strconv.FormatUint(epoch, 10)
}

func (r *Reader) info(ctx context.Context) (*jetstream.StreamInfo, error) {
	stream, err := r.js.Stream(ctx, r.stream.CachedInfo().Config.Name)
	if err != nil {
		return nil, err
	}
	return stream.CachedInfo(), nil
}
