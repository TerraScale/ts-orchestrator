// Package seatrollout restarts the TerraBase seats of a cell one at a time
// without dropping a request (TS-571): a seat is drained on the public load
// balancer before its host may restart it, and returns to rotation once it
// serves again. This file holds the durable per-seat records that the load
// balancer publisher and the host restart gate read.
package seatrollout

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// Bucket is the replicated KV bucket with one record per seat, keyed by
// node. It is durable so a new leader keeps a seat drained that its
// predecessor drained, instead of returning it to rotation mid-restart.
const Bucket = "TS_TERRABASE_SEATS"

// ErrInvalid reports a malformed or misplaced seat record. Readers fail
// closed on it: no backend set is published and no restart is granted.
var ErrInvalid = errors.New("seat record is invalid")

var nodeRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Seat is one seat's rollout state.
type Seat struct {
	Node string `json:"node"`
	// Drain keeps the seat drained on the public load balancer.
	Drain bool `json:"drain,omitzero"`
	// DrainedAt is when Drain was set; in-flight requests get a grace
	// from it.
	DrainedAt time.Time `json:"drained_at,omitzero"`
	// Permit is the highest desired generation the seat's host may restart
	// its member into.
	Permit uint64 `json:"permit,omitzero"`
	// Epoch is the authority epoch the record was written under.
	Epoch uint64 `json:"epoch"`
}

func (seat Seat) validate() error {
	// A drained seat carries its drain time and an undrained one none.
	if !nodeRE.MatchString(seat.Node) || seat.Epoch == 0 || seat.Drain != !seat.DrainedAt.IsZero() {
		return fmt.Errorf("%w: seat %q", ErrInvalid, seat.Node)
	}
	return nil
}

// Store reads and writes seat records. Every write is guarded by the
// authority epoch it carries and compare-and-set on the record's revision.
type Store struct {
	*Reader
	fencer authority.Fencer
}

// Reader observes existing seat records without mutation or restart authority.
type Reader struct {
	kv     jetstream.KeyValue
	leader nats.JetStreamContext
}

// OpenReader binds only the existing durable seat bucket; it never provisions it.
func OpenReader(ctx context.Context, js jetstream.JetStream) (*Reader, error) {
	if js == nil || js.Conn() == nil {
		return nil, fmt.Errorf("%w: seat reader configuration", ErrInvalid)
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		return nil, fmt.Errorf("open existing seat store: %w", err)
	}
	return openReader(ctx, js, kv)
}

func openReader(ctx context.Context, js jetstream.JetStream, kv jetstream.KeyValue) (*Reader, error) {
	status, err := kv.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect seat store: %w", err)
	}
	config := status.Config()
	if kv.Bucket() != Bucket || status.Bucket() != Bucket || config.Bucket != Bucket || config.Storage != jetstream.FileStorage || config.TTL != 0 || config.History != 4 || config.MaxValueSize != 4<<10 || config.Replicas != 1 && config.Replicas != 3 && config.Replicas != 5 {
		return nil, fmt.Errorf("%w: existing seat store durability or identity", ErrInvalid)
	}
	options := js.Options()
	legacyOptions := []nats.JSOpt{nats.APIPrefix(options.APIPrefix), nats.MaxWait(options.DefaultTimeout)}
	if options.Domain != "" {
		legacyOptions = append(legacyOptions, nats.Domain(options.Domain))
	}
	leader, err := js.Conn().JetStream(legacyOptions...)
	if err != nil {
		return nil, fmt.Errorf("open ordered seat reader: %w", err)
	}
	return &Reader{kv: kv, leader: leader}, nil
}

// Open provisions or binds the seat bucket.
func Open(ctx context.Context, js jetstream.JetStream, replicas int, fencer authority.Fencer) (*Store, error) {
	if js == nil || js.Conn() == nil || fencer == nil || replicas != 1 && replicas != 3 && replicas != 5 {
		return nil, fmt.Errorf("%w: seat store configuration", ErrInvalid)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Storage: jetstream.FileStorage, Replicas: replicas, History: 4, MaxValueSize: 4 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("seat store: %w", err)
	}
	reader, err := openReader(ctx, js, kv)
	if err != nil {
		return nil, err
	}
	return &Store{Reader: reader, fencer: fencer}, nil
}

// Get returns node's record and its revision; a seat without a record is
// neither drained nor permitted (revision zero).
func (s *Reader) Get(ctx context.Context, node string) (Seat, uint64, error) {
	if !nodeRE.MatchString(node) {
		return Seat{}, 0, fmt.Errorf("%w: seat %q", ErrInvalid, node)
	}
	subject := "$KV." + Bucket + "." + node
	// Drain decisions must observe the leader, never a potentially stale replica.
	entry, err := s.leader.GetLastMsg("KV_"+Bucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return Seat{Node: node}, 0, nil
	}
	if err != nil {
		return Seat{}, 0, fmt.Errorf("read seat %s: %w", node, err)
	}
	if entry == nil || entry.Subject != subject || entry.Sequence == 0 || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return Seat{}, 0, fmt.Errorf("%w: malformed or deleted seat %s", ErrInvalid, node)
	}
	var seat Seat
	if err := json.Unmarshal(entry.Data, &seat, json.RejectUnknownMembers(true)); err != nil {
		return Seat{}, 0, fmt.Errorf("%w: seat %s: %v", ErrInvalid, node, err)
	}
	if err := seat.validate(); err != nil || seat.Node != node {
		return Seat{}, 0, fmt.Errorf("%w: seat %s holds %q", ErrInvalid, node, seat.Node)
	}
	return seat, entry.Sequence, nil
}

// Put writes seat at revision (zero creates it) after checking its epoch
// still holds authority, and returns the new revision.
func (s *Store) Put(ctx context.Context, seat Seat, revision uint64) (uint64, error) {
	if err := seat.validate(); err != nil {
		return 0, err
	}
	wire, err := json.Marshal(seat)
	if err != nil {
		return 0, err
	}
	if err := s.fencer.Guard(ctx, seat.Epoch); err != nil {
		return 0, err
	}
	if revision == 0 {
		return s.kv.Create(ctx, seat.Node, wire)
	}
	return s.kv.Update(ctx, seat.Node, wire, revision)
}

// Drained returns the seats held drained.
func (s *Reader) Drained(ctx context.Context) (map[string]bool, error) {
	keys, err := s.kv.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list seats: %w", err)
	}
	defer keys.Stop()
	drained := map[string]bool{}
	for node := range keys.Keys() {
		seat, _, err := s.Get(ctx, node)
		if err != nil {
			return nil, err
		}
		if seat.Drain {
			drained[node] = true
		}
	}
	return drained, nil
}

// Granted is the host restart gate: a static TerraBase member restarts only
// into a desired generation its seat permits. Every other role restarts
// freely.
func (s *Store) Granted(ctx context.Context, node string, desired host.Desired) (bool, error) {
	if desired.Role != terrabase.Role {
		return true, nil
	}
	seat, _, err := s.Get(ctx, node)
	if err != nil {
		return false, err
	}
	return desired.Generation <= seat.Permit, nil
}
