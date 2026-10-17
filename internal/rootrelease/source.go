package rootrelease

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type sourceEntry struct {
	wire     []byte
	revision uint64
}

func (e sourceEntry) Value() []byte    { return e.wire }
func (e sourceEntry) Revision() uint64 { return e.revision }

// Fixed root/profile records require the stream leader; a follower's direct KV
// read cannot establish that an old signed authority is still current.
func (s *Sources) current(ctx context.Context, bucket, key string) (sourceEntry, error) {
	if s == nil || s.JS == nil || s.JS.Conn() == nil {
		return sourceEntry{}, ErrPending
	}
	if bucket != "TS_SERVICE_SET" || key != "current" {
		if bucket != "TS_TRUST_ROOTS" || key != "chain" {
			return sourceEntry{}, errors.New("invalid root release source")
		}
	}
	options := s.JS.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := s.JS.Conn().JetStream(opts...)
	if err != nil {
		return sourceEntry{}, err
	}
	subject := "$KV." + bucket + "." + key
	msg, err := reader.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) && bucket == "TS_TRUST_ROOTS" {
		// A deployment with no rotations has no chain record. currentRoots still
		// enforces the independently installed lineage floor before using genesis.
		return sourceEntry{wire: []byte(`{"version":1}`)}, ctx.Err()
	}
	if err != nil {
		return sourceEntry{}, err
	}
	if msg == nil || msg.Subject != subject || msg.Sequence == 0 || len(msg.Data) == 0 || msg.Header.Get("KV-Operation") != "" || msg.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return sourceEntry{}, ErrPending
	}
	return sourceEntry{wire: msg.Data, revision: msg.Sequence}, ctx.Err()
}
