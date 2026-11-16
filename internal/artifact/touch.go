package artifact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ErrChanged refuses a metadata write because the object's metadata moved
// on since it was read, for example a Touch by a new reference.
var ErrChanged = errors.New("artifact metadata changed")

// Touch republishes an object's metadata unchanged, as a compare-and-set on
// its metadata subject read from the stream leader. Every new reference to
// an object (a desired commit, an admission) touches it first: a collector
// that read the older metadata can then no longer delete it
// (DeleteIfUnchanged), whatever the collector's process does meanwhile, and
// the newer time keeps the object within the collector's grace. It fails
// with jetstream.ErrObjectNotFound once the object is absent or deleted.
func Touch(ctx context.Context, js nats.JetStreamContext, bucket, name string) error {
	subject := metaSubject(bucket, name)
	meta, err := liveMeta(ctx, js, bucket, subject, name)
	if err != nil {
		return err
	}
	err = publishMeta(ctx, js, subject, meta.Data, meta.Sequence)
	if !errors.Is(err, ErrChanged) {
		return err
	}
	// Another write since the read fences a collector just the same,
	// unless it deleted the object.
	_, err = liveMeta(ctx, js, bucket, subject, name)
	return err
}

// liveMeta reads an object's metadata from the stream leader and refuses a
// deleted object.
func liveMeta(ctx context.Context, js nats.JetStreamContext, bucket, subject, name string) (*nats.RawStreamMsg, error) {
	meta, err := js.GetLastMsg("OBJ_"+bucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, jetstream.ErrObjectNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read artifact metadata: %w", err)
	}
	var info jetstream.ObjectInfo
	if err := json.Unmarshal(meta.Data, &info); err != nil || info.Name != name {
		return nil, fmt.Errorf("%w: artifact object metadata", ErrInvalid)
	}
	if info.Deleted {
		return nil, jetstream.ErrObjectNotFound
	}
	return meta, nil
}

func metaSubject(bucket, name string) string {
	return "$O." + bucket + ".M." + base64.URLEncoding.EncodeToString([]byte(name))
}

func publishMeta(ctx context.Context, js nats.JetStreamContext, subject string, data []byte, sequence uint64) error {
	msg := nats.NewMsg(subject)
	msg.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
	msg.Data = data
	_, err := js.PublishMsg(msg, nats.Context(ctx), nats.ExpectLastSequencePerSubject(sequence))
	if apiErr, ok := errors.AsType[*nats.APIError](err); ok && (apiErr.ErrorCode == nats.JSErrCodeStreamWrongLastSequence ||
		apiErr.ErrorCode == nats.JSErrCodeStreamWrongLastSequenceConstant) {
		return ErrChanged
	}
	return err
}
