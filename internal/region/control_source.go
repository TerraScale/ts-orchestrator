package region

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	controlRootsBucket = "TS_TRUST_ROOTS"
	controlRootsKey    = "chain"
	controlSpecBucket  = "TS_SERVICE_SET"
	controlSpecKey     = "current"
)

type controlSource struct {
	created  time.Time
	revision uint64
	wire     []byte
}

func (source controlSource) same(other controlSource) bool {
	return source.created.Equal(other.created) && source.revision == other.revision && bytes.Equal(source.wire, other.wire)
}

// Fixed public keys use leader MSG.GET, never a follower's direct KV cache.
// The surrounding stream observations fence replacement and concurrent writes.
func observeControlSource(ctx context.Context, runtime *natscell.Runtime, bucket, key string) (controlSource, error) {
	if runtime == nil || runtime.JetStream() == nil || runtime.Conn() == nil ||
		(bucket != controlRootsBucket || key != controlRootsKey) && (bucket != controlSpecBucket || key != controlSpecKey) {
		return controlSource{}, errors.New("regional public source requires its concrete broker and fixed key")
	}
	js := runtime.JetStream()
	stream, err := js.Stream(ctx, "KV_"+bucket)
	if err != nil {
		return controlSource{}, err
	}
	subject := "$KV." + bucket + "." + key
	before, err := stream.Info(ctx, jetstream.WithSubjectFilter(subject), jetstream.WithDeletedDetails(true))
	if err != nil {
		return controlSource{}, err
	}
	if err := validateControlStream(before, bucket); err != nil {
		return controlSource{}, err
	}
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := runtime.Conn().JetStream(opts...)
	if err != nil {
		return controlSource{}, err
	}
	message, readErr := reader.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if readErr != nil && !errors.Is(readErr, nats.ErrMsgNotFound) {
		return controlSource{}, readErr
	}
	after, err := stream.Info(ctx, jetstream.WithSubjectFilter(subject), jetstream.WithDeletedDetails(true))
	if err != nil {
		return controlSource{}, err
	}
	if err := validateControlStream(after, bucket); err != nil {
		return controlSource{}, err
	}
	if !before.Created.Equal(after.Created) || before.Cluster.Leader != after.Cluster.Leader || !reflect.DeepEqual(before.State, after.State) {
		return controlSource{}, errors.New("regional public source changed while reading its leader")
	}
	source := controlSource{created: after.Created}
	if errors.Is(readErr, nats.ErrMsgNotFound) {
		if after.State.Subjects[subject] != 0 {
			return controlSource{}, errors.New("regional public source disappeared from a nonempty key")
		}
		return source, ctx.Err()
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 || message.Sequence < after.State.FirstSeq || message.Sequence > after.State.LastSeq ||
		slices.Contains(after.State.Deleted, message.Sequence) || after.State.Subjects[subject] == 0 || len(message.Data) == 0 ||
		message.Header.Get("KV-Operation") != "" || message.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return controlSource{}, errors.New("regional public source is deleted, empty or outside its retained stream")
	}
	source.revision, source.wire = message.Sequence, bytes.Clone(message.Data)
	return source, ctx.Err()
}

func validateControlStream(info *jetstream.StreamInfo, bucket string) error {
	if info == nil {
		return errors.New("regional public source has no stream identity")
	}
	cfg := info.Config
	if info.Created.IsZero() || cfg.Name != "KV_"+bucket || !slices.Equal(cfg.Subjects, []string{"$KV." + bucket + ".>"}) ||
		cfg.Storage != jetstream.FileStorage || cfg.Replicas != 3 || cfg.Retention != jetstream.LimitsPolicy || cfg.MaxAge != 0 || cfg.MaxMsgsPerSubject != 4 ||
		!cfg.DenyDelete || !cfg.AllowRollup || cfg.SubjectTransform != nil || len(cfg.Sources) != 0 || cfg.Mirror != nil ||
		info.Cluster == nil || info.Cluster.Leader == "" || len(info.State.Deleted) != info.State.NumDeleted {
		return errors.New("regional public source differs from its fixed retained stream contract")
	}
	return nil
}
