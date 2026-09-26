package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type startupInfoStream struct {
	jetstream.Stream
	infoCalls int
	info      func(context.Context, int) (*jetstream.StreamInfo, error)
}

func (stream *startupInfoStream) Info(ctx context.Context, _ ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	stream.infoCalls++
	return stream.info(ctx, stream.infoCalls)
}

type startupInfoJetStream struct {
	jetstream.JetStream
	stream      *startupInfoStream
	createErr   error
	createCalls int
	lookupCalls int
}

func (js *startupInfoJetStream) CreateStream(context.Context, jetstream.StreamConfig) (jetstream.Stream, error) {
	js.createCalls++
	if js.createErr != nil {
		return nil, js.createErr
	}
	return js.stream, nil
}

func (js *startupInfoJetStream) Stream(context.Context, string) (jetstream.Stream, error) {
	js.lookupCalls++
	return js.stream, nil
}

func TestOpenControlStreamWaitsForPostCreateMetadataVisibility(t *testing.T) {
	missing := &jetstream.APIError{Code: 404, ErrorCode: jetstream.JSErrCodeStreamNotFound,
		Description: "stream not found while metadata leader converges"}
	stream := &startupInfoStream{info: func(_ context.Context, attempt int) (*jetstream.StreamInfo, error) {
		if attempt == 1 {
			return nil, missing
		}
		return &jetstream.StreamInfo{Config: durableControlStreamConfig()}, nil
	}}
	js := &startupInfoJetStream{stream: stream}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	got, err := openControlStream(ctx, js, defaultReplicas)
	if err != nil || got != stream || js.createCalls != 1 || js.lookupCalls != 0 || stream.infoCalls != 2 {
		t.Fatalf("post-create metadata convergence did not open authority log: stream=%v err=%v create=%d lookup=%d info=%d",
			got, err, js.createCalls, js.lookupCalls, stream.infoCalls)
	}
}

func TestCreatedControlStreamMissingInfoRetryIsBoundedAndCancelable(t *testing.T) {
	missing := &jetstream.APIError{Code: 404, ErrorCode: jetstream.JSErrCodeStreamNotFound,
		Description: "stream not found"}
	stream := &startupInfoStream{info: func(context.Context, int) (*jetstream.StreamInfo, error) {
		return nil, missing
	}}
	started := time.Now()
	if _, err := inspectCreatedControlStream(t.Context(), stream, 250*time.Millisecond); !errors.Is(err, missing) {
		t.Fatalf("persistent exact missing Info did not preserve 10059: %v", err)
	}
	if stream.infoCalls < 2 || time.Since(started) > time.Second {
		t.Fatalf("persistent missing Info retry was not bounded: calls=%d elapsed=%s", stream.infoCalls, time.Since(started))
	}
	canceledCtx, cancel := context.WithCancel(t.Context())
	stream.infoCalls = 0
	stream.info = func(context.Context, int) (*jetstream.StreamInfo, error) {
		cancel()
		return nil, missing
	}
	started = time.Now()
	if _, err := inspectCreatedControlStream(canceledCtx, stream, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation was not propagated: %v", err)
	}
	if stream.infoCalls != 1 || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("canceled Info kept retrying: calls=%d elapsed=%s", stream.infoCalls, time.Since(started))
	}
}

func TestOpenControlStreamDoesNotRetryPermanentOrExistingMissingInfo(t *testing.T) {
	for _, test := range []struct {
		name      string
		infoErr   error
		createErr error
	}{
		{"authorization", &jetstream.APIError{Code: 403, ErrorCode: 10059}, nil},
		{"different not found", &jetstream.APIError{Code: 404, ErrorCode: 10000}, nil},
		{"bad configuration", &jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeBadRequest}, nil},
		{"existing stream missing", &jetstream.APIError{Code: 404, ErrorCode: jetstream.JSErrCodeStreamNotFound}, jetstream.ErrStreamNameAlreadyInUse},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &startupInfoStream{info: func(context.Context, int) (*jetstream.StreamInfo, error) {
				return nil, test.infoErr
			}}
			js := &startupInfoJetStream{stream: stream, createErr: test.createErr}
			started := time.Now()
			_, err := openControlStream(t.Context(), js, defaultReplicas)
			if !errors.Is(err, test.infoErr) || stream.infoCalls != 1 || time.Since(started) > time.Second {
				t.Fatalf("permanent/existing error was retried or changed: err=%v calls=%d elapsed=%s",
					err, stream.infoCalls, time.Since(started))
			}
			if test.createErr != nil && js.lookupCalls != 1 {
				t.Fatal("existing stream path did not perform its one lookup")
			}
		})
	}
}
