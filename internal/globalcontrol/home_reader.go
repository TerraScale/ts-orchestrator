package globalcontrol

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

// OpenHomeReader opens the existing home stream without creating or changing
// it. Protected capacity handlers must never read a regional mirror as truth.
func OpenHomeReader(ctx context.Context, js jetstream.JetStream, replicas int) (*Reader, error) {
	if js == nil {
		return nil, errors.New("home reader requires an authenticated JetStream connection")
	}
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyHome(info.Config, replicas); err != nil {
		return nil, err
	}
	return &Reader{stream: stream, js: js}, nil
}
