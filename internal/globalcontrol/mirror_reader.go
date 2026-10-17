package globalcontrol

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

// OpenMirrorReader verifies an existing mirror without creating or changing it.
func OpenMirrorReader(ctx context.Context, js jetstream.JetStream, home, cell string, replicas int) (*Reader, error) {
	if js == nil || !cellToken.MatchString(home) || !cellToken.MatchString(cell) || home == cell {
		return nil, errors.New("global mirror reader requires authenticated JetStream and distinct home and regional cells")
	}
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyMirror(info.Config, home, cell, replicas); err != nil {
		return nil, err
	}
	return &Reader{stream: stream, js: js, mirror: true}, nil
}
