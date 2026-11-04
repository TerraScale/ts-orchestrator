package host

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
)

type canceledCacheStore struct {
	ArtifactStore
	started  chan string
	canceled chan string
}

func (s canceledCacheStore) GetInfo(ctx context.Context, name string, _ ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.started <- name
	<-ctx.Done()
	s.canceled <- name
	return nil, ctx.Err()
}
