//go:build linux

package host

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
)

type artifactLookupHook struct {
	ArtifactStore
	before func()
}

func (s artifactLookupHook) GetInfo(ctx context.Context, name string, opts ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.before()
	return s.ArtifactStore.GetInfo(ctx, name, opts...)
}
