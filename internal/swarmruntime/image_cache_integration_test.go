package swarmruntime

import (
	"context"

	"errors"

	"sync/atomic"

	"github.com/containerd/containerd/v2/core/remotes"

	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

type deniedCacheRegistry struct{ requests atomic.Int32 }

func (r *deniedCacheRegistry) Resolve(context.Context, string) (string, imagespec.Descriptor, error) {
	r.requests.Add(1)
	return "", imagespec.Descriptor{}, errors.New("registry egress denied")
}
func (r *deniedCacheRegistry) Fetcher(context.Context, string) (remotes.Fetcher, error) {
	r.requests.Add(1)
	return nil, errors.New("registry egress denied")
}
func (r *deniedCacheRegistry) Pusher(context.Context, string) (remotes.Pusher, error) {
	r.requests.Add(1)
	return nil, errors.New("registry egress denied")
}
