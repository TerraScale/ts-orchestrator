package rollout

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// BindReader reuses the retained record validators without provisioning a
// bucket or exposing a mutation-capable store. kv must be a root-owned reader.
func BindReader(kv jetstream.KeyValue, cell string) (*Reader, error) {
	if kv == nil || kv.Bucket() != Bucket || !tokenRE.MatchString(cell) {
		return nil, fmt.Errorf("%w: rollout reader configuration", ErrInvalid)
	}
	return &Reader{store: &Store{kv: kv, cell: cell}}, nil
}

type Reader struct{ store *Store }

func (r *Reader) Desired(ctx context.Context) (Desired, uint64, error) { return r.store.Desired(ctx) }
func (r *Reader) Load(ctx context.Context, id string) (Record, uint64, error) {
	return r.store.Load(ctx, id)
}
func (r *Reader) ReleasePins(ctx context.Context) ([]string, []string, error) {
	return r.store.ReleasePins(ctx)
}
func (r *Reader) IsKnownBad(ctx context.Context, digest string) (bool, error) {
	return r.store.IsKnownBad(ctx, digest)
}

func (r *Reader) Retained(ctx context.Context) ([]Release, error) {
	desired, _, err := r.store.Desired(ctx)
	if err != nil {
		return nil, err
	}
	return r.store.retainedReleases(ctx, desired)
}

func (r *Reader) Cell(ctx context.Context) (CellState, uint64, error) { return r.store.Cell(ctx) }
