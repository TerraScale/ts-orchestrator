// Package mutationcontext carries a finite node mutation's original Raft epoch.
package mutationcontext

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrAmbiguous means a proposal may have committed; callers must reconcile its
// immutable operation identity rather than submit it with renewed authority.
var ErrAmbiguous = errors.New("node mutation outcome ambiguous after Raft admission")

type key struct{}
type admission struct {
	term, leader uint64
	submitted    atomic.Bool
}

func WithEpoch(ctx context.Context, term, leader uint64) context.Context {
	return context.WithValue(ctx, key{}, &admission{term: term, leader: leader})
}

// BeforeProposal is called immediately before handing bytes to Raft. Marking
// submission first conservatively includes cancellation during Propose itself.
func BeforeProposal(ctx context.Context, term, leader uint64) error {
	a, ok := ctx.Value(key{}).(*admission)
	if !ok {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.term == 0 || a.leader == 0 || a.term != term || a.leader != leader {
		return errors.New("node mutation Raft epoch changed before admission")
	}
	a.submitted.Store(true)
	return nil
}

func Submitted(ctx context.Context) bool {
	a, ok := ctx.Value(key{}).(*admission)
	return ok && a.submitted.Load()
}
