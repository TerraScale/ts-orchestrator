package decisionlog

import (
	"context"
	"errors"
)

const ()

// Source is the read side the dashboard, insights and remote regions use.
// Journal and Federation implement it.
type Source interface {
	Query(ctx context.Context, query Query) (Result, error)
	Chain(ctx context.Context, id string) (Chain, error)
}

// LiveSource streams decisions as they are recorded or ingested.
type LiveSource interface {
	Subscribe(ctx context.Context, buffer int) <-chan Decision
}

// ErrNotFound reports a chain lookup for an unknown decision.
var ErrNotFound = errors.New("decision not found")

var ()
