package manager

import (
	"context"
	"errors"
	"net/http"
)

// RunBootstrapAccountWithTransport runs only the fixed local account recipe.
// Transport callbacks grant no journal, source or response-sealing authority.
func RunBootstrapAccountWithTransport(ctx context.Context, token string, check func() error, dispatch func(*http.Request) (*http.Response, error)) error {
	if ctx == nil || check == nil || dispatch == nil {
		return errors.New("NetBird account bootstrap requires its private journal transport")
	}
	if err := check(); err != nil {
		return err
	}
	api, err := NewAPI("http://127.0.0.1:18081", token)
	if err != nil {
		return err
	}
	defer api.Close()
	api.beforeWrite, api.mutation = check, dispatch
	p := &plan{}
	if err := p.planAccount(ctx, api, GRU()); err != nil {
		return err
	}
	if _, err := p.run(ctx, true, nil); err != nil {
		return err
	}
	return check()
}
