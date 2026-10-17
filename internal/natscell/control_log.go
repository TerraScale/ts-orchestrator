package natscell

import (
	"context"
	"errors"
)

// EnsureControlLog belongs to the original root broker; ordinary runtimes have
// no native server. The caller must separately prove protected birth/incarnation.
func (r *Runtime) EnsureControlLog(ctx context.Context, beforeEffect func(context.Context) error) error {
	if r == nil || r.server == nil || r.resolver == nil || r.conn == nil || beforeEffect == nil {
		return errors.New("control-log initialization requires the original root broker")
	}
	account, err := r.server.LookupAccount(r.resolver.cell)
	if err != nil {
		return err
	}
	return r.server.EnsureTerraScaleControlLog(ctx, account, len(r.brokerNames), func(effect context.Context) error {
		if effect == nil || effect.Err() != nil || !r.server.Running() || r.conn.IsClosed() {
			return errors.New("original root control-log source ended")
		}
		return beforeEffect(effect)
	})
}
