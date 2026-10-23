// Package handoff holds edge dials to a loopback port while its task is
// replaced. The old task holds the port until it exits and the new one binds it
// before its readyPath answers, so without the hold a client would get a
// refused dial or a not-ready answer during every update.
package handoff

import (
	"context"
	"sync"
	"time"
)

var held sync.Map // port (uint16) -> chan struct{}, closed on Release

// Hold makes Wait block for port until Release. The executor calls it before it
// stops a task that has a readyPath.
func Hold(port uint16) { held.LoadOrStore(port, make(chan struct{})) }

// Release ends the hold on port, once its new task answers its readyPath.
func Release(port uint16) {
	if ch, ok := held.LoadAndDelete(port); ok {
		close(ch.(chan struct{}))
	}
}

// Wait returns once port is not held, deadline passes or ctx ends.
func Wait(ctx context.Context, port uint16, deadline time.Time) {
	ch, ok := held.Load(port)
	if !ok {
		return
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ch.(chan struct{}):
	case <-timer.C:
	case <-ctx.Done():
	}
}
