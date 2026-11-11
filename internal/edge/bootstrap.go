package edge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

type bootstrapBarrier struct {
	mu      sync.Mutex
	id      string
	release func()
}

// Bootstrap deliberately never calls legacy /drain or changes ownership. A
// mixed-version owner is replaced on the same node, at the same owner epoch.
func (e *Edge) Bootstrap(ctx context.Context, action string, j rolloutmaintenance.Job) error {
	if e.bootstrapErr != nil {
		return e.bootstrapErr
	}
	if e.bootstrap == nil {
		return errors.New("bootstrap journal unavailable")
	}
	r := e.regional.Load()
	if r == nil {
		return errors.New("regional router unavailable")
	}
	if action == "owner" {
		// Read-only and outside the barrier lock: a held follower polls here
		// until its pinned owner serves as writer and has released the
		// founder's ingress hold, before its driver spends its 60 s budget.
		var owner mesh.WorkerPeer
		for _, p := range (*r.nodes.Load())() {
			if p.Node == j.Owner {
				owner = p
			}
		}
		if owner.Node == "" {
			return errors.New("bootstrap owner is not admitted to this region")
		}
		retained, err := e.bootstrap.Ingress(ctx)
		if err != nil {
			return err
		}
		if retained != nil {
			return errors.New("pinned owner still holds regional ingress")
		}
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		s, err := e.regionalStatus(probe, r, owner)
		if err != nil {
			return err
		}
		if s.Owner != j.Owner || s.Epoch != j.Epoch || !s.Writer || !s.Ready {
			return fmt.Errorf("pinned owner not ready: owner=%s epoch=%d writer=%t ready=%t", s.Owner, s.Epoch, s.Writer, s.Ready)
		}
		return nil
	}
	e.bootstrapBarrier.mu.Lock()
	defer e.bootstrapBarrier.mu.Unlock()
	var member, owner mesh.WorkerPeer
	for _, p := range (*r.nodes.Load())() {
		if p.Node == j.Member {
			member = p
		}
		if p.Node == j.Owner {
			owner = p
		}
	}
	if member.Node == "" || owner.Node == "" {
		return errors.New("bootstrap pin is not admitted to this region")
	}
	status := func(p mesh.WorkerPeer, writer bool) error {
		s, err := e.regionalStatus(ctx, r, p)
		if err != nil {
			return err
		}
		if s.Owner != j.Owner || s.Epoch != j.Epoch || s.Writer != writer || !s.Ready {
			return fmt.Errorf("pinned owner/readiness mismatch: node=%s owner=%s epoch=%d writer=%t ready=%t", s.Node, s.Owner, s.Epoch, s.Writer, s.Ready)
		}
		return nil
	}
	switch action {
	case "verify":
		if err := status(member, j.Member == j.Owner); err != nil {
			return err
		}
		if j.Member != j.Owner {
			if err := status(owner, true); err != nil {
				return err
			}
			response, err := e.regionalRequest(ctx, r, member, http.MethodPost, "/v1/rollout/prime?source="+url.QueryEscape(j.Owner))
			if err != nil {
				return err
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				return fmt.Errorf("follower catch-up HTTP %d", response.StatusCode)
			}
		}
		return nil
	case "hold":
		if j.Member != j.Owner {
			if err := status(owner, true); err != nil {
				return err
			}
			return e.bootstrap.HoldIngress(ctx, j)
		}
		retained, err := e.bootstrap.Ingress(ctx)
		if err != nil {
			return err
		}
		if retained == nil {
			if err = status(member, true); err != nil {
				return err
			}
			// The upgraded follower must be live and caught up before stopping
			// the legacy owner. Its regional lease stays unchanged throughout.
			for _, peer := range (*r.nodes.Load())() {
				if peer.Node != j.Member {
					if err = status(peer, false); err != nil {
						return err
					}
					response, e := e.regionalRequest(ctx, r, peer, http.MethodPost, "/v1/rollout/prime?source="+url.QueryEscape(j.Owner))
					if e != nil {
						return e
					}
					response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						return fmt.Errorf("pre-stop follower catch-up HTTP %d", response.StatusCode)
					}
				}
			}
		}
		if err = e.bootstrap.HoldIngress(ctx, j); err != nil {
			return err
		}
		if e.bootstrapBarrier.id == j.ID {
			return nil
		}
		if e.bootstrapBarrier.id != "" {
			return rolloutmaintenance.ErrFenced
		}
		for !r.changing.TryLock() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
		r.holding.Store(true)
		for !r.ingress.TryLock() {
			select {
			case <-ctx.Done():
				r.holding.Store(false)
				r.changing.Unlock()
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
		r.endTunnels(j.Owner)
		r.transport.CloseIdleConnections()
		e.bootstrapBarrier.id = j.ID
		e.bootstrapBarrier.release = func() { r.ingress.Unlock(); r.changing.Unlock(); r.holding.Store(false) }
		return nil
	case "release":
		if j.Member != j.Owner {
			if err := status(owner, true); err != nil {
				return err
			}
			if err := status(member, false); err != nil {
				return err
			}
			return e.bootstrap.ReleaseIngress(ctx, j)
		}
		if err := status(member, true); err != nil {
			return err
		}
		if e.bootstrapBarrier.id != j.ID {
			return errors.New("bootstrap barrier must be reacquired after restart")
		}
		if err := e.bootstrap.ReleaseIngress(ctx, j); err != nil {
			return err
		}
		r.mu.Lock()
		r.owner = member
		r.checked = time.Now()
		r.mu.Unlock()
		e.bootstrapBarrier.release()
		e.bootstrapBarrier.id = ""
		e.bootstrapBarrier.release = nil
		return nil
	default:
		return errors.New("invalid bootstrap operation")
	}
}
