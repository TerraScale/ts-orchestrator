package seatrollout

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

const (
	// DefaultDrainGrace is how long a drained seat keeps finishing its
	// in-flight requests before its host may stop it; SIGTERM then drains
	// what is left.
	//
	// ponytail: a fixed grace, not an in-flight count; read the member's
	// active-request metric if releases under load show 502s.
	DefaultDrainGrace = 15 * time.Second
	// DefaultSettle is how long a restarted seat must keep reporting
	// running (its /readyz included) before it returns to rotation.
	DefaultSettle = 10 * time.Second
	// DefaultInterval is how often the leader drives the seats.
	DefaultInterval = 2 * time.Second
)

// Member names one TerraBase seat and the public load balancer backend
// (ip:port) that serves it, empty when it has none.
type Member struct {
	Node, Backend string
	// Group names the replication group; seats of one group never restart
	// together. All C# members replicate with each other today.
	Group string
}

// Backend is a load balancer backend as last observed.
type Backend struct {
	Drained, Healthy bool
}

// Hosts reads desired state and host reports.
type Hosts interface {
	ListHosts(ctx context.Context) ([]host.HostStatus, error)
	ListDesired(ctx context.Context, role string) ([]host.Desired, error)
}

// Controller restarts TerraBase seats one group member at a time. The
// controller process runs it on the leader when controller.terrabase_seats
// is enabled, which also makes Store.Granted the host restart gate. It only
// writes seat records; the load balancer publisher drains the seats they
// hold drained, and the host restart gate (Store.Granted) lets a seat
// restart only into a permitted generation. Each tick it derives every
// step from the records and what it observes, so a new leader resumes
// where the old one stopped.
type Controller struct {
	Store  *Store
	Fencer authority.Fencer
	Hosts  Hosts
	// Seats returns the cell's seats from the signed terrabase profile.
	Seats func() ([]Member, error)
	// Backends returns the public load balancer's backends by ip:port; nil
	// means there is no load balancer and nothing is drained.
	Backends func(ctx context.Context) (map[string]Backend, error)
	// Wake, when set, is called after every record write, so the load
	// balancer publisher applies a drain or return at once.
	Wake func()
	// Hold, when set and it names a reason, starts no seat's restart: no
	// seat that is not drained already is drained or permitted, so another
	// restart in the cell (an orchestrator host rollout) finishes first.
	Hold       func(ctx context.Context) (string, error)
	DrainGrace time.Duration
	Settle     time.Duration
	Interval   time.Duration
	Now        func() time.Time

	// ready and drained are leader-local: when each drained seat was first
	// seen serving its permitted generation, and first seen drained on the
	// load balancer. A new leader starts both waits again, which is only
	// slower. Entries live only while their seat's record is drained.
	ready, drained map[string]time.Time
}

// Run drives the seats until ctx ends. A tick error is logged and the next
// tick retries; a seat only ever waits.
func (c *Controller) Run(ctx context.Context) error {
	ticker := time.NewTicker(cmp.Or(c.Interval, DefaultInterval))
	defer ticker.Stop()
	for {
		if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "terrabase seat rollout tick failed", "component", "seatrollout", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// view is one seat as a tick sees it.
type view struct {
	seat    Member
	record  Seat
	rev     uint64
	desired host.Desired
	wanted  bool // a live desired the seat must run
	done    bool // the host reports the desired generation running
	backend Backend
	inLB    bool
}

// serving reports whether the load balancer sends the seat requests.
func (v view) serving() bool { return v.inLB && !v.backend.Drained && v.backend.Healthy }

// Tick takes at most one step per seat. Followers do nothing.
func (c *Controller) Tick(ctx context.Context) error {
	snapshot := c.Fencer.Current()
	if !snapshot.CanMutate() {
		c.ready, c.drained = nil, nil
		return nil
	}
	views, err := c.observe(ctx)
	if err != nil {
		return err
	}
	// Keep only the waits of seats that are drained now, so a seat that
	// left and came back, or was returned, starts them afresh.
	ready, drained := map[string]time.Time{}, map[string]time.Time{}
	for _, v := range views {
		if v.record.Drain {
			if at, ok := c.ready[v.seat.Node]; ok {
				ready[v.seat.Node] = at
			}
			if at, ok := c.drained[v.seat.Node]; ok {
				drained[v.seat.Node] = at
			}
		}
	}
	c.ready, c.drained = ready, drained
	now := c.now()
	busy := map[string]bool{}
	for _, v := range views {
		record, target := v.record, v.desired.Generation
		switch {
		case record.Drain && v.wanted && v.done && record.Permit >= target && (!v.inLB || v.backend.Healthy):
			// Restarted and serving: back to rotation once the seat has kept
			// serving for the settle time, its /readyz included, and the load
			// balancer also finds it healthy. If OCI stopped checking a
			// drained backend the seat stays drained and its group waits,
			// which costs time, never requests. A seat whose desired was
			// withdrawn stays drained, holding its group, while its host stops
			// it: it serves nothing and its group is a member short.
			first, seen := c.ready[v.seat.Node]
			if !seen {
				c.ready[v.seat.Node] = now
				first = now
			}
			if now.Sub(first) < cmp.Or(c.Settle, DefaultSettle) {
				busy[v.seat.Group] = true
				continue
			}
			delete(c.ready, v.seat.Node)
			record.Drain, record.DrainedAt = false, time.Time{}
			if err := c.put(ctx, snapshot.Epoch, v, record, "returned to rotation"); err != nil {
				return err
			}
		case record.Drain && record.Permit < target:
			// Drained: permit the restart once the load balancer stopped
			// sending it requests and the in-flight grace passed since it
			// was first seen to, not since the drain was asked for: the
			// load balancer may apply it late.
			busy[v.seat.Group] = true
			since := record.DrainedAt
			if v.inLB {
				if !v.backend.Drained {
					delete(c.drained, v.seat.Node)
					continue
				}
				first, seen := c.drained[v.seat.Node]
				if !seen {
					c.drained[v.seat.Node] = now
					first = now
				}
				since = first
			}
			if now.Sub(since) < cmp.Or(c.DrainGrace, DefaultDrainGrace) {
				continue
			}
			record.Permit = target
			if err := c.put(ctx, snapshot.Epoch, v, record, "restart permitted"); err != nil {
				return err
			}
		case record.Drain, v.wanted && !v.done && record.Permit >= target:
			// Restarting under a permit. A seat that never serves holds
			// its group until a newer desired generation (a rollback)
			// supersedes the permit.
			busy[v.seat.Group] = true
		}
	}
	if c.Hold != nil {
		reason, err := c.Hold(ctx)
		if err != nil {
			return err
		}
		if reason != "" {
			slog.DebugContext(ctx, "terrabase seats wait: "+reason, "component", "seatrollout")
			return nil
		}
	}
	var pending []view
	for _, v := range views {
		if v.wanted && !v.done && v.record.Permit < v.desired.Generation && !v.record.Drain && !busy[v.seat.Group] {
			pending = append(pending, v)
		}
	}
	// Seats the load balancer does not serve go first: restarting them
	// costs no capacity.
	slices.SortFunc(pending, func(a, b view) int {
		if a.serving() != b.serving() {
			if a.serving() {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.seat.Node, b.seat.Node)
	})
	for _, v := range pending {
		if busy[v.seat.Group] {
			continue
		}
		busy[v.seat.Group] = true
		record := v.record
		if !v.serving() {
			record.Permit = v.desired.Generation
			if err := c.put(ctx, snapshot.Epoch, v, record, "restart permitted; the seat serves no requests"); err != nil {
				return err
			}
			continue
		}
		if !slices.ContainsFunc(views, func(other view) bool { return other.seat.Node != v.seat.Node && other.serving() }) {
			slog.DebugContext(ctx, "terrabase seat waits: draining it would leave no healthy seat", "component", "seatrollout", "seat", v.seat.Node)
			continue
		}
		record.Drain, record.DrainedAt = true, now
		if err := c.put(ctx, snapshot.Epoch, v, record, "drained for its restart"); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) put(ctx context.Context, epoch uint64, v view, record Seat, what string) error {
	record.Node, record.Epoch = v.seat.Node, epoch
	if _, err := c.Store.Put(ctx, record, v.rev); err != nil {
		return fmt.Errorf("seat %s: %w", v.seat.Node, err)
	}
	if c.Wake != nil {
		c.Wake()
	}
	slog.InfoContext(ctx, "terrabase seat "+what, "component", "seatrollout", "seat", v.seat.Node, "generation", v.desired.Generation, "epoch", epoch)
	return nil
}

// observe reads every seat's record, desired, report and backend.
func (c *Controller) observe(ctx context.Context) ([]view, error) {
	seats, err := c.Seats()
	if err != nil {
		return nil, err
	}
	desired, err := c.Hosts.ListDesired(ctx, terrabase.Role)
	if err != nil {
		return nil, err
	}
	statuses, err := c.Hosts.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	backends := map[string]Backend{}
	if c.Backends != nil {
		if backends, err = c.Backends(ctx); err != nil {
			return nil, err
		}
	}
	now := c.now()
	views := make([]view, 0, len(seats))
	for _, seat := range seats {
		record, rev, err := c.Store.Get(ctx, seat.Node)
		if err != nil {
			return nil, err
		}
		v := view{seat: seat, record: record, rev: rev}
		if index := slices.IndexFunc(desired, func(d host.Desired) bool { return d.Node == seat.Node }); index >= 0 {
			v.desired = desired[index]
			v.wanted = !v.desired.Withdrawn && v.desired.ManagedMember == nil
		}
		for _, status := range statuses {
			for _, report := range status.Reports {
				if report.Node == seat.Node && report.Role == terrabase.Role && report.Generation == v.desired.Generation &&
					report.Digest == v.desired.Digest && report.State == "running" && now.Sub(report.ObservedAt) < host.ReportMaxAge {
					v.done = true
				}
			}
		}
		v.backend, v.inLB = backends[seat.Backend]
		v.inLB = v.inLB && seat.Backend != ""
		views = append(views, v)
	}
	return views, nil
}
