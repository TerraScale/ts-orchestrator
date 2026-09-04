package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

// Action is what a planned change does.
type Action string

const (
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
	// Alert marks drift the reconciler cannot repair itself; it is surfaced
	// in the plan (D-67 drift alerts) and skipped by Apply.
	Alert Action = "alert"
)

// Change is one planned mutation. Detail is safe to print: no tokens, no
// response bodies.
type Change struct {
	Action   Action
	Resource string // "dns-record", "cache-rule", ...
	Ref      string
	Detail   string
	apply    func(context.Context) error
}

// Plan is the output of one observe pass over the whole zone. Building it
// mutates nothing.
type Plan struct {
	Zone    string
	Changes []Change
}

func (p *Plan) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "zone %s: %d change(s)\n", p.Zone, len(p.Changes))
	for _, ch := range p.Changes {
		fmt.Fprintf(&b, "  %-6s %-14s %s\n", ch.Action, ch.Resource, ch.Detail)
	}
	return b.String()
}

// Apply performs the planned changes in order and stops at the first error;
// the next pass re-plans from observed state, so a partial apply is safe.
func Apply(ctx context.Context, p *Plan) error {
	for _, ch := range p.Changes {
		if ch.apply == nil {
			continue
		}
		if err := ch.apply(ctx); err != nil {
			return fmt.Errorf("apply %s %s: %w", ch.Action, ch.Resource, err)
		}
	}
	return nil
}

// ReconcileZone observes every resource type against the declared zone and
// returns the plan that would drive Cloudflare to match it (D-67: one pass =
// observe all types, diff, plan, apply).
func ReconcileZone(ctx context.Context, c *Client, z *Zone) (*Plan, error) {
	p := &Plan{Zone: z.ZoneName}
	steps := []struct {
		name string
		run  func(context.Context, *Client, *Plan) error
	}{
		{"dns records", z.reconcileDNS},        // records first: routes need them
		{"cache rules", z.reconcileCache},      // Cache Rules + Smart Tiered Cache
		{"snippet rules", z.reconcileSnippets}, // the sync.api gate rule
		{"worker routes", z.reconcileWorkerRoutes},
		{"kv namespaces", z.reconcileKVNamespaces},
		{"waf and rate rules", z.reconcileWAFAndRateRules},
		{"ssl and certificates", z.reconcileSSL},
	}
	for _, step := range steps {
		if err := step.run(ctx, c, p); err != nil {
			return nil, fmt.Errorf("cloudflare: %s: %w", step.name, err)
		}
	}
	return p, nil
}

// Run is one full pass: observe, diff, plan, then apply — or print the plan
// and touch nothing when dryRun is set.
func Run(ctx context.Context, c *Client, z *Zone, dryRun bool, w io.Writer) error {
	p, err := ReconcileZone(ctx, c, z)
	if err != nil {
		return err
	}
	if w != nil {
		fmt.Fprint(w, p)
	}
	if dryRun {
		return nil
	}
	return Apply(ctx, p)
}

type pair[T any] struct{ Live, Want T }

// diff keys live and declared items and returns creates, deletes, and
// non-equal pairs, each ordered by key so plans are deterministic.
func diff[T any](live, want []T, key func(T) string, eq func(a, b T) bool) (creates, deletes []T, updates []pair[T]) {
	liveByKey := make(map[string]T, len(live))
	for _, item := range live {
		liveByKey[key(item)] = item
	}
	wantByKey := make(map[string]T, len(want))
	for _, item := range want {
		wantByKey[key(item)] = item
	}
	for _, item := range want {
		if _, ok := liveByKey[key(item)]; !ok {
			creates = append(creates, item)
		}
	}
	for _, item := range live {
		w, ok := wantByKey[key(item)]
		if !ok {
			deletes = append(deletes, item)
			continue
		}
		if !eq(item, w) {
			updates = append(updates, pair[T]{Live: item, Want: w})
		}
	}
	sort.Slice(creates, func(i, j int) bool { return key(creates[i]) < key(creates[j]) })
	sort.Slice(deletes, func(i, j int) bool { return key(deletes[i]) < key(deletes[j]) })
	sort.Slice(updates, func(i, j int) bool { return key(updates[i].Want) < key(updates[j].Want) })
	return creates, deletes, updates
}

// jsonEqual compares two JSON payloads structurally: field order and number
// formatting must never count as drift.
func jsonEqual(a, b json.RawMessage) bool {
	var av, bv any
	if len(a) > 0 {
		_ = json.Unmarshal(a, &av)
	}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &bv)
	}
	return reflect.DeepEqual(av, bv)
}
