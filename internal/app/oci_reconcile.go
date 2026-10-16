package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nlb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/seclist"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// OciReconcileConfig enables the declarative OCI reconcile framework on the
// regional authority leader. It is off unless Enabled is set.
type OciReconcileConfig struct {
	Enabled         bool   `json:"enabled,omitzero"`
	IntervalSeconds int    `json:"interval_seconds,omitzero"`
	TagMode         string `json:"tag_mode,omitempty"`
	TagNamespace    string `json:"tag_namespace,omitempty"`
	// PublicNLB keeps the public API NLB's backend set in step with the
	// RUNNING member hosts placement observes.
	PublicNLB *OciReconcileNLBConfig `json:"public_nlb,omitempty"`
	// PublicLB keeps the public API load balancer's TerraBase backend set
	// equal to the seats the signed terrabase profile names (TS-571).
	PublicLB *OciReconcileLBConfig `json:"public_lb,omitempty"`
	// Desired publishes desired specs listed in this controller
	// configuration (bound to the signed controller manifest on baked
	// controllers) into TS_OCI_DESIRED before every pass. Off when nil.
	Desired *OciDesiredConfig `json:"desired,omitempty"`
}

// OciReconcileNLBConfig names the NLB backend set synced to placement.
type OciReconcileNLBConfig struct {
	Name       string `json:"name"`
	NLBID      string `json:"nlb_id"`
	BackendSet string `json:"backend_set"`
	Port       int    `json:"port"`
}

// OciReconcileLBConfig names the L7 load balancer backend set synced to the
// TerraBase seats: every member TERRABASE_PEERS names, at the profile's
// client port. Its desired-state key is always lb.PublicTerraBase, the one
// public-api apply stamps ownership for.
type OciReconcileLBConfig struct {
	LoadBalancerID string `json:"load_balancer_id"`
	BackendSet     string `json:"backend_set"`
	// Seats limits the backends to these seats; empty means every seat.
	//
	// ponytail: gru-1 lists gru-1-db-1 only. Members serve diverging
	// catalogs until TS-561 replicates them; drop the list then.
	Seats []string `json:"seats,omitempty"`
}

// key validates the configuration and returns its desired-state key.
func (c OciReconcileLBConfig) key(cell string) (ociresource.Key, error) {
	key := ociresource.Key{Region: cell, Kind: lb.Kind, Name: lb.PublicTerraBase}
	if err := key.Validate(); err != nil {
		return key, err
	}
	if err := (lb.Spec{LoadBalancerID: c.LoadBalancerID, BackendSet: c.BackendSet, AllowEmpty: true}).Validate(); err != nil {
		return key, err
	}
	for i, seat := range c.Seats {
		if seat == "" || slices.Contains(c.Seats[:i], seat) {
			return key, fmt.Errorf("OCI reconcile public load balancer seat %q is empty or repeated", seat)
		}
	}
	return key, nil
}

// publicLBKey validates public_lb against the rest of the configuration.
// public-api apply stamps freeform ownership only, so a defined tag_mode
// could never own the load balancer.
func (c OciReconcileConfig) publicLBKey(cell string) (ociresource.Key, error) {
	if c.TagMode != "" && c.TagMode != string(ociresource.TagModeFreeform) {
		return ociresource.Key{}, errors.New("OCI reconcile public_lb requires freeform tag_mode: public-api apply stamps freeform ownership")
	}
	return c.PublicLB.key(cell)
}

// spec derives the backend set from the current terrabase profile, with the
// seats the seat rollout holds drained. A seat the configuration lists but
// the profile does not is an error, so a typo or a removed member never
// silently shrinks the set.
func (c OciReconcileLBConfig) spec(profiles map[string]WorkloadProfile, drained map[string]bool) (lb.Spec, error) {
	profile, ok := profiles[terrabase.Role]
	if !ok {
		return lb.Spec{}, errors.New("public load balancer: the cell has no terrabase workload profile")
	}
	members, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		return lb.Spec{}, fmt.Errorf("public load balancer: %w", err)
	}
	if members.ClientPort == 0 {
		return lb.Spec{}, errors.New("public load balancer: the terrabase profile has no client listener")
	}
	spec := lb.Spec{LoadBalancerID: c.LoadBalancerID, BackendSet: c.BackendSet}
	for _, seat := range c.Seats {
		if _, ok := members.Peer(seat); !ok {
			return lb.Spec{}, fmt.Errorf("public load balancer seat %q is not in %s", seat, terrabase.EnvPeers)
		}
	}
	for _, peer := range members.Peers {
		if len(c.Seats) == 0 || slices.Contains(c.Seats, peer.Name) {
			spec.Backends = append(spec.Backends, lb.Backend{IP: peer.Address.Addr().String(), Port: members.ClientPort,
				Drain: drained[peer.Name]})
		}
	}
	return spec, nil
}

// OciDesiredEntry and OciDesiredConfig are the cell spec's types, so the
// signed config and a cell spec oci_desired section list resources alike.
type (
	OciDesiredEntry[S any] = cellspec.OCIDesiredEntry[S]
	OciDesiredConfig       = cellspec.OCIDesired
)

const (
	minOciReconcileInterval = 30 * time.Second
	maxOciReconcileInterval = time.Hour
	defaultOciPruneDelay    = time.Hour
	maxOciPruneDelay        = 7 * 24 * time.Hour
)

func (c OciReconcileConfig) interval() (time.Duration, error) {
	if c.IntervalSeconds == 0 {
		return time.Minute, nil
	}
	interval := time.Duration(c.IntervalSeconds) * time.Second
	if interval < minOciReconcileInterval || interval > maxOciReconcileInterval {
		return 0, errors.New("OCI reconcile interval must be between 30 seconds and one hour")
	}
	return interval, nil
}

func (c OciReconcileConfig) ownership(owner string) (ociresource.Ownership, error) {
	ownership := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Namespace: c.TagNamespace, Owner: owner}
	if c.TagMode != "" {
		ownership.Mode = ociresource.TagMode(c.TagMode)
	}
	return ownership, ownership.Validate()
}

// ociDesiredSet is one kind's validated entries.
type ociDesiredSet struct {
	kind    string
	entries []ociresource.Entry
}

func desiredEntries[S ociresource.Validator](entries map[string]OciDesiredEntry[S]) ([]ociresource.Entry, error) {
	out := make([]ociresource.Entry, 0, len(entries))
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		entry := entries[name]
		policy := ociresource.PolicyReport
		switch entry.Policy {
		case "", string(ociresource.PolicyReport):
		case string(ociresource.PolicyEnforce):
			policy = ociresource.PolicyEnforce
		default:
			return nil, fmt.Errorf("OCI desired %q has unsupported policy %q", name, entry.Policy)
		}
		if err := entry.Spec.Validate(); err != nil {
			return nil, fmt.Errorf("OCI desired %q: %w", name, err)
		}
		out = append(out, ociresource.Entry{Name: name, Policy: policy, Spec: entry.Spec})
	}
	return out, nil
}

// desiredSets validates every configured entry against the signed region
// configuration. NSG specs may only name the NSGs that configuration admits
// for member hosts.
func desiredSets(c OciDesiredConfig, cell string, region oci.RegionConfig) ([]ociDesiredSet, time.Duration, error) {
	delay := defaultOciPruneDelay
	if c.PruneDelaySeconds != 0 {
		delay = time.Duration(c.PruneDelaySeconds) * time.Second
		if delay < 0 || delay > maxOciPruneDelay {
			return nil, 0, errors.New("OCI desired prune delay must be between zero and seven days")
		}
	}
	for name, entry := range c.NSGRules {
		if !slices.Contains(region.NetworkSecurityGroupIDs, entry.Spec.NSGID) {
			return nil, 0, fmt.Errorf("OCI desired NSG %q is not admitted by the signed region configuration", name)
		}
	}
	var sets []ociDesiredSet
	add := func(kind string, entries []ociresource.Entry, err error) error {
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := (ociresource.Key{Region: cell, Kind: kind, Name: entry.Name}).Validate(); err != nil {
				return err
			}
		}
		if len(entries) > 0 || c.Prune {
			sets = append(sets, ociDesiredSet{kind: kind, entries: entries})
		}
		return nil
	}
	nsgEntries, err := desiredEntries(c.NSGRules)
	if err := add(nsg.Kind, nsgEntries, err); err != nil {
		return nil, 0, err
	}
	listEntries, err := desiredEntries(c.SecurityLists)
	if err := add(seclist.Kind, listEntries, err); err != nil {
		return nil, 0, err
	}
	tableEntries, err := desiredEntries(c.RouteTables)
	if err := add(routetable.Kind, tableEntries, err); err != nil {
		return nil, 0, err
	}
	bucketEntries, err := desiredEntries(c.Buckets)
	if err := add(bucket.Kind, bucketEntries, err); err != nil {
		return nil, 0, err
	}
	return sets, delay, nil
}

// currentDesiredPass publishes the desired resources in force at each leader
// pass: the cell spec's oci_desired section, else the signed config's.
func currentDesiredPass(cell string, region oci.RegionConfig, store ociresource.Store, fencer authority.Fencer,
	desired func() *OciDesiredConfig,
) ociresource.Pass {
	return ociresource.Pass{Name: "publish-desired", Run: func(ctx context.Context, epoch uint64) error {
		config := desired()
		if config == nil {
			return nil
		}
		sets, delay, err := desiredSets(*config, cell, region)
		if err != nil {
			return err
		}
		return desiredPass(cell, store, fencer, sets, config.Prune, delay).Run(ctx, epoch)
	}}
}

// desiredPass publishes the configured specs at the start of every leader
// pass, so a new controller configuration converges without a tool.
func desiredPass(cell string, store ociresource.Store, fencer authority.Fencer, sets []ociDesiredSet, prune bool,
	delay time.Duration,
) ociresource.Pass {
	return ociresource.Pass{Name: "publish-desired", Run: func(ctx context.Context, epoch uint64) error {
		var failures []error
		for _, set := range sets {
			if err := fencer.Guard(ctx, epoch); err != nil {
				return fmt.Errorf("%w: %w", ociresource.ErrFenced, err)
			}
			result, err := ociresource.PublishSet(ctx, store, cell, set.kind, set.entries, prune, time.Now().UTC(), delay,
				func(ctx context.Context) error { return fencer.Guard(ctx, epoch) })
			if result.Published > 0 || result.Tombstoned > 0 {
				decisionlog.Record(ctx, decisionlog.Decision{
					Region: strings.ToLower(cell), Actor: decisionlog.Actor{Slice: "ociresource"},
					Kind:    decisionlog.KindOCIDesiredPublished,
					Subject: decisionlog.Subject{Kind: "oci-" + set.kind, ID: cell + "/" + set.kind},
					Summary: fmt.Sprintf("Published %d and tombstoned %d %s desired specs", result.Published,
						result.Tombstoned, set.kind),
					Reason: "The controller configuration's desired OCI specs changed.",
					Rule:   "ociresource.desired",
					Signals: []decisionlog.Signal{{Name: "published", Value: float64(result.Published)},
						{Name: "tombstoned", Value: float64(result.Tombstoned)},
						{Name: "unchanged", Value: float64(result.Unchanged)}},
					Status: decisionlog.StatusSucceeded, Epoch: epoch})
			}
			if err != nil {
				if ctx.Err() != nil {
					return err
				}
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}}
}

// publicLBPass publishes the TerraBase seats as the public load balancer's
// backend set, draining the seats the seat rollout holds drained. A profile
// that yields no serving seat, or seat records it cannot read, is an error,
// and the previous set stays in force.
func publicLBPass(store ociresource.Store, fencer authority.Fencer, key ociresource.Key, public OciReconcileLBConfig,
	profiles func() map[string]WorkloadProfile, drained func(context.Context) (map[string]bool, error),
) ociresource.Pass {
	return ociresource.Pass{Name: "publish-" + lb.Kind, Run: func(ctx context.Context, epoch uint64) error {
		if err := fencer.Guard(ctx, epoch); err != nil {
			return fmt.Errorf("%w: %w", ociresource.ErrFenced, err)
		}
		seats, err := drained(ctx)
		if err != nil {
			return fmt.Errorf("public load balancer: %w", err)
		}
		spec, err := public.spec(profiles(), seats)
		if err != nil {
			return err
		}
		_, err = lb.Publish(ctx, store, key, ociresource.PolicyEnforce, spec)
		return err
	}}
}

// ociReconcileRuntime is the leader-only runner and the read side the
// insights engine uses on every controller.
type ociReconcileRuntime struct {
	runner *ociresource.Runner
	store  ociresource.StatusLister
	cell   string
	// wake starts the next pass at once; seatBackends reads the public
	// load balancer's TerraBase backends, nil without public_lb.
	wake         chan struct{}
	seatBackends func(context.Context) (map[string]seatrollout.Backend, error)
}

// wakeRunner asks for the next pass now without blocking.
func (r *ociReconcileRuntime) wakeRunner() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// resources returns the insights provider, or a nil interface when the
// reconcile is off.
func (r *ociReconcileRuntime) resources() insights.OCIResourceProvider {
	if r == nil || r.store == nil {
		return nil
	}
	return ociResourceStatuses{store: r.store, cell: r.cell}
}

// ociResourceStatuses adapts TS_OCI_OBSERVED to the insights provider.
type ociResourceStatuses struct {
	store ociresource.StatusLister
	cell  string
}

func (s ociResourceStatuses) OCIResources(ctx context.Context) ([]insights.OCIResource, error) {
	statuses, err := s.store.ListStatus(ctx, s.cell)
	if err != nil {
		return nil, err
	}
	out := make([]insights.OCIResource, 0, len(statuses))
	for _, status := range statuses {
		if status.Deleted {
			continue
		}
		resource := insights.OCIResource{Key: status.Key.String(), Kind: status.Key.Kind, Policy: string(status.Policy),
			Found: status.Found, InSync: status.InSync, Foreign: status.Foreign, Applied: status.Applied, Error: status.Error,
			ObservedAt: status.ObservedAt}
		for _, change := range status.Drift {
			resource.Drift = append(resource.Drift, change.Op+" "+change.Detail)
		}
		out = append(out, resource)
	}
	return out, nil
}

// newOCIReconcileRunner builds the leader-only reconcile runner for one
// region: configured desired specs, NSG rule sets, security lists, route
// tables, bucket protection and, when configured, the public NLB backends
// published from placement's fleet observation and the public load
// balancer's TerraBase backends published from the cell's current profiles.
func newOCIReconcileRunner(ctx context.Context, config OciReconcileConfig, region oci.RegionConfig,
	js jetstream.JetStream, replicas int, fencer authority.Fencer, fleet oci.Fleet, profiles func() map[string]WorkloadProfile,
	desired func() *OciDesiredConfig,
) (*ociReconcileRuntime, error) {
	if fencer == nil || fleet == nil {
		return nil, errors.New("OCI reconcile requires authority and the regional fleet")
	}
	interval, err := config.interval()
	if err != nil {
		return nil, err
	}
	ownership, err := config.ownership(region.Owner)
	if err != nil {
		return nil, err
	}
	cell := string(region.Region)
	if config.Desired != nil {
		if _, _, err := desiredSets(*config.Desired, cell, region); err != nil {
			return nil, err
		}
	}
	ociRegion, err := region.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	store, err := ociresource.OpenKVStore(ctx, js, replicas)
	if err != nil {
		return nil, err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, err
	}
	nsgAPI, err := nsg.NewSDKAPI(factory)
	if err != nil {
		return nil, err
	}
	listAPI, err := seclist.NewSDKAPI(factory)
	if err != nil {
		return nil, err
	}
	tableAPI, err := routetable.NewSDKAPI(factory)
	if err != nil {
		return nil, err
	}
	bucketAPI, err := bucket.NewSDKAPI(factory)
	if err != nil {
		return nil, err
	}
	var passes []ociresource.Pass
	var seatBackends func(context.Context) (map[string]seatrollout.Backend, error)
	passes = append(passes, currentDesiredPass(cell, region, store, fencer, desired),
		ociresource.ControllerPass(&ociresource.Controller[nsg.Spec, nsg.Observed]{
			Region: cell, Resource: nsg.Reconciler{API: nsgAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[seclist.Spec, seclist.List]{
			Region: cell, Resource: seclist.Reconciler{API: listAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[routetable.Spec, routetable.Table]{
			Region: cell, Resource: routetable.Reconciler{API: tableAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[bucket.Spec, bucket.Observed]{
			Region: cell, Resource: bucket.Reconciler{API: bucketAPI}, Store: store, Ownership: ownership, Authority: fencer}))
	if public := config.PublicNLB; public != nil {
		key := ociresource.Key{Region: cell, Kind: nlb.Kind, Name: public.Name}
		if err := key.Validate(); err != nil {
			return nil, err
		}
		if err := (nlb.Spec{NLBID: public.NLBID, BackendSet: public.BackendSet, AllowEmpty: true}).Validate(); err != nil {
			return nil, err
		}
		if public.Port < 1 || public.Port > 65535 {
			return nil, errors.New("OCI reconcile public NLB port is invalid")
		}
		nlbAPI, err := nlb.NewSDKAPI(factory)
		if err != nil {
			return nil, err
		}
		passes = append(passes, ociresource.Pass{Name: "publish-" + nlb.Kind, Run: func(ctx context.Context, epoch uint64) error {
			if err := fencer.Guard(ctx, epoch); err != nil {
				return fmt.Errorf("%w: %w", ociresource.ErrFenced, err)
			}
			instances, err := fleet.Observe(ctx)
			if err != nil {
				return fmt.Errorf("observe fleet for NLB backends: %w", err)
			}
			spec := nlb.FromPlacement(public.NLBID, public.BackendSet, public.Port, instances)
			if len(spec.Backends) == 0 {
				// Keep the previous backend set rather than black-holing the
				// public API on a transient empty observation.
				return nil
			}
			_, err = nlb.Publish(ctx, store, key, ociresource.PolicyEnforce, spec)
			return err
		}}, ociresource.ControllerPass(&ociresource.Controller[nlb.Spec, nlb.Observed]{
			Region: cell, Resource: nlb.Reconciler{API: nlbAPI}, Store: store, Ownership: ownership, Authority: fencer}))
	}
	if public := config.PublicLB; public != nil {
		key, err := config.publicLBKey(cell)
		if err != nil {
			return nil, err
		}
		lbAPI, err := lb.NewSDKAPI(factory)
		if err != nil {
			return nil, err
		}
		seats, err := seatrollout.Open(ctx, js, replicas, fencer)
		if err != nil {
			return nil, err
		}
		seatBackends = lbSeatBackends(lbAPI, *public)
		passes = append(passes, publicLBPass(store, fencer, key, *public, profiles, seats.Drained),
			ociresource.ControllerPass(&ociresource.Controller[lb.Spec, lb.Observed]{
				Region: cell, Resource: lb.Reconciler{API: lbAPI}, Store: store, Ownership: ownership, Authority: fencer}))
	}
	wake := make(chan struct{}, 1)
	return &ociReconcileRuntime{runner: &ociresource.Runner{Authority: fencer, Passes: passes, Interval: interval,
		Jitter: rand.Float64, Wake: wake}, store: store, cell: cell, wake: wake, seatBackends: seatBackends}, nil
}
