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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nlb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/seclist"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
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
// client port.
type OciReconcileLBConfig struct {
	Name           string `json:"name"`
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
	key := ociresource.Key{Region: cell, Kind: lb.Kind, Name: c.Name}
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

// spec derives the backend set from the current terrabase profile. A seat
// the configuration lists but the profile does not is an error, so a typo
// or a removed member never silently shrinks the set.
func (c OciReconcileLBConfig) spec(profiles map[string]WorkloadProfile) (lb.Spec, error) {
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
			spec.Backends = append(spec.Backends, lb.Backend{IP: peer.Address.Addr().String(), Port: members.ClientPort})
		}
	}
	return spec, nil
}

// OciDesiredEntry is one desired resource. Policy is "report" (the default:
// drift is only recorded) or "enforce".
type OciDesiredEntry[S any] struct {
	Policy string `json:"policy,omitempty"`
	Spec   S      `json:"spec"`
}

// OciDesiredConfig lists desired specs by logical name per kind.
type OciDesiredConfig struct {
	NSGRules      map[string]OciDesiredEntry[nsg.Spec]        `json:"nsg_rules,omitempty"`
	SecurityLists map[string]OciDesiredEntry[seclist.Spec]    `json:"security_lists,omitempty"`
	RouteTables   map[string]OciDesiredEntry[routetable.Spec] `json:"route_tables,omitempty"`
	Buckets       map[string]OciDesiredEntry[bucket.Spec]     `json:"buckets,omitempty"`
	// Prune tombstones records of these kinds that this configuration no
	// longer lists, released PruneDelaySeconds later (default one hour).
	// Off by default: unlisted records, including ones written by tools,
	// are left alone.
	Prune             bool `json:"prune,omitzero"`
	PruneDelaySeconds int  `json:"prune_delay_seconds,omitzero"`
}

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

// sets validates every configured entry against the signed region
// configuration. NSG specs may only name the NSGs that configuration admits
// for member hosts.
func (c OciDesiredConfig) sets(cell string, region oci.RegionConfig) ([]ociDesiredSet, time.Duration, error) {
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
// backend set. A profile that yields no seat is an error, and the previous
// set stays in force.
func publicLBPass(store ociresource.Store, fencer authority.Fencer, key ociresource.Key, public OciReconcileLBConfig,
	profiles func() map[string]WorkloadProfile,
) ociresource.Pass {
	return ociresource.Pass{Name: "publish-" + lb.Kind, Run: func(ctx context.Context, epoch uint64) error {
		if err := fencer.Guard(ctx, epoch); err != nil {
			return fmt.Errorf("%w: %w", ociresource.ErrFenced, err)
		}
		spec, err := public.spec(profiles())
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
	var desiredSets []ociDesiredSet
	var pruneDelay time.Duration
	if config.Desired != nil {
		if desiredSets, pruneDelay, err = config.Desired.sets(cell, region); err != nil {
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
	if len(desiredSets) > 0 {
		passes = append(passes, desiredPass(cell, store, fencer, desiredSets, config.Desired.Prune, pruneDelay))
	}
	passes = append(passes,
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
		key, err := public.key(cell)
		if err != nil {
			return nil, err
		}
		lbAPI, err := lb.NewSDKAPI(factory)
		if err != nil {
			return nil, err
		}
		passes = append(passes, publicLBPass(store, fencer, key, *public, profiles),
			ociresource.ControllerPass(&ociresource.Controller[lb.Spec, lb.Observed]{
				Region: cell, Resource: lb.Reconciler{API: lbAPI}, Store: store, Ownership: ownership, Authority: fencer}))
	}
	return &ociReconcileRuntime{runner: &ociresource.Runner{Authority: fencer, Passes: passes, Interval: interval,
		Jitter: rand.Float64}, store: store, cell: cell}, nil
}
