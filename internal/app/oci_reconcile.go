package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/seclist"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// OciReconcileConfig carries signed resource amendments beside the always-on
// regional foundation. Its absence never disables foundation reconciliation.
type OciReconcileConfig struct {
	// PublicNLB keeps the public API NLB's backend set in step with the
	// RUNNING member hosts placement observes.
	PublicNLB *OciReconcileNLBConfig `json:"public_nlb,omitempty"`
	// PublicLB keeps the public API load balancer's TerraBase backend set
	// equal to the seats the signed terrabase profile names (TS-571).
	PublicLB *OciReconcileLBConfig `json:"public_lb,omitempty"`
	// Desired publishes desired specs listed in this controller
	// configuration (bound to the signed controller manifest on baked
	// controllers) into the protected foundation journal before every pass.
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
	ociReconcileInterval = time.Minute
	defaultOciPruneDelay = time.Hour
	maxOciPruneDelay     = 7 * 24 * time.Hour
)

// ociDesiredSet is one kind's validated entries.
type ociDesiredSet struct {
	kind    string
	entries []ociresource.Entry
}

func desiredEntries[S ociresource.Validator](entries map[string]OciDesiredEntry[S]) ([]ociresource.Entry, error) {
	out := make([]ociresource.Entry, 0, len(entries))
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		entry := entries[name]

		if err := entry.Spec.Validate(); err != nil {
			return nil, fmt.Errorf("OCI desired %q: %w", name, err)
		}
		out = append(out, ociresource.Entry{Name: name, Policy: ociresource.PolicyEnforce, Spec: entry.Spec})
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
