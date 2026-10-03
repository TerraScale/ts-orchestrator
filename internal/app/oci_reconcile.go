package app

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nlb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nsg"
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
}

// OciReconcileNLBConfig names the NLB backend set synced to placement.
type OciReconcileNLBConfig struct {
	Name       string `json:"name"`
	NLBID      string `json:"nlb_id"`
	BackendSet string `json:"backend_set"`
	Port       int    `json:"port"`
}

const (
	minOciReconcileInterval = 30 * time.Second
	maxOciReconcileInterval = time.Hour
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

// newOCIReconcileRunner builds the leader-only reconcile runner for one
// region: NSG rule sets, and, when configured, the public NLB backends
// published from placement's fleet observation.
func newOCIReconcileRunner(ctx context.Context, config OciReconcileConfig, region oci.RegionConfig,
	js jetstream.JetStream, replicas int, fencer authority.Fencer, fleet oci.Fleet,
) (*ociresource.Runner, error) {
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
	cell := string(region.Region)
	passes := []ociresource.Pass{ociresource.ControllerPass(&ociresource.Controller[nsg.Spec, nsg.Observed]{
		Region: cell, Resource: nsg.Reconciler{API: nsgAPI}, Store: store, Ownership: ownership, Authority: fencer})}
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
	return &ociresource.Runner{Authority: fencer, Passes: passes, Interval: interval, Jitter: rand.Float64}, nil
}
