package control

import (
	"context"
	"errors"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// SignedDeliveryRuntimeConfig supplies the concrete release and rollout ports.
// The regional runtime owns the authenticated connection, durable journal,
// command-generation admission and live authority checks.
type SignedDeliveryRuntimeConfig struct {
	Fetcher delivery.ArtifactFetcher
	Trust   func() *delivery.TrustSet
	Mirror  *delivery.ArtifactMirror
	Rollout delivery.RolloutConfig
}

func (c SignedDeliveryRuntimeConfig) Validate() error {
	if deliveryNil(c.Fetcher) || c.Trust == nil || c.Trust() == nil || c.Mirror == nil || deliveryNil(c.Mirror.Store) {
		return errors.New("signed delivery: verified release fetch, trust and mirror are required")
	}
	if _, ok := c.Mirror.Store.(delivery.RegionObjectStoreContentReader); !ok {
		return errors.New("signed delivery: all-region mirror content reads are required")
	}
	if _, ok := c.Mirror.Store.(delivery.FencedRegionObjectStore); !ok {
		return errors.New("signed delivery: mirror must enforce the durable operation fence")
	}
	if !reflect.DeepEqual(c.Rollout.Spec, c.Mirror.Spec) {
		return errors.New("signed delivery: rollout and mirror estates differ")
	}
	if deliveryNil(c.Rollout.Hosts) || deliveryNil(c.Rollout.Control) || deliveryNil(c.Rollout.Edge) || deliveryNil(c.Rollout.KV) {
		return errors.New("signed delivery: host inventory, ts-node control, edge and KV publication are required")
	}
	gates := map[string]bool{}
	for _, gate := range c.Rollout.Gates {
		if deliveryNil(gate) || gates[gate.Name()] {
			return errors.New("signed delivery: gate identity is missing or duplicated")
		}
		gates[gate.Name()] = true
	}
	if !gates["health"] || !gates["catch-up"] {
		return errors.New("signed delivery: live health and catch-up gates are required")
	}
	_, err := delivery.NewRollout(c.Rollout)
	return err
}

func deliveryNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (r *NatsRuntime) deliveryDispatcher(ctx context.Context, state *natsRuntimeState, config SignedDeliveryRuntimeConfig) (CommandIngressDispatcher, error) {
	if r == nil || r.topology == nil || r.authority == nil || state == nil || state.leaders == nil {
		return nil, errors.New("signed delivery: regional runtime is incomplete")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	store, err := newNatsDeliveryStore(ctx, state.delivery, r.client)
	if err != nil {
		return nil, err
	}
	journal, err := delivery.NewDurableJournal(store)
	if err != nil {
		return nil, err
	}
	rollout, err := delivery.NewRollout(config.Rollout)
	if err != nil {
		return nil, err
	}
	dispatcher := &signedDeliveryDispatcher{connection: r.client, cell: r.topology.Cell, instance: r.topology.Instance, authority: r.authority, leaders: state.leaders, store: state.delivery}
	executor, err := delivery.NewExecutor(delivery.ExecutorConfig{
		MirrorMode: delivery.MirrorModeVerifyAll, OwnerID: r.topology.Cell + "-" + r.topology.Instance, Fetcher: config.Fetcher, Trust: config.Trust,
		Mirror: config.Mirror, Rollout: rollout, Journal: journal, Authority: dispatcher.checkAuthority,
	})
	if err != nil {
		return nil, err
	}
	dispatcher.executor = executor
	return dispatcher.dispatch, nil
}
