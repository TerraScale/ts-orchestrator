package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// Regional host delivery never owns Cloudflare account mutations. The global
// master completes edge releases once under its durable operation and lease.
type regionalDeliveryEdge struct{}

func (regionalDeliveryEdge) PromoteWorker(context.Context, string, string) error {
	return errors.New("delivery: edge release must execute under global master authority")
}
func (regionalDeliveryEdge) PromoteSnippet(context.Context, string, string) error {
	return errors.New("delivery: edge release must execute under global master authority")
}

type productionGlobalDeliveryEdge struct {
	workers      *cloudflare.EdgeReleasePromoter
	capabilities *cloudflare.SnippetCapabilityStore
	authorize    func(context.Context) error
}

func (r *constructedProductionDelivery) GlobalEdge(mirror *delivery.ArtifactMirror, capabilities *cloudflare.SnippetCapabilityStore, authorize func(context.Context) error) (delivery.EdgePromoter, error) {
	if r == nil || r.plan == nil || r.plan.cell != "gru" || mirror == nil || capabilities == nil || authorize == nil {
		return nil, errors.New("delivery: global edge requires GRU mirror, shared capability store and live authority")
	}
	f := r.plan.file.Cloudflare
	token, err := readProductionDeliveryToken(f.TokenFile)
	if err != nil {
		return nil, err
	}
	zone, err := cloudflare.Production(nil, f.TailscaleEgressCIDRs)
	if err != nil {
		return nil, err
	}
	workers, err := cloudflare.NewEdgeReleasePromoter(cloudflare.EdgeReleasePromoterConfig{Client: cloudflare.NewClient(token, f.ZoneID, f.AccountID), Zone: zone, Artifacts: productionDeliveryMirrorSource{mirror: mirror, region: "gru"}, SnippetServices: f.SnippetServices, WorkerStages: f.WorkerStages})
	if err != nil {
		return nil, err
	}
	return &productionGlobalDeliveryEdge{workers: workers, capabilities: capabilities, authorize: authorize}, nil
}
func (e *productionGlobalDeliveryEdge) check(ctx context.Context) error {
	if err := delivery.CheckExecutionFence(ctx); err != nil {
		return err
	}
	return e.authorize(ctx)
}
func (e *productionGlobalDeliveryEdge) PromoteWorker(ctx context.Context, service, digest string) error {
	return e.PromoteWorkerGradual(ctx, service, digest)
}
func (e *productionGlobalDeliveryEdge) PromoteWorkerGradual(ctx context.Context, service, digest string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.workers.PromoteWorkerGradual(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}
func (e *productionGlobalDeliveryEdge) PromoteSnippet(ctx context.Context, service, digest string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.capabilities.PromoteTemplate(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}
func (e *productionGlobalDeliveryEdge) CoordinateSnippetZoneRules(ctx context.Context, service, digest string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.capabilities.CoordinateTemplateRules(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}
