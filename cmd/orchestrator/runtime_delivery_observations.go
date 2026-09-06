package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

type productionDeliveryMembership struct{ source *observedKVHealthSource }

func newProductionDeliveryMembership(spec estate.Spec, path string) (*productionDeliveryMembership, error) {
	source := &observedKVHealthSource{spec: spec, path: path}
	config, err := source.configuration()
	if err != nil {
		return nil, err
	}
	for _, region := range config.Regions {
		credentials, err := bootstrapcredentials.Load(region.Connection)
		if err != nil {
			return nil, err
		}
		credentials.Close()
	}
	return &productionDeliveryMembership{source: source}, nil
}

func (m *productionDeliveryMembership) configuration(ctx context.Context) (healthObservationConfig, error) {
	if ctx == nil {
		return healthObservationConfig{}, errors.New("delivery: context required")
	}
	if err := ctx.Err(); err != nil {
		return healthObservationConfig{}, err
	}
	return m.source.configuration()
}

func (m *productionDeliveryMembership) Hosts(ctx context.Context, region string) ([]string, error) {
	config, err := m.configuration(ctx)
	if err != nil {
		return nil, err
	}
	for _, admitted := range config.Regions {
		if admitted.Code != region {
			continue
		}
		hosts := make([]string, 0, len(admitted.Members))
		for _, member := range admitted.Members {
			hosts = append(hosts, member.ID)
		}
		slices.Sort(hosts)
		return hosts, nil
	}
	return nil, errors.New("delivery: region is not admitted")
}

func (m *productionDeliveryMembership) ResolveHost(ctx context.Context, id string) (hostcontrol.Host, error) {
	config, err := m.configuration(ctx)
	if err != nil {
		return hostcontrol.Host{}, err
	}
	for _, region := range config.Regions {
		for _, member := range region.Members {
			if member.ID == id {
				node, err := hostagent.NewNodeId(id)
				if err != nil {
					return hostcontrol.Host{}, err
				}
				return hostcontrol.Host{NodeID: node, Region: strings.ToUpper(region.Code), Architecture: *member.Architecture}, nil
			}
		}
	}
	return hostcontrol.Host{}, errors.New("delivery: host is no longer admitted")
}

type productionDeliveryObservations struct {
	membership *productionDeliveryMembership
	status     func(context.Context, string) (hostagent.NodeStatusReport, error)
	catalog    interface {
		ResolveTarget(context.Context, hostcontrol.Host, string) (hostcontrol.Release, error)
	}
}

func (o *productionDeliveryObservations) observe(ctx context.Context, id string) (hostcontrol.Host, hostagent.NodeStatusReport, error) {
	host, err := o.membership.ResolveHost(ctx, id)
	if err != nil {
		return host, hostagent.NodeStatusReport{}, err
	}
	report, err := o.status(ctx, id)
	if err != nil {
		return host, report, err
	}
	engine := report.Facts.Engine
	observed := time.UnixMilli(engine.ObservedAtUnixMS)
	now := time.Now()
	if report.NodeId != id || (report.State != hostagent.NodeStateServing && report.State != hostagent.NodeStateDraining) || report.Facts.State != report.State || report.Quiesced || !engine.Measured || !engine.Serving || engine.Draining || engine.ObservedAtUnixMS <= 0 || observed.After(now.Add(time.Second)) || now.Sub(observed) > 30*time.Second || !report.Facts.ClockMeasured || report.Facts.ClockUnhealthy || report.Facts.Disk.TotalBytes <= 0 || report.Facts.Disk.AvailableBytes <= 0 {
		return host, report, errors.New("delivery: fresh serving host health is not established")
	}
	return host, report, nil
}

func (o *productionDeliveryObservations) Healthy(ctx context.Context, id, digest string) error {
	host, report, err := o.observe(ctx, id)
	if err != nil {
		return err
	}
	release, err := o.catalog.ResolveTarget(ctx, host, digest)
	if err != nil {
		return err
	}
	manifestSHA, err := hostmanifest.HostManifestSha256(release.Manifest)
	if err != nil {
		return err
	}
	if report.Facts.ManifestSha256 != manifestSHA || len(report.Facts.Components) != len(release.Manifest.Components) {
		return errors.New("delivery: observed manifest differs from signed release")
	}
	seen := make(map[string]bool)
	for _, target := range release.Manifest.Components {
		found := false
		for _, fact := range report.Facts.Components {
			if fact.Name != target.Name {
				continue
			}
			if seen[fact.Name] || fact.Version != target.Version || fact.Desired != target.Version || !fact.Installed || !fact.UnitActive {
				return errors.New("delivery: release component is not active")
			}
			seen[fact.Name] = true
			found = true
		}
		if !found {
			return errors.New("delivery: release component is unobserved")
		}
	}
	return nil
}

func (o *productionDeliveryObservations) CaughtUp(ctx context.Context, id string) error {
	_, report, err := o.observe(ctx, id)
	if err != nil {
		return err
	}
	if !report.Facts.Engine.LagMeasured || report.Facts.Engine.LagMS != 0 {
		return errors.New("delivery: replication catchup is not measured complete")
	}
	// TBEP currently exposes neither backup catchup completion nor a measured
	// replication catchup contract. Zero lag alone cannot establish both.
	return errors.New("delivery: backup catchup completion is unobserved")
}

func newProductionDeliveryGates(membership *productionDeliveryMembership, client *hostcontrol.Client, catalog *hostcontrol.SignedReleaseCatalog) []delivery.Gate {
	observations := &productionDeliveryObservations{membership: membership, status: client.Status, catalog: catalog}
	return []delivery.Gate{delivery.HealthGate{Source: observations}, delivery.CatchUpGate{Source: observations}}
}
