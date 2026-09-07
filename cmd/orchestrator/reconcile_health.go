package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

const reconcileHealthConfigEnvironment = "TS_ORCH_HEALTH_CONFIG_FILE"

type healthMember struct {
	ID           string                        `json:"id"`
	Address      string                        `json:"address"`
	Architecture *runtimeplan.HostArchitecture `json:"architecture"`
}
type healthRegion struct {
	Code       string                         `json:"code"`
	Latitude   *float64                       `json:"latitude"`
	Longitude  *float64                       `json:"longitude"`
	Connection bootstrapcredentials.Reference `json:"connection"`
	Members    []healthMember                 `json:"members"`
}
type healthObservationConfig struct {
	Regions []healthRegion `json:"regions"`
}

// observedKVHealthSource rereads host admission and credential configuration on
// each tick, then accepts only nonce-bound replies through authenticated NATS.
// No previous successful status is cached across ticks or transport failures.
type observedKVHealthSource struct {
	spec   estate.Spec
	pools  cloudflare.Members
	path   string
	sample func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error)
	// proof is supplied by the lease-owned composition root. Host reports carry
	// replica and backup receipts, but cannot assert placement residency or
	// control quorum for themselves.
	proof autoscaleProofProducer
}

func newObservedKVHealthSource(spec estate.Spec, pools cloudflare.Members, lookup envLookup) (*observedKVHealthSource, error) {
	path, ok := lookup(reconcileHealthConfigEnvironment)
	if !ok || path == "" {
		return nil, fmt.Errorf("reconcile: %s is required for authenticated host observations", reconcileHealthConfigEnvironment)
	}
	source := &observedKVHealthSource{spec: spec, pools: pools, path: path, sample: sampleRegionHosts}
	config, err := source.configuration()
	if err != nil {
		return nil, err
	}
	for _, region := range config.Regions {
		credentials, err := bootstrapcredentials.Load(region.Connection)
		if err != nil {
			return nil, fmt.Errorf("reconcile: health credentials for %s: %w", region.Code, err)
		}
		credentials.Close()
	}
	return source, nil
}
func (s *observedKVHealthSource) configuration() (healthObservationConfig, error) {
	var config healthObservationConfig
	raw, err := bootstrapcredentials.ReadFile(s.path, true, 1<<20)
	if err != nil {
		return config, err
	}
	if json.Unmarshal(raw, &config, json.RejectUnknownMembers(true)) != nil {
		return config, errors.New("reconcile: malformed host health configuration")
	}
	expected := map[string]bool{}
	for _, region := range s.spec.Regions {
		expected[region.Code] = true
	}
	seen := map[string]bool{}
	for _, region := range config.Regions {
		if !expected[region.Code] || seen[region.Code] || len(region.Members) == 0 || len(region.Members) > 1024 || region.Latitude == nil || region.Longitude == nil || math.IsNaN(*region.Latitude) || math.IsNaN(*region.Longitude) || *region.Latitude < -90 || *region.Latitude > 90 || *region.Longitude < -180 || *region.Longitude > 180 {
			return config, errors.New("reconcile: invalid host health region")
		}
		seen[region.Code] = true
		hosts := map[string]bool{}
		addresses := map[string]bool{}
		for _, member := range region.Members {
			_, err := hostagent.NewNodeId(member.ID)
			address, addressErr := netip.ParseAddr(member.Address)
			if err != nil || !strings.HasPrefix(member.ID, region.Code+"-") || hosts[member.ID] || addressErr != nil || !address.IsGlobalUnicast() || addresses[member.Address] || member.Architecture == nil || (*member.Architecture != runtimeplan.HostArchitectureArm64 && *member.Architecture != runtimeplan.HostArchitectureX64) {
				return config, errors.New("reconcile: invalid admitted health member")
			}
			hosts[member.ID] = true
			addresses[member.Address] = true
		}
		if s.pools != nil {
			pool := s.pools[region.Code]
			if len(pool) != len(addresses) {
				return config, errors.New("reconcile: observed host admission differs from load balancer pool")
			}
			for _, address := range pool {
				if !addresses[address] {
					return config, errors.New("reconcile: observed host admission differs from load balancer pool")
				}
			}
		}
	}
	if len(seen) != len(expected) {
		return config, errors.New("reconcile: health configuration must cover every estate region")
	}
	return config, nil
}

func sampleRegionHosts(ctx context.Context, region healthRegion) ([]hostagent.NodeStatusReport, error) {
	credentials, err := bootstrapcredentials.Load(region.Connection)
	if err != nil {
		return nil, err
	}
	defer credentials.Close()
	connection, err := dialBootstrapStore(ctx, bootstrap.ControlNATSStore{URL: credentials.URL, Options: credentials.Options})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	observer, err := hostcontrol.NewObserver(strings.ToUpper(region.Code), connection, func(ctx context.Context, id string) (hostcontrol.Host, error) {
		if err := ctx.Err(); err != nil {
			return hostcontrol.Host{}, err
		}
		for _, member := range region.Members {
			if member.ID == id {
				node, _ := hostagent.NewNodeId(id)
				return hostcontrol.Host{NodeID: node, Region: strings.ToUpper(region.Code), Architecture: *member.Architecture}, nil
			}
		}
		return hostcontrol.Host{}, errors.New("reconcile: host is no longer admitted")
	}, 10*time.Second)
	if err != nil {
		return nil, err
	}
	reports := make([]hostagent.NodeStatusReport, 0, len(region.Members))
	var mu sync.Mutex
	var workers sync.WaitGroup
	for worker := range min(8, len(region.Members)) {
		workers.Go(func() {
			for index := worker; index < len(region.Members); index += 8 {
				if ctx.Err() != nil {
					return
				}
				report, err := observer.Status(ctx, region.Members[index].ID)
				if err != nil {
					continue
				}
				mu.Lock()
				reports = append(reports, report)
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	return reports, nil
}

func (s *observedKVHealthSource) ObserveRegionHealth(ctx context.Context) (map[string]cloudflare.RegionHealth, error) {
	if ctx == nil {
		return nil, errors.New("reconcile: health context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := s.configuration()
	if err != nil {
		return nil, err
	}
	result := make(map[string]cloudflare.RegionHealth, len(config.Regions))
	tick, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var mu sync.Mutex
	var workers sync.WaitGroup
	for _, region := range config.Regions {
		workers.Go(func() {
			entry := cloudflare.RegionHealth{Region: region.Code, Lat: *region.Latitude, Lon: *region.Longitude}
			reports, err := s.sample(tick, region)

			if err != nil {
				mu.Lock()
				result[region.Code] = entry
				mu.Unlock()
				return
			}
			now := time.Now().UTC()
			measuredLag := 0
			seen := map[string]bool{}
			for _, report := range reports {
				engine := report.Facts.Engine
				observedAt := time.UnixMilli(engine.ObservedAtUnixMS)
				if !engine.Measured || engine.ObservedAtUnixMS <= 0 || observedAt.After(now.Add(time.Second)) || now.Sub(observedAt) > 30*time.Second || engine.LagMS < 0 {
					continue
				}
				memberIndex := slices.IndexFunc(region.Members, func(member healthMember) bool { return member.ID == report.NodeId })
				if memberIndex < 0 || seen[report.NodeId] {
					continue
				}
				seen[report.NodeId] = true
				draining := report.State != hostagent.NodeStateServing || report.Quiesced || engine.Draining
				disk := report.Facts.Disk
				overloaded := disk.TotalBytes > 0 && disk.AvailableBytes <= 0
				entry.Draining = entry.Draining || draining
				entry.Overloaded = entry.Overloaded || overloaded
				if !engine.Serving || draining || overloaded || !report.Facts.ClockMeasured || report.Facts.ClockUnhealthy {
					continue
				}
				entry.Healthy = true
				entry.Members = append(entry.Members, region.Members[memberIndex].Address)
				if engine.LagMeasured {
					measuredLag++
					entry.LagMS = max(entry.LagMS, engine.LagMS)
				}
				if entry.UpdatedAt.IsZero() || observedAt.Before(entry.UpdatedAt) {
					entry.UpdatedAt = observedAt
				}
			}
			// The regional load balancer still contains all admitted members. Do
			// not advertise a region while it may select an unobserved host.
			entry.Healthy = len(entry.Members) == len(region.Members)
			entry.LagMeasured = entry.Healthy && measuredLag == len(region.Members)
			slices.Sort(entry.Members)
			mu.Lock()
			result[region.Code] = entry
			mu.Unlock()
		})
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
