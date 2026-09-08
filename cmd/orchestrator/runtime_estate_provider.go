package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// productionEstateFile admits the ordinary public database destination before
// the broker starts. Credentials are read again for each mutation, so an atomic
// replacement by key rotation takes effect without restarting the publisher.
type productionEstateFile struct {
	Endpoint  string `json:"endpoint"`
	Database  string `json:"database"`
	ProjectID string `json:"projectId"`
	TokenFile string `json:"tokenFile"`
}

func (c productionEstateFile) validate() error {
	endpoint, err := url.ParseRequestURI(c.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("production estate: endpoint must be an HTTPS public API origin")
	}
	if c.Database == "" || strings.TrimSpace(c.Database) != c.Database || len(c.Database) > 256 || strings.ContainsAny(c.Database, "/\\\r\n\x00") {
		return errors.New("production estate: database scope is required and must be a single name")
	}
	if c.ProjectID == "" || len(c.ProjectID) > 256 || strings.ContainsAny(c.ProjectID, " \t\r\n\x00") {
		return errors.New("production estate: project scope is required")
	}
	if !filepath.IsAbs(c.TokenFile) {
		return errors.New("production estate: token file must be absolute")
	}
	_, err = readProductionEstateToken(c.TokenFile)
	return err
}

func readProductionEstateToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("production estate: token file cannot be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("production estate: token file must be a private regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return "", errors.New("production estate: token file exceeds bound or cannot be read")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, " \t\r\n\x00") {
		return "", errors.New("production estate: token file must contain one bearer credential")
	}
	return token, nil
}

// constructProductionEstateClient is called only by the acquired global lease
// session. Its close function releases this session's idle HTTP connections.
func constructProductionEstateClient(config productionEstateFile) (*estate.ControlPlaneClient, func() error, error) {
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	closeClient := func() error { transport.CloseIdleConnections(); return nil }
	client, err := estate.NewControlPlaneClient(estate.ControlPlaneClientConfig{
		BaseURL: config.Endpoint, Database: config.Database, ProjectID: config.ProjectID,
		Token: func() string {
			token, err := readProductionEstateToken(config.TokenFile)
			if err != nil {
				return ""
			}
			return token
		},
		HTTP: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	})
	if err != nil {
		_ = closeClient()
		return nil, nil, fmt.Errorf("production estate: public document client: %w", err)
	}
	return client, closeClient, nil
}

// productionEstateSource projects one complete authenticated observation pass.
// Database inventory and windowed SLOs are explicitly unknown: host status
// measures engine health, clock, disk, and component convergence only.
type productionEstateSource struct {
	health    *observedKVHealthSource
	databases databaseadmission.Journal
}

func constructProductionEstateSource(spec estate.Spec, healthFile string, databases databaseadmission.Journal) (*productionEstateSource, error) {
	if databases == nil {
		return nil, errors.New("production estate: live database admission journal is required")
	}
	health, err := newObservedKVHealthSource(spec, nil, func(key string) (string, bool) {
		return healthFile, key == reconcileHealthConfigEnvironment && healthFile != ""
	})
	if err != nil {
		return nil, err
	}
	return &productionEstateSource{health: health, databases: databases}, nil
}

type productionEstateHost struct {
	ID       string               `json:"id"`
	Region   string               `json:"region"`
	Observed bool                 `json:"observed"`
	State    string               `json:"state,omitempty"`
	Quiesced bool                 `json:"quiesced"`
	Facts    *hostagent.HostFacts `json:"facts,omitzero"`
}

func (s *productionEstateSource) Snapshot(ctx context.Context) (estate.Snapshot, error) {
	if s == nil || s.health == nil {
		return estate.Snapshot{}, errors.New("production estate: live observation source is unavailable")
	}
	config, err := s.health.configuration()
	if err != nil {
		return estate.Snapshot{}, err
	}
	slices.SortFunc(config.Regions, func(a, b healthRegion) int { return strings.Compare(a.Code, b.Code) })
	hosts := make([]productionEstateHost, 0)
	regions := make([]map[string]any, 0, len(config.Regions))
	engines := make([]map[string]any, 0)
	rollouts := make([]map[string]any, 0)
	slo := make([]map[string]any, 0)
	reconcile := make([]map[string]any, 0)
	tick, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, region := range config.Regions {
		reports, err := s.health.sample(tick, region)
		if err != nil {
			return estate.Snapshot{}, fmt.Errorf("production estate: observe region %s: %w", region.Code, err)
		}
		byID := make(map[string]hostagent.NodeStatusReport, len(reports))
		for _, report := range reports {
			if slices.IndexFunc(region.Members, func(m healthMember) bool { return m.ID == report.NodeId }) < 0 {
				return estate.Snapshot{}, errors.New("production estate: unadmitted host observation")
			}
			if _, exists := byID[report.NodeId]; exists {
				return estate.Snapshot{}, errors.New("production estate: duplicate host observation")
			}
			byID[report.NodeId] = report
		}
		slices.SortFunc(region.Members, func(a, b healthMember) int { return strings.Compare(a.ID, b.ID) })
		regions = append(regions, map[string]any{"code": region.Code, "admittedHosts": len(region.Members), "observedHosts": len(reports)})
		for _, member := range region.Members {
			report, observed := byID[member.ID]
			host := productionEstateHost{ID: member.ID, Region: region.Code, Observed: observed}
			if observed {
				host.State = report.State
				host.Quiesced = report.Quiesced
				facts := report.Facts
				slices.SortFunc(facts.Components, func(a, b hostagent.ComponentFact) int { return strings.Compare(a.Name, b.Name) })
				host.Facts = &facts
				engine := facts.Engine
				now := time.Now()
				if engine.ObservedAtUnixMS <= 0 || time.UnixMilli(engine.ObservedAtUnixMS).After(now.Add(time.Second)) || now.Sub(time.UnixMilli(engine.ObservedAtUnixMS)) > 30*time.Second {
					engine = hostagent.EngineFacts{}
				}
				// Observation time drives freshness only, never the document revision.
				engine.ObservedAtUnixMS = 0
				host.Facts.Engine = engine
				engines = append(engines, map[string]any{"host": member.ID, "region": region.Code, "health": engine})
				rollouts = append(rollouts, map[string]any{"host": member.ID, "region": region.Code, "components": facts.Components, "agentVersion": facts.TsNodeVersion})
				slo = append(slo, map[string]any{"host": member.ID, "clockMeasured": facts.ClockMeasured, "clockUnhealthy": facts.ClockUnhealthy, "clockOffsetMillis": facts.ClockOffsetMillis, "lagMeasured": engine.LagMeasured, "lagMs": engine.LagMS, "disk": facts.Disk})
				converged := len(facts.Components) > 0
				for _, component := range facts.Components {
					converged = converged && component.Installed && component.UnitActive && component.Version == component.Desired
				}
				reconcile = append(reconcile, map[string]any{"host": member.ID, "manifestSha256": facts.ManifestSha256, "componentsConverged": converged})
			}
			hosts = append(hosts, host)
		}
	}
	databases := make([]map[string]any, 0)
	if s.databases != nil {
		records, err := s.databases.List(tick)
		if err != nil {
			return estate.Snapshot{}, fmt.Errorf("production estate: database admission inventory: %w", err)
		}
		for _, record := range records {
			databases = append(databases, map[string]any{"id": record.DatabaseID, "name": record.Request.Name, "environment": record.Request.Environment, "regions": record.Request.Regions, "admissionState": record.State, "revision": record.Revision})
		}
	}
	if err := tick.Err(); err != nil {
		return estate.Snapshot{}, err
	}
	return estate.Snapshot{
		Regions: map[string]any{"regions": regions}, Hosts: map[string]any{"hosts": hosts},
		Databases: map[string]any{"admissionInventoryMeasured": s.databases != nil, "servingInventoryMeasured": false, "databases": databases, "engines": engines},
		Rollouts:  map[string]any{"hosts": rollouts}, SLO: map[string]any{"windowMeasured": false, "hosts": slo}, Reconcile: map[string]any{"hosts": reconcile},
	}, nil
}

// productionKVFile pins the account and durable accepted placement projection.
// The placement producer must atomically replace PlacementFile after accepting
// a membership transition; pending admission records are never routed.
type productionKVFile struct {
	AccountID     string `json:"accountId"`
	ZoneID        string `json:"zoneId"`
	TokenFile     string `json:"tokenFile"`
	PlacementFile string `json:"placementFile"`
	Catalog       []cloudflare.WorkerRegionCatalog `json:"catalog"`
}

func (c productionKVFile) validate() error {
	for _, id := range []string{c.AccountID, c.ZoneID} {
		if len(id) != 32 {
			return errors.New("production KV: exact account and zone IDs are required")
		}
		for _, ch := range id {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				return errors.New("production KV: account or zone ID is invalid")
			}
		}
	}
	if !filepath.IsAbs(c.TokenFile) {
		return errors.New("production KV: token file must be absolute")
	}
	if _, err := readProductionEstateToken(c.TokenFile); err != nil {
		return err
	}
	_, err := newFileKVPlacementSource(c.PlacementFile)
	return err
}

type productionKVTransport struct {
	transport *http.Transport
	session   globalWorkerSession
	tokenFile string
}

func (t *productionKVTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.session.CheckEffectAuthority(request.Context()); err != nil {
		return nil, err
	}
	token, err := readProductionEstateToken(t.tokenFile)
	if err != nil {
		return nil, err
	}
	cloned := request.Clone(request.Context())
	cloned.Header.Set("Authorization", "Bearer "+token)
	return t.transport.RoundTrip(cloned)
}

// constructProductionKVWriter starts no goroutines. Root runs writer.Step on
// its ten-second lease-owned service and closes it before releasing transport.
func constructProductionKVWriter(config productionKVFile, spec estate.Spec, healthFile string, session globalWorkerSession) (*cloudflare.KVWriter, func() error, error) {
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	health, err := newObservedKVHealthSource(spec, nil, func(key string) (string, bool) {
		return healthFile, key == reconcileHealthConfigEnvironment && healthFile != ""
	})
	if err != nil {
		return nil, nil, err
	}
	regions := make([]string, 0, len(spec.Regions))
	for _, region := range spec.Regions {
		regions = append(regions, region.Code)
	}
	placement, err := newFileKVPlacementSource(config.PlacementFile, regions)
	if err != nil {
		return nil, nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	token, err := readProductionEstateToken(config.TokenFile)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	client := cloudflare.NewClient(token, config.ZoneID, config.AccountID)
	client.HTTP = &productionKVTransport{transport: transport, session: session, tokenFile: config.TokenFile}
	writer, err := cloudflare.NewKVWriter(cloudflare.KVWriterConfig{Store: client, Health: health, Placement: placement, Catalog: config.Catalog, HealthInterval: cloudflare.DefaultKVWriterHealthInterval})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	closeWriter := func() error { err := writer.Close(); transport.CloseIdleConnections(); return err }
	return writer, closeWriter, nil
}
