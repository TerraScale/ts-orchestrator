package mesh

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	seedRecordPrefix = "ts-orch-seeds-"
	seedsEvery       = 30 * time.Second
)

func SeedRecord(region string) string { return seedRecordPrefix + region }

type Seeds struct {
	Region  string   `json:"region"`
	Version int64    `json:"version"`
	Cluster string   `json:"cluster"`
	Hosts   []string `json:"hosts"`
}

var fleetHostName = regexp.MustCompile(`^(?:ts-([a-z]+)-[0-9]+|([a-z]+)-node-[0-9]+)$`)

func HostRegion(hostname string) string {
	match := fleetHostName.FindStringSubmatch(hostname)
	if match == nil {
		return ""
	}
	return match[1] + match[2]
}

func decodeStrict(value string, into any) error {
	return json.Unmarshal([]byte(value), into, json.RejectUnknownMembers(true))
}

func parseSeeds(region, value string) (Seeds, []string, error) {
	var seeds Seeds
	if err := decodeStrict(value, &seeds); err != nil {
		return Seeds{}, nil, fmt.Errorf("%s is not a seed record: %w", SeedRecord(region), err)
	}
	if seeds.Region != region || seeds.Version < 1 || seeds.Cluster == "" {
		return Seeds{}, nil, fmt.Errorf("%s names region %q, version %d, cluster %q", SeedRecord(region), seeds.Region, seeds.Version, seeds.Cluster)
	}
	hosts, dropped := regionHosts(region, seeds.Hosts)
	if len(hosts) == 0 {
		return Seeds{}, dropped, fmt.Errorf("%s lists no %s host", SeedRecord(region), region)
	}
	seeds.Hosts = hosts
	return seeds, dropped, nil
}

func regionHosts(region string, listed []string) (hosts, dropped []string) {
	for _, host := range listed {
		if HostRegion(host) == region {
			hosts = append(hosts, host)
		} else {
			dropped = append(dropped, host)
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts), dropped
}

func encodeRecord(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func PublishSeeds(ctx context.Context, records Records, region, cluster string, listed []string) error {
	hosts, dropped := regionHosts(region, listed)
	if len(dropped) != 0 {
		slog.WarnContext(ctx, "mesh seed hosts outside the fleet naming left out", "region", region, "hosts", dropped)
	}
	if len(hosts) == 0 || cluster == "" {
		return fmt.Errorf("%s needs a cluster and at least one %s host", SeedRecord(region), region)
	}
	value, version, err := records.Read(ctx, SeedRecord(region))
	if err != nil {
		return err
	}
	if version == 0 {
		return records.Create(ctx, SeedRecord(region), encodeRecord(Seeds{Region: region, Version: 1, Cluster: cluster, Hosts: hosts}))
	}
	if current, _, err := parseSeeds(region, value); err == nil && current.Cluster == cluster && slices.Equal(current.Hosts, hosts) {
		return nil
	}
	return records.Swap(ctx, SeedRecord(region), version, encodeRecord(Seeds{Region: region, Version: version + 1, Cluster: cluster, Hosts: hosts}))
}

func ensureOwnSeeds(ctx context.Context, cfg config) error {
	value, version, err := cfg.records.Read(ctx, SeedRecord(cfg.region))
	if err != nil {
		return err
	}
	if version != 0 {
		if current, _, err := parseSeeds(cfg.region, value); err == nil && current.Cluster == cfg.cluster {
			return nil
		}
	}
	return PublishSeeds(ctx, cfg.records, cfg.region, cfg.cluster, []string{cfg.server})
}

type seedBook struct {
	region  string
	mu      sync.Mutex
	routes  map[string]string
	refused map[string]string
	total   atomic.Int64
}

func newSeedBook(region string) *seedBook {
	return &seedBook{region: region, routes: map[string]string{}, refused: map[string]string{}}
}

func seedName(host string) string { return host + "." + netBirdDomain }

func namedRegion(serverName string) string {
	host, ok := strings.CutSuffix(serverName, "."+netBirdDomain)
	if !ok {
		return ""
	}
	return HostRegion(host)
}

func (b *seedBook) verify(serverName, certificate string) error {
	named := namedRegion(serverName)
	presented, _ := strings.CutSuffix(certificate, "."+Domain)
	if named == "" || named == presented || named == b.region {
		return nil
	}
	b.total.Add(1)
	b.mu.Lock()
	first := b.refused[serverName] != presented
	b.refused[serverName] = presented
	b.mu.Unlock()
	if first {
		slog.Warn("mesh seed host presented another region's certificate; connection refused", "host", serverName, "region", named, "certificate", certificate)
	}
	return fmt.Errorf("mesh seed %s is a %s host but its peer presented %s", serverName, named, certificate)
}

func (b *seedBook) read(ctx context.Context, records Records) map[string]string {
	peers := slices.DeleteFunc(Regions(b.region), func(peer string) bool { return peer == b.region })
	hosts := make([][]string, len(peers))
	failures := make([]error, len(peers))
	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Go(func() {
			peerCtx, cancel := context.WithTimeout(ctx, seedsEvery)
			defer cancel()
			hosts[i], failures[i] = peerHosts(peerCtx, records, peer)
		})
	}
	wg.Wait()
	b.mu.Lock()
	previous := maps.Clone(b.routes)
	b.mu.Unlock()
	next := map[string]string{}
	for i, peer := range peers {
		if failures[i] != nil {
			slog.WarnContext(ctx, "mesh peer seeds unavailable; keeping the last good seeds", "region", peer, "error", failures[i])
			for name, region := range previous {
				if region == peer {
					next[name] = peer
				}
			}
			continue
		}
		for _, host := range hosts[i] {
			next[seedName(host)] = peer
		}
	}
	return next
}

func peerHosts(ctx context.Context, records Records, peer string) ([]string, error) {
	value, version, err := records.Read(ctx, SeedRecord(peer))
	if err != nil {
		return nil, err
	}
	if version == 0 {
		return nil, fmt.Errorf("%s is not published or not readable", SeedRecord(peer))
	}
	seeds, dropped, err := parseSeeds(peer, value)
	if len(dropped) != 0 {
		slog.WarnContext(ctx, "mesh peer seed hosts from another region refused", "region", peer, "hosts", dropped)
	}
	return seeds.Hosts, err
}

func seedURL(name string) *url.URL {
	return &url.URL{Scheme: "nats", Host: net.JoinHostPort(name, strconv.Itoa(ClusterPort))}
}

func (b *seedBook) install(next map[string]string) (added []*url.URL, retired map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	retired = map[string]bool{}
	for name := range b.routes {
		if _, kept := next[name]; !kept {
			retired[name] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(next)) {
		if _, known := b.routes[name]; !known {
			added = append(added, seedURL(name))
		}
	}
	b.routes = next
	return added, retired
}

func (n *Node) refreshSeeds() {
	tick := time.NewTicker(seedsEvery)
	defer tick.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
		added, retired := n.seeds.install(n.seeds.read(n.ctx, n.cfg.records))
		if len(retired) != 0 {
			n.server.RetainRoutes(func(route *url.URL) bool { return !retired[route.Hostname()] })
		}
		if len(added) != 0 {
			n.server.AddRoutes(added)
		}
	}
}
