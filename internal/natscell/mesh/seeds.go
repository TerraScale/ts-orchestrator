package mesh

import (
	"context"
	"encoding/json"
	"errors"
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
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
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
}

func newSeedBook(region string) *seedBook {
	return &seedBook{region: region, routes: map[string]string{}, refused: map[string]string{}}
}

func (b *seedBook) regionOf(address string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.routes[address]
}

func (b *seedBook) refuse(address string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refused[address] = b.routes[address]
	delete(b.routes, address)
}

func (b *seedBook) read(ctx context.Context, records Records) map[string]string {
	b.mu.Lock()
	previous := maps.Clone(b.routes)
	b.mu.Unlock()
	next := map[string]string{}
	for _, peer := range Regions(b.region) {
		if peer == b.region {
			continue
		}
		hosts, err := peerHosts(ctx, records, peer)
		if err != nil {
			slog.WarnContext(ctx, "mesh peer seeds unavailable; keeping the last good seeds", "region", peer, "error", err)
			for address, region := range previous {
				if region == peer {
					next[address] = peer
				}
			}
			continue
		}
		for _, host := range hosts {
			addresses, err := net.DefaultResolver.LookupHost(ctx, host+"."+netBirdDomain)
			if err != nil {
				slog.WarnContext(ctx, "mesh peer seed host does not resolve", "region", peer, "host", host, "error", err)
				continue
			}
			for _, address := range addresses {
				if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
					next[address] = peer
				}
			}
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

func seedURL(address string) *url.URL {
	return &url.URL{Scheme: "nats", Host: net.JoinHostPort(address, strconv.Itoa(ClusterPort))}
}

func (b *seedBook) install(next map[string]string) (added []*url.URL, retired map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for address, region := range b.refused {
		if next[address] == region {
			delete(next, address)
		} else {
			delete(b.refused, address)
		}
	}
	retired = map[string]bool{}
	for address := range b.routes {
		if _, kept := next[address]; !kept {
			retired[address] = true
		}
	}
	for _, address := range slices.Sorted(maps.Keys(next)) {
		if _, known := b.routes[address]; !known {
			added = append(added, seedURL(address))
		}
	}
	b.routes = next
	return added, retired
}

func (n *Node) refreshSeeds() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	read := time.Now()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
		n.checkSeedRoutes()
		if time.Since(read) < seedsEvery {
			continue
		}
		read = time.Now()
		ctx, cancel := context.WithTimeout(n.ctx, seedsEvery)
		added, retired := n.seeds.install(n.seeds.read(ctx, n.cfg.records))
		cancel()
		if len(retired) != 0 {
			n.server.RetainRoutes(func(route *url.URL) bool { return !retired[route.Hostname()] })
		}
		if len(added) != 0 {
			n.server.AddRoutes(added)
		}
	}
}

func (n *Node) checkSeedRoutes() {
	for _, route := range n.routes() {
		expected := n.seeds.regionOf(route.IP)
		if !route.DidSolicit || !route.IsConfigured || expected == "" || serverRegion(route.RemoteName) == expected {
			continue
		}
		n.seeds.refuse(route.IP)
		n.refusedSeeds.Add(1)
		slog.Warn("mesh seed reached a server of another region; seed retired", "region", expected, "address", route.IP, "server", route.RemoteName)
		n.server.RetainRoutes(func(configured *url.URL) bool { return configured.Hostname() != route.IP })
	}
}
