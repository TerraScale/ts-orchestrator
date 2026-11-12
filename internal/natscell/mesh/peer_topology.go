package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type topologyPeer struct {
	Node    string `json:"node"`
	Region  string `json:"region"`
	Address string `json:"address"`
}

type peerTopology struct {
	Generation int64          `json:"generation"`
	ObservedAt time.Time      `json:"observedAt"`
	Regions    []string       `json:"regions"`
	Peers      []topologyPeer `json:"peers"`
}

// PeerAttestation has only counts and fixed diagnostics, never peer-controlled labels.
type PeerAttestation struct {
	Topology  string    `json:"topology"`
	Expected  int       `json:"expected"`
	Rejected  int       `json:"rejected"`
	Mismatch  int       `json:"mismatch"`
	CheckedAt time.Time `json:"checkedAt"`
}

// Publish while holding n.mu; monitoring never waits for reconciliation RPCs.
func (n *Node) publishTopologyDesired() {
	entries := make(map[string]Entry, len(n.desired))
	invalid := make(map[string]error, len(n.specInvalid))
	for name, state := range n.desired {
		if err := validState(name, state); err != nil {
			invalid[name] = err
			continue
		}
		entries[name] = state.entry()
	}
	n.specInvalid = invalid
	n.topologyDesired.Store(&entries)
	n.specInvalidPublished.Store(&invalid)
}

func (n *Node) awaitPeerAdmission(ctx context.Context, spec *swarmruntime.ServiceSpec) error {
	if spec == nil || len(spec.Regions) > 0 && !slices.Contains(spec.Regions, n.cfg.region) {
		return nil
	}
	for {
		up, _, _ := n.pingPeers(ctx, time.Second)
		if ctx.Err() != nil {
			return errors.New("admitted peer topology is incomplete")
		}
		if err := n.peers.admit(up, n.regions()); err != nil {
			return err
		}
		n.peers.mu.Lock()
		_, complete := n.peers.expected(spec.Regions)
		n.peers.mu.Unlock()
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("admitted peer topology is incomplete")
		case <-time.After(n.cfg.peersEvery):
		}
	}
}

func newPeers(cfg config) (*peers, error) {
	p := &peers{root: cfg.peersDir, region: cfg.region, node: cfg.server, address: cfg.address, worker: cfg.applier == nil,
		registry: filepath.Join(cfg.dir, "admitted-peers.json"), admitted: map[string]peer{}, regions: append([]string{cfg.region}, slices.Sorted(maps.Keys(cfg.seeds))...)}
	data, err := os.ReadFile(p.registry)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var admitted []topologyPeer
		if err := protocol.DecodeStrict(data, &admitted, maxWire); err != nil {
			return nil, err
		}
		for _, at := range admitted {
			if _, duplicate := p.admitted[at.Region]; duplicate || !validPeer(at.Region, peer{at.Node, at.Address}) {
				return nil, errors.New("invalid admitted peer registry")
			}
			p.admitted[at.Region] = peer{at.Node, at.Address}
			p.regions = append(p.regions, at.Region)
		}
	}
	if !p.worker {
		if address, addressErr := p.address(); addressErr == nil {
			if err := p.admit(map[string]peer{p.region: {p.node, address}}, p.regions); err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(p.regions)
	p.regions = slices.Compact(p.regions)
	return p, nil
}

// admit learns identities only from authenticated mesh replies, preserving them
// through outages/restarts. Reachability cannot authorize a membership removal.
func (p *peers) admit(answered map[string]peer, regions []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := maps.Clone(p.admitted)
	for region, at := range answered {
		if validPeer(region, at) {
			next[region] = at
		}
	}
	if !reflect.DeepEqual(next, p.admitted) {
		data, err := protocol.EncodeJSON(topologyPeers(next))
		if err != nil {
			return err
		}
		if err := writePrivate(p.registry, data); err != nil {
			return err
		}
		p.admitted = next
	}
	p.regions = slices.Sorted(maps.Keys(next))
	p.regions = append(p.regions, regions...)
	slices.Sort(p.regions)
	p.regions = slices.Compact(p.regions)
	return nil
}

func topologyPeers(admitted map[string]peer) []topologyPeer {
	out := make([]topologyPeer, 0, len(admitted))
	for _, region := range slices.Sorted(maps.Keys(admitted)) {
		at := admitted[region]
		out = append(out, topologyPeer{at.node, region, at.address})
	}
	return out
}

// expected uses placement and the separate admission registry, never p.up or seed.
// The caller holds p.mu.
func (p *peers) expected(regions []string) ([]byte, bool) {
	return p.expectedFor("", regions)
}

// expectedFor is expected for service, whose per-node file also lists each
// region's joined workers after its founder. The caller holds p.mu.
func (p *peers) expectedFor(service string, regions []string) ([]byte, bool) {
	if len(regions) == 0 {
		regions = p.regions
	}
	founders := map[string]peer{}
	for _, region := range regions {
		at, ok := p.admitted[region]
		if !ok {
			return nil, false
		}
		founders[region] = at
	}
	return p.render(service, founders), len(founders) > 0
}

func (n *Node) attestPeers() {
	n.peers.mu.Lock()
	defer n.peers.mu.Unlock()
	reports := map[string]PeerAttestation{}
	for name, entry := range *n.topologyDesired.Load() {
		if entry.Spec == nil || len(entry.Spec.Regions) > 0 && !slices.Contains(entry.Spec.Regions, n.cfg.region) {
			continue
		}
		regions := entry.Spec.Regions
		if len(regions) == 0 {
			regions = n.peers.regions
		}
		topology := peerTopology{Generation: entry.Generation, ObservedAt: time.Now().UTC(), Regions: slices.Clone(regions), Peers: []topologyPeer{}}
		for _, at := range topologyPeers(n.peers.admitted) {
			if slices.Contains(regions, at.Region) {
				topology.Peers = append(topology.Peers, at)
			}
		}
		expected, complete := n.peers.expectedFor(name, regions)
		current, err := os.ReadFile(filepath.Join(n.peers.root, name, "peers"))
		report := PeerAttestation{Expected: len(regions), CheckedAt: topology.ObservedAt, Rejected: n.peers.rejected[name], Topology: fmt.Sprintf("%x", sha256.Sum256(expected))}
		if !complete || err != nil || !bytes.Equal(current, expected) {
			report.Mismatch = 1
		}
		data, encodeErr := protocol.EncodeJSON(topology)
		dir := filepath.Join(n.peers.root, name)
		if encodeErr != nil || os.MkdirAll(dir, 0755) != nil || os.Chmod(dir, 0755) != nil || writePublic(filepath.Join(dir, "topology.json"), data) != nil {
			report.Mismatch = 1
		}
		reports[name] = report
	}
	n.peerReportMu.Lock()
	defer n.peerReportMu.Unlock()
	if n.peerReports == nil {
		n.peerReports = map[string]map[string]PeerAttestation{}
	}
	n.peerReports[n.cfg.region] = reports
}

func writePublic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".topology-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	err = temp.Chmod(0644)
	if err == nil {
		_, err = temp.Write(data)
	}
	err = errors.Join(err, temp.Close())
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func (n *Node) localAttestations() map[string]PeerAttestation {
	n.peerReportMu.Lock()
	defer n.peerReportMu.Unlock()
	return maps.Clone(n.peerReports[n.cfg.region])
}

// Only desired service names and admitted region names become metric labels.
func (n *Node) writePeerMetrics(w io.Writer) {
	if invalid := n.specInvalidPublished.Load(); invalid != nil {
		for _, service := range slices.Sorted(maps.Keys(*invalid)) {
			fmt.Fprintf(w, "ts_orch_service_spec_invalid{service=%q} 1\n", service)
		}
	}
	n.peers.mu.Lock()
	defer n.peers.mu.Unlock()
	n.peerReportMu.Lock()
	defer n.peerReportMu.Unlock()
	for service, entry := range *n.topologyDesired.Load() {
		if entry.Spec == nil {
			continue
		}
		regions := entry.Spec.Regions
		if len(regions) == 0 {
			regions = n.peers.regions
		}
		expected, complete := n.peers.expectedFor(service, regions)
		digest := fmt.Sprintf("%x", sha256.Sum256(expected))
		for _, region := range regions {
			report, ok := n.peerReports[region][service]
			if !ok || !complete || report.Topology != digest || report.Expected != len(regions) || report.CheckedAt.After(time.Now().Add(5*time.Second)) || report.Mismatch != 0 {
				report.Mismatch = 1
			}
			fmt.Fprintf(w, "ts_orch_peer_topology_mismatch{region=%q,service=%q} %d\n", region, service, report.Mismatch)
			fmt.Fprintf(w, "ts_orch_peer_topology_expected{region=%q,service=%q} %d\n", region, service, report.Expected)
			fmt.Fprintf(w, "ts_orch_peer_topology_generation_rejected{region=%q,service=%q} %d\n", region, service, min(1, max(0, report.Rejected)))
			fmt.Fprintf(w, "ts_orch_peer_topology_age_seconds{region=%q,service=%q} %.3f\n", region, service, max(0, time.Since(report.CheckedAt).Seconds()))
		}
	}
}

func (n *Node) servePeerMetrics(ctx context.Context) {
	server := &http.Server{Addr: "127.0.0.1:9097", ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			n.writePeerMetrics(w)
		})}
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.ErrorContext(ctx, "peer topology metrics listener failed", "address", server.Addr, "error", err)
	}
}
