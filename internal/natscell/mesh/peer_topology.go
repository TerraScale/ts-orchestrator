package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
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
	Topology        string    `json:"topology"`
	Expected        int       `json:"expected"`
	RuntimeMismatch int       `json:"runtimeMismatch"`
	Rejected        int       `json:"rejected"`
	Mismatch        int       `json:"mismatch"`
	CheckedAt       time.Time `json:"checkedAt"`
}

// Publish while holding n.mu; monitoring never waits for reconciliation RPCs.
func (n *Node) publishTopologyDesired() {
	entries := make(map[string]Entry, len(n.desired))
	for name, state := range n.desired {
		entries[name] = state.entry()
	}
	n.topologyDesired.Store(&entries)
}

func (n *Node) awaitPeerAdmission(ctx context.Context, spec *swarmruntime.ServiceSpec) error {
	if spec == nil || len(spec.Regions) > 0 && !slices.Contains(spec.Regions, n.cfg.region) {
		return nil
	}
	for {
		up, _ := n.pingPeers(ctx, time.Second)
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
	p := &peers{root: cfg.peersDir, region: cfg.region, node: cfg.server, address: cfg.address,
		registry: filepath.Join(cfg.dir, "admitted-peers.json"), admitted: map[string]peer{}, regions: append([]string{cfg.region}, slices.Sorted(maps.Keys(cfg.gateways))...)}
	data, err := os.ReadFile(p.registry)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
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
	if len(regions) == 0 {
		regions = p.regions
	}
	var lines []string
	for _, region := range regions {
		at, ok := p.admitted[region]
		if !ok {
			return nil, false
		}
		lines = append(lines, at.node+" "+region+" "+at.address+"\n")
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "")), len(lines) > 0
}

func (n *Node) attestPeers(ctx context.Context) {
	runtimeMismatch := runtimePeerMismatch(ctx)
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
		expected, complete := n.peers.expected(regions)
		current, err := os.ReadFile(filepath.Join(n.peers.root, name, "peers"))
		report := PeerAttestation{Expected: len(regions), CheckedAt: topology.ObservedAt, Rejected: n.peers.rejected[name], Topology: fmt.Sprintf("%x", sha256.Sum256(expected))}
		if name == "terrabase" {
			report.RuntimeMismatch = runtimeMismatch
		}
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
		expected, complete := n.peers.expected(regions)
		digest := fmt.Sprintf("%x", sha256.Sum256(expected))
		for _, region := range regions {
			report, ok := n.peerReports[region][service]
			if !ok || !complete || report.Topology != digest || report.Expected != len(regions) || report.CheckedAt.After(time.Now().Add(5*time.Second)) || report.Mismatch != 0 {
				report.Mismatch = 1
			}
			fmt.Fprintf(w, "ts_orch_peer_topology_mismatch{region=%q,service=%q} %d\n", region, service, report.Mismatch)
			fmt.Fprintf(w, "ts_orch_peer_topology_expected{region=%q,service=%q} %d\n", region, service, report.Expected)
			fmt.Fprintf(w, "ts_orch_peer_topology_generation_rejected{region=%q,service=%q} %d\n", region, service, min(1, max(0, report.Rejected)))
			if service == "terrabase" {
				mismatch := report.RuntimeMismatch
				if !ok || mismatch != 0 {
					mismatch = 1
				}
				fmt.Fprintf(w, "ts_orch_peer_topology_runtime_mismatch{region=%q,service=%q} %d\n", region, service, mismatch)
			}
			fmt.Fprintf(w, "ts_orch_peer_topology_age_seconds{region=%q,service=%q} %.3f\n", region, service, max(0, time.Since(report.CheckedAt).Seconds()))
		}
	}
}

// This is the native exporter, not the switching edge or the peers file.
func runtimePeerMismatch(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9091/metrics", nil)
	request.Header.Set("Accept", "text/plain; version=0.0.4")
	response, err := client.Do(request)
	if err != nil {
		return 1
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 1
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		return 1
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	metric := families["terrabase_peer_topology_mismatch"].GetMetric()
	if err != nil || len(metric) != 1 || metric[0].GetGauge() == nil || metric[0].GetGauge().GetValue() != 0 {
		return 1
	}
	return 0
}

func (n *Node) servePeerMetrics(ctx context.Context) {
	server := &http.Server{Addr: "127.0.0.1:9095", ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			n.writePeerMetrics(w)
		})}
	go func() { <-ctx.Done(); _ = server.Close() }()
	_ = server.ListenAndServe()
}
