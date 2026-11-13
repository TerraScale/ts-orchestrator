package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// peersEvery is how often a node pings every region for its peers files, so
// liveness is refreshed without authorizing membership removal.
const peersEvery = 5 * time.Second

type peer struct{ node, address string }

type workerObservation struct {
	peers     []peer
	startedAt time.Time
}

// peers keeps <root>/<service>/peers current for every service this node runs.
type peers struct {
	root, region, node string
	address            func() (string, error)

	mu       sync.Mutex
	up       map[string]peer     // region -> node that answered the last ping round
	missed   map[string]int      // region -> consecutive rounds it did not answer
	targets  map[string][]string // service -> its regions; empty means every region
	admitted map[string]peer     // independent, durable identities; never seeded from a peers file
	registry string
	regions  []string
	rejected map[string]int

	worker       bool
	workers      map[string][]peer
	workerMissed map[string]map[string]int
	workersReady map[string]time.Time
	perNode      map[string]bool
}

// peersMissedRounds is how many ping rounds in a row a region must miss
// before its line leaves the files: the first round after a start runs before
// the gateways connect, and a restart must not shrink a file to this region.
const peersMissedRounds = 2

func NetBirdAddress() (string, error) {
	return client.Address()
}

func validPeer(region string, at peer) bool {
	ip := net.ParseIP(at.address)
	_, known := catalog.LookupName(region)
	return known && swarmruntime.NodeName.MatchString(at.node) && ip != nil && ip.To4() != nil
}

func (p *peers) track(service string, regions []string, perNode bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.up == nil {
		p.up = map[string]peer{}
	}
	if p.targets == nil {
		p.targets = map[string][]string{}
	}
	if p.perNode == nil {
		p.perNode = map[string]bool{}
	}
	p.perNode[service] = perNode
	if p.admitted == nil {
		p.seed(service)
	} else {
		p.up = maps.Clone(p.admitted)
	}
	p.targets[service] = slices.Clone(regions)
	return p.write(service)
}

// seed takes the regions the service's file already lists (written by this
// node's previous run) as up until the ping rounds say otherwise; the caller
// holds p.mu.
func (p *peers) seed(service string) {
	data, err := os.ReadFile(filepath.Join(p.root, service, "peers"))
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		if at := (peer{fields[0], fields[2]}); validPeer(fields[1], at) {
			if _, known := p.up[fields[1]]; !known {
				p.up[fields[1]] = at
			}
		}
	}
}

func (p *peers) untrack(service string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.targets, service)
	delete(p.rejected, service)
	delete(p.perNode, service)
	return os.RemoveAll(filepath.Join(p.root, service))
}

func (p *peers) observe(answered map[string]peer, workers map[string]workerObservation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	up := maps.Clone(answered)
	if !p.worker {
		if own, ok := p.up[p.region]; ok {
			up[p.region] = own
		}
		if address, err := p.address(); err == nil {
			up[p.region] = peer{p.node, address}
		}
	}
	if p.missed == nil {
		p.missed = map[string]int{}
	}
	for region := range answered {
		delete(p.missed, region)
	}
	for region, at := range p.up {
		if _, ok := up[region]; ok {
			continue
		}
		if p.missed[region]++; p.missed[region] < peersMissedRounds {
			up[region] = at
		} else {
			delete(p.missed, region)
		}
	}
	p.up = up
	p.observeWorkers(answered, workers)
	var errs []error
	for _, service := range slices.Sorted(maps.Keys(p.targets)) {
		errs = append(errs, p.write(service))
	}
	return errors.Join(errs...)
}

func (p *peers) observeWorkers(answered map[string]peer, observations map[string]workerObservation) {
	if p.workers == nil {
		p.workers = map[string][]peer{}
		p.workerMissed = map[string]map[string]int{}
		p.workersReady = map[string]time.Time{}
	}
	for region := range p.workers {
		if _, ok := p.up[region]; !ok {
			if _, admitted := p.admitted[region]; admitted {
				continue
			}
			delete(p.workers, region)
			delete(p.workerMissed, region)
			delete(p.workersReady, region)
		}
	}
	for region := range answered {
		observation := observations[region]
		age := time.Since(observation.startedAt)
		if len(observation.peers) == 0 && !observation.startedAt.IsZero() && age >= 0 && age < time.Minute &&
			!p.workersReady[region].Equal(observation.startedAt) {
			delete(p.workerMissed, region)
			continue
		}
		if len(observation.peers) > 0 {
			p.workersReady[region] = observation.startedAt
		}
		if p.workerMissed[region] == nil {
			p.workerMissed[region] = map[string]int{}
		}
		missed := p.workerMissed[region]
		next := map[string]peer{}
		for _, at := range observation.peers {
			next[at.node] = at
			delete(missed, at.node)
		}
		for _, at := range p.workers[region] {
			if _, ok := next[at.node]; ok {
				continue
			}
			if missed[at.node]++; missed[at.node] < peersMissedRounds {
				next[at.node] = at
			} else {
				delete(missed, at.node)
			}
		}
		p.workers[region] = slices.Collect(maps.Values(next))
		slices.SortFunc(p.workers[region], func(a, b peer) int { return strings.Compare(a.node, b.node) })
	}
}

// write replaces the file by rename in its own directory, only when it changes; the caller holds p.mu.
func (p *peers) write(service string) error {
	regions := p.targets[service]
	founders := map[string]peer{}
	for region, at := range p.up {
		if len(regions) == 0 || slices.Contains(regions, region) {
			founders[region] = at
		}
	}
	data := p.render(service, founders)
	address, err := p.address()
	if err != nil {
		return fmt.Errorf("own NetBird address for the peers file: %w", err)
	}
	if err := swarmruntime.ValidatePeers(data, p.node, p.region, address); err != nil {
		return err
	}
	if p.admitted != nil {
		expected, complete := p.expectedFor(service, regions)
		if p.rejected == nil {
			p.rejected = map[string]int{}
		}
		p.rejected[service] = 0
		if !complete || !bytes.Equal(data, expected) {
			p.rejected[service] = 1
			return errors.New("peers generation differs from admitted topology")
		}
	}
	dir := filepath.Join(p.root, service)
	file := filepath.Join(dir, "peers")
	if current, err := os.ReadFile(file); err == nil && bytes.Equal(current, data) {
		return nil
	}
	// The task runs as a non-root user and reads the file through a read-only bind.
	// Explicit chmod: the ts-orch unit's umask would leave 0700/0600.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	temp := filepath.Join(dir, ".peers.tmp")
	if err := os.WriteFile(temp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o644); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, file); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

// render is a peers file: the founders' lines sorted, and for a per-node
// service each region's fully joined workers right after its founder, since
// TerraBase reaches a region at its first line. The caller holds p.mu.
func (p *peers) render(service string, founders map[string]peer) []byte {
	type block struct {
		line  string
		lines []string
	}
	var blocks []block
	for region, at := range founders {
		b := block{line: at.node + " " + region + " " + at.address + "\n"}
		if p.perNode[service] {
			for _, worker := range p.workers[region] {
				b.lines = append(b.lines, worker.node+" "+region+" "+worker.address+"\n")
			}
		}
		blocks = append(blocks, b)
	}
	slices.SortFunc(blocks, func(a, b block) int { return strings.Compare(a.line, b.line) })
	var out strings.Builder
	for _, b := range blocks {
		out.WriteString(b.line)
		for _, line := range b.lines {
			out.WriteString(line)
		}
	}
	return []byte(out.String())
}

func (n *Node) pingPeers(ctx context.Context, wait time.Duration) (map[string]peer, map[string]workerObservation, map[string]map[string]PeerAttestation) {
	up := map[string]peer{}
	workers := map[string]workerObservation{}
	reports := map[string]map[string]PeerAttestation{}
	_ = collect(ctx, n.conn, PingSubject, nil, len(n.regions()), wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			if at := (peer{reply.Server, reply.Address}); validPeer(reply.Region, at) {
				up[reply.Region] = at
				reports[reply.Region] = reply.Attestations
				observation := workerObservation{startedAt: reply.StartedAt}
				for _, worker := range reply.Workers {
					if w := (peer{worker.Node, worker.Address}); validPeer(reply.Region, w) && w.node != at.node {
						observation.peers = append(observation.peers, w)
					}
				}
				workers[reply.Region] = observation
			}
		}
		return true
	})
	return up, workers, reports
}

// watchPeers pings every region each cfg.peersEvery and rewrites the files.
func (n *Node) watchPeers(ctx context.Context) {
	for {
		up, workers, reports := n.pingPeers(ctx, min(n.cfg.peersEvery/2, peersEvery/2))
		// A round cut short by shutdown saw only this node: never write it.
		if ctx.Err() != nil || n.ctx.Err() != nil {
			return
		}
		if err := n.peers.admit(up, n.regions()); err != nil {
			slog.WarnContext(ctx, "mesh peer admission failed", "error", err)
		} else {
			n.peerReportMu.Lock()
			if n.peerReports == nil {
				n.peerReports = map[string]map[string]PeerAttestation{}
			}
			for region, report := range reports {
				if region != n.cfg.region {
					n.peerReports[region] = report
				}
			}
			n.peerReportMu.Unlock()
			n.attestPeers()
			if err := n.peers.observe(up, workers); err != nil {
				slog.WarnContext(ctx, "mesh peers file write failed", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-n.ctx.Done():
			return
		case <-time.After(n.cfg.peersEvery):
		}
	}
}
