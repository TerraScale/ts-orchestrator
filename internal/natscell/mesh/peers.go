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

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// peersEvery is how often a node pings every region for its peers files, so
// liveness is refreshed without authorizing membership removal.
const peersEvery = 5 * time.Second

type peer struct{ node, address string }

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
}

// peersMissedRounds is how many ping rounds in a row a region must miss
// before its line leaves the files: the first round after a start runs before
// the gateways connect, and a restart must not shrink a file to this region.
const peersMissedRounds = 2

// NetBirdAddress is this host's NetBird IPv4 (wt0).
func NetBirdAddress() (string, error) {
	iface, err := net.InterfaceByName("wt0")
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4().String(), nil
		}
	}
	return "", errors.New("wt0 has no IPv4 address")
}

func validPeer(region string, at peer) bool {
	ip := net.ParseIP(at.address)
	_, known := catalog.LookupName(region)
	return known && swarmruntime.NodeName.MatchString(at.node) && ip != nil && ip.To4() != nil
}

// track writes service's file, at least with this node's own line, before
// the service is applied.
func (p *peers) track(service string, regions []string) error {
	address, err := p.address()
	if err != nil {
		return fmt.Errorf("own NetBird address for the peers file: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.up == nil {
		p.up = map[string]peer{}
	}
	if p.targets == nil {
		p.targets = map[string][]string{}
	}
	p.up[p.region] = peer{p.node, address}
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
	return os.RemoveAll(filepath.Join(p.root, service))
}

// observe takes the regions that answered a ping round (keeping the own line
// while its address is known); a region that did not keeps its line until it
// missed peersMissedRounds rounds in a row. It rewrites every tracked file
// whose content changed.
func (p *peers) observe(answered map[string]peer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	up := maps.Clone(answered)
	if own, ok := p.up[p.region]; ok {
		up[p.region] = own
	}
	if address, err := p.address(); err == nil {
		up[p.region] = peer{p.node, address}
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
	var errs []error
	for _, service := range slices.Sorted(maps.Keys(p.targets)) {
		errs = append(errs, p.write(service))
	}
	return errors.Join(errs...)
}

// write replaces the file by rename in its own directory, only when it changes; the caller holds p.mu.
func (p *peers) write(service string) error {
	regions := p.targets[service]
	var lines []string
	for region, at := range p.up {
		if len(regions) == 0 || slices.Contains(regions, region) {
			lines = append(lines, at.node+" "+region+" "+at.address+"\n")
		}
	}
	slices.Sort(lines)
	data := []byte(strings.Join(lines, ""))
	if p.admitted != nil {
		expected, complete := p.expected(regions)
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

func (n *Node) pingPeers(ctx context.Context, wait time.Duration) (map[string]peer, map[string]map[string]PeerAttestation) {
	up := map[string]peer{}
	reports := map[string]map[string]PeerAttestation{}
	_ = collect(ctx, n.conn, PingSubject, nil, len(n.regions()), wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			if at := (peer{reply.Server, reply.Address}); validPeer(reply.Region, at) {
				up[reply.Region] = at
				reports[reply.Region] = reply.Attestations
			}
		}
		return true
	})
	return up, reports
}

// watchPeers pings every region each cfg.peersEvery and rewrites the files.
func (n *Node) watchPeers(ctx context.Context) {
	for {
		up, reports := n.pingPeers(ctx, min(n.cfg.peersEvery/2, peersEvery/2))
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
			n.attestPeers(ctx)
			if err := n.peers.observe(up); err != nil {
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
