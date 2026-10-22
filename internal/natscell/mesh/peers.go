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

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// peersEvery is how often a node pings every region for its peers files, so
// a down region drops out within two rounds.
const peersEvery = 5 * time.Second

type peer struct{ node, address string }

// peers keeps <root>/<service>/peers current for every service this node runs.
type peers struct {
	root, region, node string
	address            func() (string, error)

	mu      sync.Mutex
	up      map[string]peer     // region -> node that answered the last ping round
	targets map[string][]string // service -> its regions; empty means every region
}

// wt0Address is this host's NetBird IPv4.
func wt0Address() (string, error) {
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
	return slices.Contains(Regions(), region) && swarmruntime.NodeName.MatchString(at.node) && ip != nil && ip.To4() != nil
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
	p.targets[service] = slices.Clone(regions)
	return p.write(service)
}

func (p *peers) untrack(service string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.targets, service)
	return os.RemoveAll(filepath.Join(p.root, service))
}

// observe replaces the up set (keeping the own line while its address is
// known) and rewrites every tracked file whose content changed.
func (p *peers) observe(up map[string]peer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if own, ok := p.up[p.region]; ok {
		up[p.region] = own
	}
	if address, err := p.address(); err == nil {
		up[p.region] = peer{p.node, address}
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

// watchPeers pings every region each cfg.peersEvery and rewrites the files.
func (n *Node) watchPeers(ctx context.Context) {
	for {
		up := map[string]peer{}
		_ = collect(ctx, n.conn, PingSubject, nil, len(Regions()), n.cfg.peersEvery/2, func(data []byte) bool {
			var reply Reply
			if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
				if at := (peer{reply.Server, reply.Address}); validPeer(reply.Region, at) {
					up[reply.Region] = at
				}
			}
			return true
		})
		if err := n.peers.observe(up); err != nil {
			slog.WarnContext(ctx, "mesh peers file write failed", "error", err)
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
