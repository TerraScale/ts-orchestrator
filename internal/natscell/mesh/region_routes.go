package mesh

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type gossipedRoute struct {
	route   *url.URL
	account string
}

type inRegionGossip struct {
	region     string
	mu         sync.Mutex
	peers      map[string][]gossipedRoute
	membership atomic.Int64
	rounds     atomic.Uint64
}

func newInRegionGossip(region string, now time.Time) *inRegionGossip {
	gossip := &inRegionGossip{region: region, peers: map[string][]gossipedRoute{}}
	gossip.membership.Store(now.UnixNano())
	return gossip
}

func (g *inRegionGossip) solicit(name string, route *url.URL, account string) bool {
	if serverRegion(name) != g.region {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	routes := slices.DeleteFunc(g.peers[name], func(known gossipedRoute) bool { return known.account == account })
	g.peers[name] = append(routes, gossipedRoute{route: route, account: account})
	return false
}

func regionRoutesSubject(region string) string {
	return protocol.MeshWorkerPrefix + region + ".routes"
}

func (n *Node) membershipLive() bool {
	return time.Since(time.Unix(0, n.gossip.membership.Load())) < 3*n.cfg.peersEvery
}

func (n *Node) receiveRegionRoutes(m *nats.Msg) {
	var members []string
	if protocol.DecodeTolerant(m.Data, &members, maxWire) != nil || !n.inRegion(members) {
		n.rejectedRoutes.Add(1)
		slog.WarnContext(n.ctx, "region routes rejected", "subject", m.Subject, "members", len(members))
		return
	}
	n.gossip.membership.Store(time.Now().UnixNano())
	n.reconcileRegionRoutes(members)
}

func (n *Node) inRegion(members []string) bool {
	if len(members) == 0 || !n.cfg.vcn.IsValid() {
		return false
	}
	for _, member := range members {
		ip, err := netip.ParseAddr(member)
		if err != nil || !ip.Is4() || !n.cfg.vcn.Contains(ip) {
			return false
		}
	}
	return true
}

func (n *Node) regionRoutes() {
	ticker := time.NewTicker(n.cfg.peersEvery)
	defer ticker.Stop()
	started := time.Now()
	n.gossip.membership.Store(started.UnixNano())
	reachedRegion := false
	failure := ""
	for {
		if !reachedRegion && n.routedInRegion() {
			reachedRegion = true
			close(n.regionReached)
			n.gossip.membership.Store(max(n.gossip.membership.Load(), time.Now().UnixNano()))
		}
		if n.membershipConn != nil {
			members, err := n.regionMembers(n.ctx)
			if err == nil {
				n.gossip.membership.Store(time.Now().UnixNano())
				n.reconcileRegionRoutes(members)
				var data []byte
				if data, err = protocol.EncodeJSON(members); err == nil {
					err = n.membershipConn.Publish(regionRoutesSubject(n.cfg.region), data)
				}
			}
			if err != nil && err.Error() != failure {
				slog.WarnContext(n.ctx, "region routes not shared", "error", err)
			}
			failure = ""
			if err != nil {
				failure = err.Error()
			}
		}
		if reachedRegion || time.Since(started) >= time.Minute {
			n.dialGossipedPeers()
		}
		n.gossip.rounds.Add(1)
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (n *Node) routedInRegion() bool {
	return slices.ContainsFunc(n.routes(), func(route *server.RouteInfo) bool { return serverRegion(route.RemoteName) == n.cfg.region })
}

func (n *Node) dialGossipedPeers() {
	routes := n.routes()
	if n.membershipLive() && slices.ContainsFunc(routes, func(route *server.RouteInfo) bool {
		ip, err := netip.ParseAddr(route.IP)
		return err == nil && n.cfg.vcn.Contains(ip) && serverRegion(route.RemoteName) == n.cfg.region
	}) {
		return
	}
	type peerAccount struct{ name, account string }
	routed := map[peerAccount]bool{}
	for _, route := range routes {
		routed[peerAccount{route.RemoteName, route.Account}] = true
	}
	n.gossip.mu.Lock()
	peers := n.gossip.peers
	n.gossip.peers = map[string][]gossipedRoute{}
	n.gossip.mu.Unlock()
	for name, routes := range peers {
		for _, gossiped := range routes {
			if !routed[peerAccount{name, gossiped.account}] {
				n.server.ConnectImplicitRoute(gossiped.route, gossiped.account)
			}
		}
	}
}

func (n *Node) regionMembers(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialControl(filepath.Dir(n.cfg.dir))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	current, err := swarmruntime.ListMembers(ctx, client)
	if err != nil {
		return nil, err
	}
	listed := current.Members
	ready := map[string]bool{}
	for _, member := range listed {
		if member.State == "READY" {
			ready[member.Hostname] = true
		}
	}
	members := []string{}
	for _, member := range listed {
		if member.State != "READY" && ready[member.Hostname] {
			continue
		}
		host, _, err := net.SplitHostPort(member.Address)
		if err != nil {
			host = member.Address
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() && (!n.cfg.vcn.IsValid() || n.cfg.vcn.Contains(ip)) && !slices.Contains(members, ip.String()) {
			members = append(members, ip.String())
		}
	}
	slices.Sort(members)
	return members, nil
}

func (n *Node) inRegionRoute(route *url.URL) bool {
	ip, err := netip.ParseAddr(route.Hostname())
	return err == nil && ip.Is4() && n.cfg.vcn.IsValid() && n.cfg.vcn.Contains(ip)
}

func (n *Node) reconcileRegionRoutes(members []string) {
	if n.cfg.vcn.IsValid() {
		n.server.RetainRoutes(func(route *url.URL) bool {
			return !n.inRegionRoute(route) || slices.Contains(members, route.Hostname())
		})
	}
	routes := []*url.URL{}
	for _, member := range members {
		route, err := url.Parse("nats://" + net.JoinHostPort(member, strconv.Itoa(n.cfg.clusterPort)))
		if err == nil {
			routes = append(routes, route)
		}
	}
	if len(routes) != 0 {
		n.server.AddRoutes(routes)
	}
}

func (n *Node) writeRouteMetrics(w io.Writer) {
	fmt.Fprintf(w, "ts_orch_mesh_region_routes_rejected_total %d\n", n.rejectedRoutes.Load())
	fmt.Fprintf(w, "ts_orch_mesh_region_routes_rounds_total %d\n", n.gossip.rounds.Load())
	live := 0
	if n.membershipLive() {
		live = 1
	}
	fmt.Fprintf(w, "ts_orch_mesh_region_membership_live %d\n", live)
	varz, err := n.server.Varz(nil)
	if err != nil {
		return
	}
	for _, configured := range varz.Cluster.URLs {
		host, _, err := net.SplitHostPort(strings.TrimPrefix(configured, "nats://"))
		if err != nil {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil && n.cfg.vcn.IsValid() && n.cfg.vcn.Contains(ip) {
			fmt.Fprintf(w, "ts_orch_mesh_region_route_configured{address=%q} 1\n", ip.String())
		}
	}
}
