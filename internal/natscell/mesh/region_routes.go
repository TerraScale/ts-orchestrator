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
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func regionRoutesSubject(region string) string {
	return protocol.MeshWorkerPrefix + region + ".routes"
}

func (n *Node) receiveRegionRoutes(m *nats.Msg) {
	var members []string
	if protocol.DecodeTolerant(m.Data, &members, maxWire) != nil || !n.inRegion(members) {
		n.rejectedRoutes.Add(1)
		slog.WarnContext(n.ctx, "region routes rejected", "subject", m.Subject, "members", len(members))
		return
	}
	n.authority.Store(true)
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

func (n *Node) shareRegionRoutes() {
	ticker := time.NewTicker(n.cfg.peersEvery)
	defer ticker.Stop()
	failure := ""
	for {
		members, err := n.regionMembers(n.ctx)
		if err == nil {
			n.reconcileRegionRoutes(members)
			var data []byte
			if data, err = protocol.EncodeJSON(members); err == nil {
				err = n.conn.Publish(regionRoutesSubject(n.cfg.region), data)
			}
		}
		if err != nil && err.Error() != failure {
			slog.WarnContext(n.ctx, "region routes not shared", "error", err)
		}
		failure = ""
		if err != nil {
			failure = err.Error()
		}
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (n *Node) regionMembers(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialSingleHost(filepath.Dir(n.cfg.dir))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	listed, err := swarmruntime.ListMembers(ctx, client)
	if err != nil {
		return nil, err
	}
	members := []string{}
	for _, member := range listed {
		if member.State != "READY" {
			continue
		}
		host, _, err := net.SplitHostPort(member.Address)
		if err != nil {
			host = member.Address
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() && (!n.cfg.vcn.IsValid() || n.cfg.vcn.Contains(ip)) {
			members = append(members, ip.String())
		}
	}
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
	connected := map[string]bool{}
	for _, route := range n.routes() {
		connected[route.IP] = true
	}
	missing := []*url.URL{}
	for _, member := range members {
		if connected[member] {
			continue
		}
		route, err := url.Parse("nats://" + net.JoinHostPort(member, strconv.Itoa(n.cfg.clusterPort)))
		if err == nil {
			missing = append(missing, route)
		}
	}
	if len(missing) != 0 {
		n.server.AddRoutes(missing)
	}
}

func (n *Node) writeRouteMetrics(w io.Writer) {
	fmt.Fprintf(w, "ts_orch_mesh_region_routes_rejected_total %d\n", n.rejectedRoutes.Load())
	authoritative := 0
	if n.authority.Load() {
		authoritative = 1
	}
	fmt.Fprintf(w, "ts_orch_mesh_region_membership_authoritative %d\n", authoritative)
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
