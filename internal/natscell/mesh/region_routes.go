package mesh

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func regionRoutesSubject(region string) string {
	return protocol.MeshWorkerPrefix + region + ".routes"
}

func (n *Node) receiveRegionRoutes(m *nats.Msg) {
	var addresses []string
	if protocol.DecodeTolerant(m.Data, &addresses, maxWire) == nil {
		n.addRegionRoutes(addresses)
	}
}

func (n *Node) shareRegionRoutes() {
	ticker := time.NewTicker(n.cfg.peersEvery)
	defer ticker.Stop()
	failure := ""
	for {
		addresses, err := n.regionAddresses(n.ctx)
		if err == nil {
			n.addRegionRoutes(addresses)
			var data []byte
			if data, err = protocol.EncodeJSON(addresses); err == nil {
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

func (n *Node) regionAddresses(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialSingleHost(filepath.Dir(n.cfg.dir))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	members, err := swarmruntime.ListMembers(ctx, client)
	if err != nil {
		return nil, err
	}
	addresses := []string{}
	for _, member := range members {
		if member.State != "READY" {
			continue
		}
		host, _, err := net.SplitHostPort(member.Address)
		if err != nil {
			host = member.Address
		}
		addresses = append(addresses, host)
	}
	return addresses, nil
}

func (n *Node) addRegionRoutes(addresses []string) {
	connected := map[string]bool{}
	for _, route := range n.routes() {
		connected[route.IP] = true
	}
	missing := []*url.URL{}
	for _, address := range addresses {
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Is4() || connected[ip.String()] {
			continue
		}
		route, err := url.Parse("nats://" + net.JoinHostPort(ip.String(), strconv.Itoa(n.cfg.clusterPort)))
		if err != nil {
			continue
		}
		missing = append(missing, route)
	}
	if len(missing) != 0 {
		n.server.AddRoutes(missing)
	}
}
