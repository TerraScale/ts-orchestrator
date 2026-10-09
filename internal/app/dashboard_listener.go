package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// netbirdRanges are the NetBird overlay's IPv4 range (internal/netbird/manager)
// and the IPv6 prefix the account gives every peer, which NetBird DNS names
// resolve to; netbirdProbes are addresses in them no peer holds, only routed
// to.
var (
	netbirdRanges = [2]netip.Prefix{netip.MustParsePrefix("10.200.0.0/16"),
		netip.MustParsePrefix("fd9c:200:2182:65f2::/64")}
	netbirdProbes = [2]netip.AddrPort{netip.MustParseAddrPort("10.200.255.254:9"),
		netip.MustParseAddrPort("[fd9c:200:2182:65f2::fffe]:9")}
)

// netbirdAddresses are a node's IPv4 and IPv6 NetBird addresses; either may
// be the zero address.
type netbirdAddresses [2]netip.Addr

// dashboardPort is cellspec.DashboardPort; tests move it.
var dashboardPort uint16 = cellspec.DashboardPort

var (
	// dashboardCheck is how often a controller reads the spec's dashboard
	// and its NetBird address; dashboardTokenRead how often it re-reads the
	// token, so a rotated secret takes effect without a new spec.
	dashboardCheck     = 5 * time.Second
	dashboardTokenRead = 5 * time.Minute
)

// dashboardListener is what one NetBird listener serves.
type dashboardListener struct {
	section    cellspec.Dashboard
	addresses  netbirdAddresses
	token      vaultsecret.VersionedValue
	generation uint64
}

// dashboardLoop serves the operator dashboard on this controller's NetBird
// address while the adopted cell spec carries a dashboard section
// (docs/observability.md): at cellspec.DashboardPort, behind the token the
// section names in Vault, read with the controller's instance principal. A
// changed section, a rotated token or a new NetBird address restarts the
// listener and a removed section stops it, without a controller restart. A
// listener that cannot start is retried at the next check; the dashboard
// never stops the controller.
func (runtime *runtimeObservability) dashboardLoop(ctx context.Context, current func() (*cellspec.Dashboard, uint64),
	addresses func() (netbirdAddresses, bool), readToken func(context.Context, vaultsecret.Ref) (vaultsecret.VersionedValue, error),
) {
	var running, want dashboardListener
	var serving <-chan error
	var read time.Time
	stop, failure := func() {}, ""
	defer func() { stop() }()
	ticker := time.NewTicker(dashboardCheck)
	defer ticker.Stop()
	for {
		section, generation := current()
		var err error
		if section == nil {
			want = dashboardListener{}
		} else if want.section != *section || want.generation != generation || time.Since(read) >= dashboardTokenRead {
			token, readErr := readToken(ctx, section.Token)
			switch {
			case readErr == nil:
				want.generation = generation
				want.section, want.token, read = *section, token, time.Now()
			case want.section != *section:
				// A new section never serves the old token.
				want, read, err = dashboardListener{section: *section}, time.Time{}, readErr
			default:
				// Vault is unavailable: keep serving the token read last.
				err = readErr
			}
		}
		if section != nil && err == nil {
			var found bool
			if want.addresses, found = addresses(); !found {
				err = errNoNetBirdAddress
			}
		}
		if want != running || serving == nil && section != nil && err == nil {
			stop()
			stop, running, serving = func() {}, dashboardListener{}, nil
			if section != nil && err == nil {
				stop, serving, err = runtime.startDashboard(ctx, want)
				if err != nil {
					// A cached version rejected by KV must be refreshed next check.
					read = time.Time{}
				}
				if err == nil {
					running = want
					slog.Info("dashboard serving on the NetBird address", observability.ComponentKey, "dashboard",
						"addresses", want.addresses.listen())
				}
			}
		}
		if err != nil && err.Error() != failure {
			slog.Warn("dashboard is not serving on the NetBird address; retrying", observability.ComponentKey, "dashboard",
				"error", err)
		}
		failure = ""
		if err != nil {
			failure = err.Error()
		}
		select {
		case <-ctx.Done():
			return
		case err := <-serving:
			slog.Warn("dashboard NetBird listener stopped; restarting", observability.ComponentKey, "dashboard", "error", err)
			stop()
			stop, running, serving = func() {}, dashboardListener{}, nil
		case <-ticker.C:
		}
	}
}

var errNoNetBirdAddress = errors.New("this node has no NetBird address yet")

// listen are the listen addresses of the node's NetBird addresses.
func (addresses netbirdAddresses) listen() []string {
	var out []string
	for _, address := range addresses {
		if address.IsValid() {
			out = append(out, netip.AddrPortFrom(address, dashboardPort).String())
		}
	}
	return out
}

// startDashboard binds a listener on each NetBird address, each with its own
// dashboard fed the runtime's providers. The returned channel yields when
// any of them stops serving.
func (runtime *runtimeObservability) startDashboard(ctx context.Context, listener dashboardListener) (func(), <-chan error, error) {
	openCtx, openCancel := context.WithTimeout(ctx, 5*time.Second)
	store, err := observability.OpenSessionStore(openCtx, runtime.sessionJS, runtime.sessionReplicas, "netbird")
	openCancel()
	if err != nil {
		return func() {}, nil, err
	}
	serveCtx, cancel := context.WithCancel(ctx)
	var servers []*observability.Server
	var boards []*dashboard.Dashboard
	stop := func() {
		cancel()
		for _, server := range servers {
			_ = server.Close()
		}
		for _, board := range boards {
			runtime.removeBoard(board)
		}
	}
	stopped := make(chan error, len(listener.addresses))
	for _, address := range listener.addresses.listen() {
		settings := observability.Config{ListenAddress: address, Dashboard: true}
		server, err := observability.NewTokenServer(settings, listener.token.Value, observability.ServerDeps{
			Registry: runtime.registry, Health: runtime.health, Events: runtime.events, Sessions: store,
			TokenVersion: observability.TokenVersion{Source: listener.token.SecretID, Number: listener.token.Number, SpecGeneration: listener.generation}})
		if err != nil {
			stop()
			return func() {}, nil, err
		}
		board := dashboard.New(dashboard.Options{Health: runtime.health, Events: runtime.events, SignOut: true})
		board.Mount(server)
		serving, err := server.Start(serveCtx, settings)
		if err != nil {
			stop()
			return func() {}, nil, err
		}
		servers, boards = append(servers, server), append(boards, board)
		runtime.addBoard(board)
		go func() { stopped <- <-serving }()
	}
	return stop, stopped, nil
}

// localNetBirdAddresses are this node's addresses in the NetBird overlay.
// The controller unit allows no netlink socket, so interfaces cannot be
// listed; connecting a UDP socket, which sends nothing, asks the kernel which
// source address routes into each range.
func localNetBirdAddresses() (netbirdAddresses, bool) {
	var addresses netbirdAddresses
	for index, probe := range netbirdProbes {
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(probe))
		if err != nil {
			continue
		}
		address := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
		_ = conn.Close()
		if netbirdRanges[index].Contains(address) {
			addresses[index] = address
		}
	}
	return addresses, addresses[0].IsValid() || addresses[1].IsValid()
}

// readDashboardToken reads the dashboard token with the instance principal.
func readDashboardToken(ctx context.Context, ref vaultsecret.Ref) (vaultsecret.VersionedValue, error) {
	return vaultsecret.ReadRefVersioned(ctx, ref)
}
