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

// netbirdRange is the NetBird overlay every peer's address is in
// (internal/netbird/manager).
var netbirdRange = netip.MustParsePrefix("10.200.0.0/16")

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
	section cellspec.Dashboard
	address netip.Addr
	token   string
}

// dashboardLoop serves the operator dashboard on this controller's NetBird
// address while the adopted cell spec carries a dashboard section
// (docs/observability.md): at cellspec.DashboardPort, behind the token the
// section names in Vault, read with the controller's instance principal. A
// changed section, a rotated token or a new NetBird address restarts the
// listener and a removed section stops it, without a controller restart. A
// listener that cannot start is retried at the next check; the dashboard
// never stops the controller.
func (runtime *runtimeObservability) dashboardLoop(ctx context.Context, current func() *cellspec.Dashboard,
	address func() (netip.Addr, bool), readToken func(context.Context, vaultsecret.Ref) (string, error),
) {
	var running, want dashboardListener
	var serving <-chan error
	var read time.Time
	stop, failure := func() {}, ""
	defer func() { stop() }()
	ticker := time.NewTicker(dashboardCheck)
	defer ticker.Stop()
	for {
		section := current()
		var err error
		if section == nil {
			want = dashboardListener{}
		} else if want.section != *section || time.Since(read) >= dashboardTokenRead {
			token, readErr := readToken(ctx, section.Token)
			switch {
			case readErr == nil:
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
			if want.address, found = address(); !found {
				err = errNoNetBirdAddress
			}
		}
		if want != running || serving == nil && section != nil && err == nil {
			stop()
			stop, running, serving = func() {}, dashboardListener{}, nil
			if section != nil && err == nil {
				stop, serving, err = runtime.startDashboard(ctx, want)
				if err == nil {
					running = want
					slog.Info("dashboard serving on the NetBird address", observability.ComponentKey, "dashboard",
						"address", netip.AddrPortFrom(want.address, dashboardPort).String())
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

// startDashboard binds one NetBird listener with its own dashboard, fed the
// runtime's providers.
func (runtime *runtimeObservability) startDashboard(ctx context.Context, listener dashboardListener) (func(), <-chan error, error) {
	settings := observability.Config{
		ListenAddress: netip.AddrPortFrom(listener.address, dashboardPort).String(), Dashboard: true}
	server, err := observability.NewTokenServer(settings, listener.token, observability.ServerDeps{
		Registry: runtime.registry, Health: runtime.health, Events: runtime.events})
	if err != nil {
		return nil, nil, err
	}
	board := dashboard.New(dashboard.Options{Health: runtime.health, Events: runtime.events, SignOut: true})
	board.Mount(server)
	serveCtx, cancel := context.WithCancel(ctx)
	serving, err := server.Start(serveCtx, settings)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	runtime.addBoard(board)
	return func() {
		cancel()
		_ = server.Close()
		runtime.removeBoard(board)
	}, serving, nil
}

// localNetBirdAddress is this node's address in the NetBird overlay.
func localNetBirdAddress() (netip.Addr, bool) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil && netbirdRange.Contains(prefix.Addr()) {
			return prefix.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// readDashboardToken reads the dashboard token with the instance principal.
func readDashboardToken(ctx context.Context, ref vaultsecret.Ref) (string, error) {
	values, err := vaultsecret.ReadRefs(ctx, map[string]vaultsecret.Ref{cellspec.DashboardKey: ref})
	if err != nil {
		return "", err
	}
	return values[cellspec.DashboardKey], nil
}
