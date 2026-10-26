// Package hostdashboard serves a single-host region's operator dashboard on
// the host's NetBird address (wt0) at TCP 9463, behind the region's token in
// gru-vault, which the first host to need it creates. Nothing turns it on:
// every region host serves it. The pages read this host's snapshot and every
// region's health over the cross-region mesh; they never change state.
package hostdashboard

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
)

// Port is the dashboard's TCP port on the NetBird address.
const Port = cellspec.DashboardPort

var (
	// checkEvery is how often the loop reads the NetBird address and retries
	// a listener that is down; tokenEvery how often it re-reads the token, so
	// a rotated secret takes effect without a restart; tokenRetry how soon a
	// failed read is retried.
	checkEvery = 5 * time.Second
	tokenEvery = 5 * time.Minute
	tokenRetry = 30 * time.Second
)

// sources are what the loop needs from the host; tests replace them.
type sources struct {
	port    int
	address func() (string, error)
	token   func(context.Context) (string, error)
}

// Run serves the dashboard until ctx ends. A missing NetBird address, an
// unreadable token or a port it cannot bind is logged and retried; it never
// stops the host. While Vault is unavailable the token read last keeps
// serving.
func Run(ctx context.Context, state, region string) {
	host, err := os.Hostname()
	if err != nil {
		slog.WarnContext(ctx, "dashboard is not serving: no hostname", observability.ComponentKey, "dashboard", "error", err)
		return
	}
	registry := observability.NewRegistry(true)
	health := new(observability.Health)
	var local observability.Cache[regionhealth.Report]
	local.TTL = 10 * time.Second
	health.Add(observability.Check{Name: "region health", Run: func(ctx context.Context) (bool, string) {
		report, _ := local.Get(ctx, func(ctx context.Context) (regionhealth.Report, error) {
			return regionhealth.Check(ctx, state), nil
		})
		return report.State == regionhealth.StateOK, report.State
	}})
	collector, err := observability.NewCollector(observability.CollectorConfig{Cell: region, Member: host, Role: Role,
		Registry: registry, Health: health,
		Filesystems: []observability.FilesystemRole{{Role: "root", Path: "/"}, {Role: "state", Path: state}}})
	if err != nil {
		slog.WarnContext(ctx, "dashboard is not serving", observability.ComponentKey, "dashboard", "error", err)
		return
	}
	reports := &meshReports{state: state}
	defer reports.close()
	deps := observability.ServerDeps{Registry: registry, Health: health, Snapshots: collector,
		Cluster: &meshCluster{region: region, local: collector, regions: mesh.Regions, ask: reports.ask},
		Events:  observability.NewEventBus(observability.DefaultEventCapacity), LocalSessions: true}
	serve(ctx, deps, sources{port: Port, address: mesh.NetBirdAddress, token: func(ctx context.Context) (string, error) {
		return readToken(ctx, region)
	}})
}

// listener is what one running listener serves.
type listener struct{ address, token string }

func serve(ctx context.Context, deps observability.ServerDeps, from sources) {
	var running, want listener
	var server *observability.Server
	var serving <-chan error
	var nextRead time.Time
	failure := ""
	stop := func() {
		if server != nil {
			_ = server.Close()
		}
		server, serving, running = nil, nil, listener{}
	}
	defer stop()
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()
	for {
		var err error
		if !time.Now().Before(nextRead) {
			token, readErr := from.token(ctx)
			if readErr == nil {
				want.token, nextRead = token, time.Now().Add(tokenEvery)
			} else {
				err, nextRead = readErr, time.Now().Add(tokenRetry)
			}
		}
		address, addressErr := from.address()
		if addressErr == nil {
			want.address = net.JoinHostPort(address, strconv.Itoa(from.port))
		} else {
			want.address, err = "", addressErr
		}
		if server != nil && want != running {
			stop()
		}
		if server == nil && want.address != "" && want.token != "" {
			server, serving, err = start(ctx, deps, want)
			if err == nil {
				running = want
				slog.InfoContext(ctx, "dashboard serving on the NetBird address", observability.ComponentKey, "dashboard",
					"address", want.address)
			}
		}
		if err != nil && err.Error() != failure {
			slog.WarnContext(ctx, "dashboard is not serving on the NetBird address; retrying", observability.ComponentKey, "dashboard",
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
			slog.WarnContext(ctx, "dashboard NetBird listener stopped; restarting", observability.ComponentKey, "dashboard", "error", err)
			stop()
		case <-ticker.C:
		}
	}
}

// start binds one listener with its own dashboard over deps.
func start(ctx context.Context, deps observability.ServerDeps, want listener) (*observability.Server, <-chan error, error) {
	config := observability.Config{ListenAddress: want.address}
	server, err := observability.NewTokenServer(config, want.token, deps)
	if err != nil {
		return nil, nil, err
	}
	dashboard.New(dashboard.Options{Health: deps.Health, Events: deps.Events, Snapshots: deps.Snapshots,
		Cluster: deps.Cluster, SignOut: true}).Mount(server)
	serving, err := server.Start(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	return server, serving, nil
}
