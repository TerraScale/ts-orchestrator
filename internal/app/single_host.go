package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/hostdashboard"
	"github.com/TerraScale/ts-orchestrator/internal/hostmetrics"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// runSingleHost runs this host's SwarmKit node (plan) with the containerd
// executor and the release NATS listener (:4222) CI pushes releases to.
// Outside OCI it needs no Vault, NetBird or admission. Serving the release
// subjects ends a pushed binary's probation.
func runSingleHost(ctx context.Context, state string, output io.Writer, plan hostPlan, probation *releasepush.Probation, swarmReady chan struct{}, health func(context.Context) error) error {
	executor, err := swarmruntime.NewExecutor("/run/containerd/containerd.sock", state)
	if err != nil {
		return err
	}
	if err := executor.BindVaultSecrets(vaultsecret.ReadInstanceSecrets); err != nil {
		return err
	}
	defer executor.Close()
	if err := executor.SetRegistryResolver(swarmruntime.GHCRResolver(vaultsecret.ReadGHCRPullToken)); err != nil {
		return err
	}
	founder := plan.region != "" && !plan.joiner()
	if founder {
		// The region's workers dial the manager; the host NSG admits only the VCN.
		if err := releasepush.OpenTCP(ctx, swarmruntime.SwarmPort); err != nil {
			fmt.Fprintf(output, "swarm firewall: %v\n", err)
		}
	}
	node, err := swarmruntime.StartSingleHost(ctx, state, executor, plan.listen, plan.advertise, plan.admission)
	if err != nil {
		return err
	}
	close(swarmReady)
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = node.Stop(stop)
	}()
	healthCtx, stopHealth := context.WithCancel(ctx)
	defer stopHealth()
	go hostmetrics.Run(healthCtx, plan.region, executor)
	go syncHostTargets(healthCtx)
	go executor.ReapExitedTasks(healthCtx)
	failed := make(chan error, 2)
	go func() {
		if err := executor.ServeBootstrap(healthCtx, state); healthCtx.Err() == nil {
			failed <- errors.Join(errors.New("bootstrap executor endpoint stopped"), err)
		}
	}()
	// shortcut: a worker has no control socket and would answer for its region a second time; give workers their own health row when they serve.
	if !plan.joiner() {
		go regionhealth.Run(healthCtx, state)
		if plan.region != "" {
			// The operator dashboard on the NetBird address; its token lives in gru-vault.
			go func() {
				if err := hostdashboard.Run(healthCtx, state, plan.region); healthCtx.Err() == nil {
					failed <- errors.Join(errors.New("host dashboard stopped"), err)
				}
			}()
		}
	}
	if err := releasepush.EnsureFirewall(ctx); err != nil {
		// Workloads keep serving; only release pushes are blocked until the next start.
		fmt.Fprintf(output, "release listener firewall: %v\n", err)
	}
	for _, port := range []int{80, 443, edge.PostgresPort, hostmetrics.Port, hostdashboard.Port} {
		if err := releasepush.OpenTCP(ctx, port); err != nil {
			fmt.Fprintf(output, "edge firewall: %v\n", err)
		}
	}
	// NetBird WireGuard (51820) and the server's STUN (3478); without them every peer path stays relayed.
	for _, port := range []int{3478, 51820} {
		if err := releasepush.OpenUDP(ctx, port); err != nil {
			fmt.Fprintf(output, "netbird firewall: %v\n", err)
		}
	}
	releases, err := releasepush.NewHandler(state)
	if err != nil {
		return err
	}
	releases.Health = health
	releases.Mesh = mesh.Bridge(state)
	releases.App = mesh.Release(state)
	if founder {
		releases.Relay = func(request []byte) { relayRelease(state, plan.region, request) }
	}
	natsServer, natsConn, err := releasepush.Start(state)
	if err != nil {
		return err
	}
	defer natsServer.Shutdown()
	defer natsConn.Close()
	if err := releases.Serve(natsConn); err != nil {
		return err
	}
	if plan.joiner() && plan.address != "" {
		go serveWorkerReleases(ctx, state, plan.region, releases)
	}
	if founder {
		go publishJoin(ctx, state, plan)
	}
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("single-host node ready"); err != nil {
		return err
	}
	if probation.Served() {
		releases.NodeList.AdoptEmbedded()
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintf(output, "single-host %s %s ready; advertise %s\n", plan.admission.Role, node.ID(), plan.advertise); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- node.Wait(ctx) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-failed:
		slog.ErrorContext(ctx, "single-host background service failed", "error", err)
		return err
	case err := <-waited:
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	case <-releases.Installed:
		// Non-zero so Restart=always starts the new binary; containerd keeps workloads running.
		return errors.New("installed a pushed release; exiting so systemd starts it")
	}
}

// hostPlan is how this host takes part in its region's SwarmKit cluster.
type hostPlan struct {
	listen, advertise string
	admission         swarmruntime.Admission
	// region is the OCI region token and address the private VCN IP; both
	// are "" outside OCI, where no host joins.
	region, address string
}

func (p hostPlan) joiner() bool { return p.admission.HostID != p.admission.FounderID }

func planHost(ctx context.Context, state string, output io.Writer) (hostPlan, error) {
	loopback := hostPlan{listen: swarmruntime.SingleHostAddress, advertise: swarmruntime.SingleHostAddress, admission: swarmruntime.FounderAdmission()}
	stored, restarted, err := swarmruntime.StoredAdmission(state)
	if err != nil {
		return hostPlan{}, err
	}
	asset, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return hostPlan{}, fmt.Errorf("read host platform: %w", err)
	}
	oracle := strings.TrimSpace(string(asset)) == "OracleCloud.com"
	if !oracle {
		for _, path := range []string{filepath.Join(state, "mesh"), filepath.Join(state, hostMetadataFile)} {
			if _, err := os.Stat(path); err == nil {
				return hostPlan{}, errors.New("host platform is not Oracle but stored mesh state exists")
			} else if !errors.Is(err, os.ErrNotExist) {
				return hostPlan{}, err
			}
		}
	}
	if !restarted {
		if _, err := os.Stat(swarmruntime.SingleHostSwarmDir(state)); err == nil {
			return hostPlan{}, errors.New("cluster state exists without stored admission")
		} else if !errors.Is(err, os.ErrNotExist) {
			return hostPlan{}, err
		}
	}
	if !oracle {
		if restarted {
			if stored.HostID != stored.FounderID {
				return hostPlan{}, errors.New("host platform is not Oracle but stored mesh worker admission exists")
			}
			loopback.admission = stored
		}
		fmt.Fprintln(output, "local host; using a loopback-only cluster")
		return loopback, nil
	}
	notifier := sdnotify.New(os.Getenv("NOTIFY_SOCKET"), "", "", os.Getpid())
	if err := notifier.ExtendStart(2 * hostMetadataWindow); err != nil {
		return hostPlan{}, fmt.Errorf("extend host startup window: %w", err)
	}
	instance, metadataErr := readHostMetadata(ctx, output)
	if err := ctx.Err(); err != nil {
		return hostPlan{}, err
	}
	if metadataErr != nil {
		if !restarted {
			return hostPlan{}, fmt.Errorf("read host metadata: %w", metadataErr)
		}
		if stored.HostID == stored.FounderID {
			instance, err = storedHostMetadata(state)
			if err != nil {
				return hostPlan{}, fmt.Errorf("read host metadata: %w", errors.Join(metadataErr, err))
			}
			fmt.Fprintf(output, "using stored host metadata; advertise %s\n", net.JoinHostPort(instance.PrivateIP, strconv.Itoa(swarmruntime.SwarmPort)))
		} else {
			fmt.Fprintln(output, "host metadata unavailable; restarting worker from stored admission")
		}
	}
	if metadataErr == nil {
		data, err := json.Marshal(instance)
		if err == nil {
			err = writeOwnerOnlyFile(state, hostMetadataFile, data)
		}
		if err != nil {
			return hostPlan{}, fmt.Errorf("persist host metadata: %w", err)
		}
	}
	if restarted && stored.HostID != stored.FounderID {
		return hostPlan{listen: loopback.listen, advertise: loopback.advertise, admission: stored,
			region: instance.Region, address: instance.PrivateIP}, nil
	}
	port := strconv.Itoa(swarmruntime.SwarmPort)
	founder := hostPlan{listen: net.JoinHostPort("0.0.0.0", port), advertise: net.JoinHostPort(instance.PrivateIP, port),
		admission: loopback.admission, region: instance.Region, address: instance.PrivateIP}
	if restarted {
		founder.admission = stored
		return founder, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return hostPlan{}, err
	}
	for {
		material, err := regionjoin.Claim(ctx, instance.Region, hostname)
		switch {
		case err != nil:
			fmt.Fprintf(output, "region join: %v; retrying\n", err)
		case material.Founder == hostname:
			return founder, nil
		case material.Manager != "" && material.WorkerToken != "":
			fmt.Fprintf(output, "joining %s at %s\n", material.Founder, material.Manager)
			return hostPlan{listen: loopback.listen, advertise: loopback.advertise, region: instance.Region, address: instance.PrivateIP,
				admission: swarmruntime.JoinerAdmission(hostname, instance.ID, material.Manager, material.WorkerToken)}, nil
		default:
			fmt.Fprintf(output, "waiting for founder %s to publish %s\n", material.Founder, regionjoin.SecretName(instance.Region))
		}
		select {
		case <-ctx.Done():
			return hostPlan{}, ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
}

// publishJoin keeps the region's join material current in Vault. A denial
// (hosts not yet allowed to manage the secret) is logged and retried; the
// founder keeps serving.
func publishJoin(ctx context.Context, state string, plan hostPlan) {
	hostname, err := os.Hostname()
	if err != nil {
		slog.WarnContext(ctx, "region join material not published", "error", err)
		return
	}
	for {
		err := func() error {
			client, conn, err := swarmruntime.DialSingleHost(state)
			if err != nil {
				return err
			}
			defer conn.Close()
			clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
			if err != nil || len(clusters.Clusters) != 1 {
				return errors.Join(errors.New("read the cluster's worker join token"), err)
			}
			return regionjoin.Publish(ctx, plan.region, regionjoin.Material{Founder: hostname, Manager: plan.advertise,
				WorkerToken: clusters.Clusters[0].RootCA.JoinTokens.Worker, Route: meshRoute(plan.address)})
		}()
		wait := 10 * time.Minute
		if err != nil {
			slog.WarnContext(ctx, "region join material not published; retrying", "secret", regionjoin.SecretName(plan.region), "error", err)
			wait = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// relayRelease publishes CI's accepted ts-orch release request to the
// region's workers over the mesh. A worker that misses it catches up on the
// next push, which CI repeats until every region is current.
func relayRelease(state, region string, request []byte) {
	conn, err := mesh.Connect(state)
	if err != nil {
		slog.Warn("release not relayed to the region's workers", "error", err)
		return
	}
	defer conn.Close()
	if err := errors.Join(conn.Publish(protocol.MeshWorkerReleasePrefix+region, request), conn.Flush()); err != nil {
		slog.Warn("release not relayed to the region's workers", "error", err)
	}
}

// serveWorkerReleases installs the releases this worker's founder relays,
// reconnecting to the local mesh node until ctx ends.
func serveWorkerReleases(ctx context.Context, state, region string, releases *releasepush.Handler) {
	for ctx.Err() == nil {
		conn, err := mesh.Connect(state)
		if err == nil {
			closed := make(chan struct{})
			conn.SetClosedHandler(func(*nats.Conn) { close(closed) })
			if err = releases.ServeWorker(conn, protocol.MeshWorkerReleasePrefix+region); err == nil {
				select {
				case <-ctx.Done():
				case <-closed:
				}
			}
			conn.Close()
		}
		if err != nil {
			slog.WarnContext(ctx, "worker release subscription failed; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
}

func meshRoute(address string) string {
	return "nats://" + net.JoinHostPort(address, strconv.Itoa(mesh.ClusterPort))
}

func meshCluster(plan hostPlan) mesh.Cluster {
	cluster := mesh.Cluster{Worker: plan.joiner()}
	if cluster.Worker {
		cluster.Routes = func(ctx context.Context, region string) ([]string, error) {
			material, err := regionjoin.Read(ctx, region)
			if err == nil && material.Route == "" {
				err = fmt.Errorf("%s names no mesh route yet", regionjoin.SecretName(region))
			}
			return []string{material.Route}, err
		}
	}
	return cluster
}
