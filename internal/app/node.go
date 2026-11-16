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
	"slices"
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
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func serveNode(ctx context.Context, state string, output io.Writer, plan hostPlan, probation *releasepush.Probation, swarmReady chan struct{}, health func(context.Context, string) releasepush.HealthResult, prepareStop func(context.Context) error, abortStop func()) error {
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
	if plan.region != "" && plan.address != "" {
		if err := swarmruntime.OpenFirewall(ctx, plan.address, plan.vcnCIDR); err != nil {
			fmt.Fprintf(output, "swarm firewall: %v\n", err)
		}
	}
	node, err := swarmruntime.StartHost(ctx, state, executor, plan.listen, plan.advertise, plan.admission)
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
	go executor.ReapExitedTasks(healthCtx)
	failed := make(chan error, 2)
	go func() {
		if err := executor.ServeBootstrap(healthCtx, state); healthCtx.Err() == nil {
			failed <- errors.Join(errors.New("bootstrap executor endpoint stopped"), err)
		}
	}()
	go runManagerServices(healthCtx, state, plan, node, executor, failed)
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
	releases.PrepareStop = prepareStop
	releases.AbortStop = abortStop
	releases.Mesh = mesh.Bridge(state)
	releases.App = mesh.Release(state)
	if plan.region != "" {
		releases.Claim = func(ctx context.Context, release, sha string, digests map[string]string) error {
			if !node.IsManager() {
				return nil
			}
			fabric, err := mesh.ConnectFabric(state)
			if err != nil {
				return err
			}
			defer fabric.Close()
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return pullrelease.ClaimPush(ctx, fabric, plan.region, pullrelease.PushClaim{Release: release, SHA: sha, Binaries: digests, Host: node.ID()})
		}
		releases.Unclaim = func(ctx context.Context, release string) {
			if !node.IsManager() {
				return
			}
			fabric, err := mesh.ConnectFabric(state)
			if err == nil {
				defer fabric.Close()
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				err = pullrelease.ReleasePush(ctx, fabric, plan.region, release)
			}
			if err != nil {
				slog.WarnContext(ctx, "release push claim not released; the region's updater drops it when it lapses", "release", release, "error", err)
			}
		}
		releases.HostReady = func(ctx context.Context, host, sha string, digests map[string]string) error {
			conn, err := mesh.Connect(state)
			if err != nil {
				return err
			}
			defer conn.Close()
			return releasepush.AwaitReady(ctx, conn, plan.region, host, sha, digests)
		}
		releases.Relay = func(ctx context.Context, request []byte) []releasepush.HostVersion {
			if node.IsManager() {
				return relayRelease(ctx, state, plan.region, request)
			}
			return nil
		}
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
	if plan.region != "" {
		go serveHostReleases(ctx, state, plan.region, node, releases)
		go runPullUpdates(ctx, state, plan.region, node, releases)
	}
	notifier := sdnotify.Process()
	if err := notifier.Ready("node ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintf(output, "node %s %s ready; advertise %s\n", plan.admission.Role, node.ID(), plan.advertise); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- node.Wait(ctx) }()
	go func() {
		defer func() {
			if value := recover(); value != nil {
				slog.Warn("Host log settings skipped", "panic", fmt.Sprint(value))
			}
		}()
		if err := ensureHostLogs(ctx); err != nil {
			slog.Warn("Host log settings skipped", "error", err)
		} else {
			slog.Info("Host log settings applied")
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-failed:
		slog.ErrorContext(ctx, "node background service failed", "error", err)
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

func runManagerServices(ctx context.Context, state string, plan hostPlan, node *swarmruntime.Node, executor *swarmruntime.Executor, failed chan<- error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		manager := node.IsManager()
		serving, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if manager {
				serveManagerRole(serving, state, plan, node, executor, failed)
			} else {
				syncHostTargets(serving)
			}
		}()
		for ctx.Err() == nil && node.IsManager() == manager {
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
		}
		stop()
		<-done
	}
}

func serveManagerRole(ctx context.Context, state string, plan hostPlan, node *swarmruntime.Node, executor *swarmruntime.Executor, failed chan<- error) {
	serving, stop := context.WithCancel(ctx)
	defer stop()
	go regionhealth.Run(serving, state)
	targetsDone := make(chan struct{})
	go func() {
		defer close(targetsDone)
		syncSLOTargets(serving, state, plan.region, executor)
	}()
	defer func() {
		stop()
		<-targetsDone
	}()
	if plan.region != "" {
		go publishJoin(serving, state, plan, node.ID())
		go func() {
			if err := hostdashboard.Run(serving, state, plan.region); serving.Err() == nil {
				select {
				case failed <- errors.Join(errors.New("host dashboard stopped"), err):
				case <-ctx.Done():
				}
			}
		}()
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for node.IsManager() {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

type hostPlan struct {
	listen, advertise        string
	admission                swarmruntime.Admission
	region, address, vcnCIDR string
}

func (p hostPlan) joiner() bool { return p.admission.HostID != p.admission.FounderID }

func planHost(ctx context.Context, state string, output io.Writer) (hostPlan, error) {
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
		if _, err := os.Stat(swarmruntime.SwarmDir(state)); err == nil {
			return hostPlan{}, errors.New("cluster state exists without stored admission")
		} else if !errors.Is(err, os.ErrNotExist) {
			return hostPlan{}, err
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return hostPlan{}, err
	}
	if !oracle {
		local := hostPlan{admission: swarmruntime.FoundingAdmission(hostname, hostname)}
		local.listen, local.advertise = swarmruntime.SwarmAddresses("")
		if restarted {
			if stored.HostID != stored.FounderID {
				return hostPlan{}, errors.New("host platform is not Oracle but stored mesh worker admission exists")
			}
			local.admission = stored
		}
		fmt.Fprintln(output, "local host; using a loopback-only cluster")
		return local, nil
	}
	instance, metadataErr := readHostMetadata(ctx, output)
	if err := ctx.Err(); err != nil {
		return hostPlan{}, err
	}
	if metadataErr != nil {
		if !restarted {
			return hostPlan{}, fmt.Errorf("read host metadata: %w", metadataErr)
		}
		if stored.Role == "manager" {
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
	plan := hostPlan{region: instance.Region, address: instance.PrivateIP, vcnCIDR: instance.VCNCIDR}
	plan.listen, plan.advertise = swarmruntime.SwarmAddresses(instance.PrivateIP)
	if restarted {
		plan.admission = stored
		return plan, nil
	}
	for {
		material, err := regionjoin.Claim(ctx, instance.Region, hostname)
		switch {
		case err != nil:
			fmt.Fprintf(output, "region join: %v; retrying\n", err)
		default:
			manager, joinable := "", false
			if material.WorkerToken != "" {
				manager, joinable = reachableManager(ctx, material.Managers)
			}
			switch {
			case joinable:
				plan.admission, err = swarmruntime.JoiningAdmission(hostname, instance.ID, manager, material.WorkerToken)
				if err != nil {
					return hostPlan{}, err
				}
				fmt.Fprintf(output, "joining %s at %s as a worker\n", regionjoin.SecretName(instance.Region), manager)
				return plan, nil
			case material.Founder == hostname:
				plan.admission = swarmruntime.FoundingAdmission(hostname, instance.ID)
				return plan, nil
			case material.WorkerToken != "":
				fmt.Fprintf(output, "no manager in %s answers yet\n", regionjoin.SecretName(instance.Region))
			default:
				fmt.Fprintf(output, "waiting for founder %s to publish %s\n", material.Founder, regionjoin.SecretName(instance.Region))
			}
		}
		select {
		case <-ctx.Done():
			return hostPlan{}, ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
}

func publishJoin(ctx context.Context, state string, plan hostPlan, nodeID string) {
	for {
		err := func() error {
			client, conn, err := swarmruntime.DialControl(state)
			if err != nil {
				return err
			}
			defer conn.Close()
			listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
			if err != nil {
				return err
			}
			if !swarmruntime.IsLeader(listed.Nodes, nodeID) {
				return nil
			}
			managers, members := []string{}, []string{}
			for _, node := range listed.Nodes {
				if node.Status.State != api.NodeStatus_READY {
					continue
				}
				if node.Role != api.NodeRoleManager {
					members = append(members, node.Status.Addr)
					continue
				}
				if node.ManagerStatus == nil {
					continue
				}
				managers = append(managers, node.ManagerStatus.Addr)
				members = append(members, hostOf(node.ManagerStatus.Addr))
			}
			slices.Sort(managers)
			slices.Sort(members)
			routes := []string{}
			for _, member := range members {
				routes = append(routes, meshRoute(member))
			}
			stored, err := regionjoin.Read(ctx, plan.region)
			if err != nil {
				return err
			}
			if stored.WorkerToken == "" {
				clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
				if err != nil || len(clusters.Clusters) != 1 {
					return errors.Join(errors.New("read the cluster's worker join token"), err)
				}
				stored.WorkerToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
			}
			stored.Managers, stored.Routes = managers, routes
			return regionjoin.Publish(ctx, plan.region, stored)
		}()
		if err != nil {
			slog.WarnContext(ctx, "region join material not published; retrying", "secret", regionjoin.SecretName(plan.region), "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func reachableManager(ctx context.Context, managers []string) (string, bool) {
	for _, manager := range managers {
		dial, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := (&net.Dialer{}).DialContext(dial, "tcp", manager)
		cancel()
		if err == nil {
			_ = conn.Close()
			return manager, true
		}
	}
	return "", false
}

func hostOf(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func relayRelease(ctx context.Context, state, region string, request []byte) []releasepush.HostVersion {
	var nodes []*api.Node
	control, closer, err := swarmruntime.DialControl(state)
	if err == nil {
		defer closer.Close()
		inventoryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		listed, err := control.ListNodes(inventoryCtx, &api.ListNodesRequest{})
		if err == nil {
			nodes = append([]*api.Node{}, listed.Nodes...)
		}
	}
	conn, err := mesh.Connect(state)
	if err != nil {
		rows := []releasepush.HostVersion{}
		for _, node := range nodes {
			if node.Role == api.NodeRoleWorker {
				rows = append(rows, releasepush.HostVersion{ID: node.ID, Host: node.ID, Error: "no answer"})
			}
		}
		if nodes == nil {
			rows = append(rows, releasepush.HostVersion{Host: "worker inventory", Error: "no answer"})
		}
		return rows
	}
	defer conn.Close()
	return releasepush.RelayWorkers(ctx, conn, protocol.MeshWorkerReleasePrefix+region, request, nodes)
}

func serveHostReleases(ctx context.Context, state, region string, node *swarmruntime.Node, releases *releasepush.Handler) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		worker := !node.IsManager()
		roleChanged := false
		conn, err := mesh.Connect(state)
		if err == nil {
			closed := make(chan struct{})
			conn.SetClosedHandler(func(*nats.Conn) { close(closed) })
			err = releases.ServeHostVersion(conn, region, node.ID())
			if err == nil {
				err = releases.ServePulled(conn, region, node.ID())
			}
			if err == nil && worker {
				err = releases.ServeWorker(conn, protocol.MeshWorkerReleasePrefix+region, node.ID())
			}
			if err == nil {
			wait:
				for {
					select {
					case <-ctx.Done():
						break wait
					case <-closed:
						break wait
					case <-tick.C:
						if worker == node.IsManager() {
							roleChanged = true
							break wait
						}
					}
				}
			}
			conn.Close()
		}
		if roleChanged {
			continue
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

func runPullUpdates(ctx context.Context, state, region string, node *swarmruntime.Node, releases *releasepush.Handler) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		if !node.IsManager() {
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
			continue
		}
		conn, err := mesh.Connect(state)
		var fabric *nats.Conn
		if err == nil {
			if fabric, err = mesh.ConnectFabric(state); err != nil {
				conn.Close()
			}
		}
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
			}
			continue
		}
		managing, stop := context.WithCancel(ctx)
		go func() {
			for managing.Err() == nil && node.IsManager() && !conn.IsClosed() && !fabric.IsClosed() {
				select {
				case <-managing.Done():
				case <-tick.C:
				}
			}
			stop()
		}()
		updater := pullrelease.New(region, node.ID(), state, conn, fabric, releases, func(ctx context.Context) ([]pullrelease.Host, error) {
			return regionHosts(ctx, state)
		})
		if err := updater.Run(managing); err != nil && ctx.Err() == nil && managing.Err() == nil {
			slog.WarnContext(ctx, "pull release updater stopped", "error", err)
		}
		stop()
		conn.Close()
		fabric.Close()
	}
}

func regionHosts(ctx context.Context, state string) ([]pullrelease.Host, error) {
	control, closer, err := swarmruntime.DialControl(state)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	listed, err := control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	hosts := make([]pullrelease.Host, 0, len(listed.Nodes))
	for _, node := range listed.Nodes {
		name := node.ID
		if node.Description != nil && node.Description.Hostname != "" {
			name = node.Description.Hostname
		}
		hosts = append(hosts, pullrelease.Host{ID: node.ID, Name: name})
	}
	return hosts, nil
}

func meshRoute(address string) string {
	return "nats://" + net.JoinHostPort(address, strconv.Itoa(mesh.ClusterPort))
}

func meshCluster(plan hostPlan) mesh.Cluster {
	cluster := mesh.Cluster{Worker: plan.admission.Role != "manager"}
	cluster.VCN, _, _ = swarmruntime.VCNPrefix(plan.address, plan.vcnCIDR)
	if plan.joiner() {
		cluster.Routes = func(ctx context.Context, region string) ([]string, error) {
			material, err := regionjoin.Read(ctx, region)
			if err != nil {
				return nil, err
			}
			if len(material.Routes) == 0 {
				return nil, fmt.Errorf("%s names no mesh route yet", regionjoin.SecretName(region))
			}
			return material.Routes, nil
		}
	}
	return cluster
}
