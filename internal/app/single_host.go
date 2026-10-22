package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// runSingleHost runs this host's SwarmKit node (plan) with the containerd
// executor and the release NATS listener (:4222) CI pushes releases to.
// Outside OCI it needs no Vault, NetBird or admission.
func runSingleHost(ctx context.Context, state string, output io.Writer, plan hostPlan) error {
	executor, err := swarmruntime.NewExecutor("/run/containerd/containerd.sock", state)
	if err != nil {
		return err
	}
	if err := executor.BindVaultSecrets(vaultsecret.ReadInstanceSecrets); err != nil {
		return err
	}
	defer executor.Close()
	if err := executor.SetRegistryResolver(swarmruntime.GHCRResolver(func(ctx context.Context) (string, error) {
		return vaultsecret.ReadInstanceSecret(ctx, "ghcr-pull-token")
	})); err != nil {
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
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = node.Stop(stop)
	}()
	healthCtx, stopHealth := context.WithCancel(ctx)
	defer stopHealth()
	// shortcut: a worker has no control socket and would answer for its region a second time; give workers their own health row when they serve.
	if !plan.joiner() {
		go regionhealth.Run(healthCtx, state)
	}
	if err := releasepush.EnsureFirewall(ctx); err != nil {
		// Workloads keep serving; only release pushes are blocked until the next start.
		fmt.Fprintf(output, "release listener firewall: %v\n", err)
	}
	// The edge's :80/:443 sit behind the same Ubuntu OCI image INPUT REJECT.
	for _, port := range []int{80, 443} {
		if err := releasepush.OpenTCP(ctx, port); err != nil {
			fmt.Fprintf(output, "edge firewall: %v\n", err)
		}
	}
	releases, err := releasepush.NewHandler(state)
	if err != nil {
		return err
	}
	releases.Mesh = mesh.Bridge(state)
	releases.App = mesh.Release(state)
	natsServer, natsConn, err := releasepush.Start(state)
	if err != nil {
		return err
	}
	defer natsServer.Shutdown()
	defer natsConn.Close()
	if err := releases.Serve(natsConn); err != nil {
		return err
	}
	if founder {
		go publishJoin(ctx, state, plan)
	}
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("single-host node ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintf(output, "single-host %s %s ready; advertise %s\n", plan.admission.Role, node.ID(), plan.advertise); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- node.Wait(ctx) }()
	select {
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

// planHost reuses the stored admission of a restarted host. A fresh OCI host
// founds its region's cluster when it wins the region's Vault claim and
// otherwise joins the founder that published join material; it waits and
// retries until one holds, since it serves nothing yet.
func planHost(ctx context.Context, state string, output io.Writer) (hostPlan, error) {
	loopback := hostPlan{listen: swarmruntime.SingleHostAddress, advertise: swarmruntime.SingleHostAddress, admission: swarmruntime.FounderAdmission()}
	stored, restarted, err := swarmruntime.StoredAdmission(state)
	if err != nil {
		return hostPlan{}, err
	}
	var instance regionjoin.Instance
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		if instance, err = regionjoin.Local(ctx); err == nil || ctx.Err() != nil {
			break
		}
	}
	if restarted && stored.HostID != stored.FounderID {
		// A worker binds no remote API and reconnects from its persisted manager
		// list; without IMDS it only runs its tasks, outside the mesh.
		return hostPlan{listen: loopback.listen, advertise: loopback.advertise, admission: stored,
			region: instance.Region, address: instance.PrivateIP}, nil
	}
	if err != nil {
		// shortcut: an IMDS outage at an OCI host's first start founds a loopback cluster no host joins; fence it if one is ever seen.
		fmt.Fprintf(output, "not an OCI host (%v); founding a loopback-only cluster\n", err)
		return loopback, nil
	}
	port := strconv.Itoa(swarmruntime.SwarmPort)
	founder := hostPlan{listen: net.JoinHostPort("0.0.0.0", port), advertise: net.JoinHostPort(instance.PrivateIP, port),
		admission: loopback.admission, region: instance.Region, address: instance.PrivateIP}
	if restarted {
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

func meshRoute(address string) string {
	return "nats://" + net.JoinHostPort(address, strconv.Itoa(mesh.ClusterPort))
}

// meshCluster places this host's mesh server in its region's NATS cluster;
// a worker routes to the founder that published the region's join material.
func meshCluster(plan hostPlan) mesh.Cluster {
	cluster := mesh.Cluster{Address: plan.address, Worker: plan.joiner()}
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
