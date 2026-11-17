// Package app composes the controller, host, and regional operator runtime.
package app

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func RunNode(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("node", flag.ContinueOnError)
	flags.SetOutput(output)
	state := flags.String("state", "/var/lib/ts-orch", "absolute state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("node accepts only --state")
	}
	if os.Geteuid() != 0 {
		return errors.New("node requires root")
	}
	if err := os.MkdirAll(*state, 0o700); err != nil {
		return err
	}
	stateLock := flock.New(filepath.Join(*state, "runtime.lock"))
	locked, err := stateLock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("another ts-orch node already runs on %s", *state)
	}
	defer stateLock.Unlock()
	startupErr := sdnotify.Process().ExtendStart(2 * hostMetadataWindow)
	probation, err := releasepush.Probe(*state, output)
	if err != nil {
		return err
	}
	if startupErr != nil {
		return fmt.Errorf("extend host startup window: %w", startupErr)
	}
	plan, err := planHost(ctx, *state, output)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	swarmReady := make(chan struct{})
	edgeDone := make(chan error, 1)
	public := edge.New(*state)
	go func() {
		err := public.Run(ctx)
		cancel()
		edgeDone <- err
	}()
	var inventory atomic.Pointer[func() (mesh.EdgeInventory, bool)]
	published := make(chan struct{}, 1)
	go public.FollowInventory(ctx, func() (mesh.EdgeInventory, bool) {
		if source := inventory.Load(); source != nil {
			return (*source)()
		}
		return mesh.EdgeInventory{}, false
	}, func(ctx context.Context, ref string) error {
		return refreshEdgeRequestProof(ctx, public, ref, vaultsecret.ReadInstanceSecrets)
	}, published)
	var meshNode atomic.Pointer[mesh.Node]
	manager := plan.admission.Role == "manager"
	if !manager {
		public.SetInventoryFollower()
	}
	var local atomic.Pointer[mesh.EdgeInventory]
	if manager {
		source := func() (mesh.EdgeInventory, bool) {
			if current := local.Load(); current != nil {
				return *current, true
			}
			return mesh.EdgeInventory{}, false
		}
		inventory.Store(&source)
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-swarmReady:
		}
		syncEdgeInventory(ctx, *state, plan.region, func(current mesh.EdgeInventory) {
			if manager {
				local.Store(&current)
				select {
				case published <- struct{}{}:
				default:
				}
			}
			if node := meshNode.Load(); node != nil {
				if err := node.PublishEdgeInventory(*state, current); err != nil {
					slog.WarnContext(ctx, "edge inventory publication failed", "error", err)
				}
			}
		})
	}()
	meshDone := make(chan struct{})
	if plan.joiner() && plan.address == "" {
		close(meshDone) // a worker without IMDS stays out of the region's NATS cluster
	} else {
		go func() {
			mesh.Run(ctx, *state, meshCluster(plan), func(node *mesh.Node) {
				meshNode.Store(node)
				plannedstop.Register(ctx, node.PrepareStop)
				handoff.SetTaskDrainer(node.DrainTask)
				handoff.SetBootstrap(node.Bootstrap)
				handoff.SetClearPeer(node.ClearPeer)
				public.JoinMesh(node)
				if manager {
					node.SetRegionalDrainer(public.DrainRegionalNode)
					node.SetBootstrap(public.Bootstrap)
				} else {
					follow := node.FollowEdgeInventory(*state)
					inventory.Store(&follow)
				}
			})
			close(meshDone)
		}()
	}
	err = serveNode(ctx, *state, output, plan, public, probation, swarmReady, func(ctx context.Context, service string) releasepush.HealthResult {
		return releaseHealth(ctx, *state, service, meshNode.Load(), public)
	}, func(ctx context.Context) error {
		if node := meshNode.Load(); node != nil {
			return node.PrepareStop(ctx)
		}
		if plan.region == "" || (plan.joiner() && plan.address == "") {
			return nil
		}
		return errors.New("mesh not started; planned release refused")
	}, func() {
		if node := meshNode.Load(); node != nil {
			node.AbortStop()
		}
	})
	cancel()
	<-meshDone
	return errors.Join(err, <-edgeDone)
}

func syncEdgeInventory(ctx context.Context, state, region string, publish func(mesh.EdgeInventory)) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	ref := ""
	for {
		if swarmruntime.HoldsManagerCertificate(state) {
			ref = publishEdgeRoutes(ctx, state, region, ref, publish)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func publishEdgeRoutes(ctx context.Context, state, region, ref string, publish func(mesh.EdgeInventory)) string {
	client, conn, err := swarmruntime.DialControl(state)
	if err != nil {
		slog.WarnContext(ctx, "edge control socket unavailable", "error", err)
		return ref
	}
	defer conn.Close()
	list, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		slog.WarnContext(ctx, "edge route sync failed", "error", err)
		return ref
	}
	web, postgres, services := edgeRouteTables(list.Services, region)
	ref, err = edge.RequestProofRef(list.Services, ref)
	if err != nil {
		slog.WarnContext(ctx, "edge request proof reference invalid", "error", err)
	}
	publish(mesh.EdgeInventory{Web: web, Postgres: postgres, Services: services, Readiness: edgeReadinessRoutes(list.Services, region), ProofRef: ref})
	return ref
}

func edgeRoutes(services []*api.Service, region string) (web, postgres map[string]int) {
	web, postgres, _ = edgeRouteTables(services, region)
	return web, postgres
}

func edgeRouteTables(services []*api.Service, region string) (web, postgres map[string]int, owners map[string]string) {
	services = slices.Clone(services)
	slices.SortStableFunc(services, func(a, b *api.Service) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	web, postgres = map[string]int{}, map[string]int{}
	owners, derivedOwners := map[string]string{}, map[string]string{}
	derived, derivedPG := map[string]int{}, map[string]int{}
	derive := func(table map[string]int, host string, port int) {
		if region != "" && (host == "api.terrascale.tech" || host == "pg.terrascale.tech") {
			if _, owned := table[region+"."+host]; !owned {
				table[region+"."+host] = port
			}
		}
	}
	for _, svc := range services {
		labels := svc.Spec.Annotations.Labels
		var ports []*api.PortConfig
		if svc.Spec.Endpoint != nil {
			ports = svc.Spec.Endpoint.Ports
		}
		port, _ := strconv.Atoi(labels[swarmruntime.LabelPort])
		if len(ports) != 0 {
			port = int(ports[0].PublishedPort)
		}
		if port == 0 {
			continue
		}
		for host := range strings.SplitSeq(labels[swarmruntime.LabelHostnames], ",") {
			if host == "" {
				continue
			}
			if _, owned := web[host]; !owned {
				web[host] = port
				owners[host] = svc.Spec.Annotations.Name
			}
			if _, owned := derived[region+"."+host]; !owned {
				derivedOwners[region+"."+host] = svc.Spec.Annotations.Name
			}
			derive(derived, host, port)
		}
		if pgHost := labels[swarmruntime.LabelPostgres]; pgHost != "" && len(ports) >= 2 {
			if _, owned := postgres[pgHost]; !owned {
				postgres[pgHost] = int(ports[1].PublishedPort)
			}
			derive(derivedPG, pgHost, int(ports[1].PublishedPort))
		}
	}
	for host, port := range derived {
		if _, declared := web[host]; !declared {
			web[host] = port
			owners[host] = derivedOwners[host]
		}
	}
	for host, port := range derivedPG {
		if _, declared := postgres[host]; !declared {
			postgres[host] = port
		}
	}
	return web, postgres, owners
}

func releaseHealth(ctx context.Context, state, service string, node *mesh.Node, public *edge.Edge) releasepush.HealthResult {
	admission, _, err := swarmruntime.StoredAdmission(state)
	if err != nil {
		return releasepush.HealthResult{Service: err}
	}
	manager := admission.Role == "manager"
	result := releasepush.HealthResult{}
	if manager {
		result.Service = regionhealth.Serving(ctx, state, service)
	}
	switch {
	case node == nil:
		result.Mesh = errors.New("mesh not started")
	case manager:
		result.Mesh = node.ReleaseHealth(ctx)
	}
	if public != nil {
		result.Edge = public.Readiness(ctx).InfraErr()
	}
	return result
}
