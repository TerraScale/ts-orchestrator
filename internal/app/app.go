// Package app composes the controller, host, and regional operator runtime.
package app

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// RunSingleHostServing runs this host's SwarmKit node (founder or joiner of
// its region's cluster, planHost) together with the public HTTPS edge, which
// routes each service's hostnames to its published loopback port, and the
// cross-region mesh that applies services in every region.
func RunSingleHostServing(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("single-host", flag.ContinueOnError)
	flags.SetOutput(output)
	state := flags.String("state", "/var/lib/ts-orch", "absolute state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("single-host accepts only --state")
	}
	if os.Geteuid() != 0 {
		return errors.New("single-host requires root")
	}
	startupErr := sdnotify.Process().ExtendStart(2 * hostMetadataWindow)
	probation, err := releasepush.Probe(*state, output)
	if err != nil {
		return err
	}
	if startupErr != nil {
		return fmt.Errorf("extend host startup window: %w", startupErr)
	}
	nodelist.InitIdentity(*state)
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
	go public.FollowInventory(ctx, func() (mesh.EdgeInventory, bool) {
		if source := inventory.Load(); source != nil {
			return (*source)()
		}
		return mesh.EdgeInventory{}, false
	}, func(ctx context.Context, ref string) error {
		return refreshEdgeRequestProof(ctx, public, ref, vaultsecret.ReadInstanceSecrets)
	})
	var meshNode atomic.Pointer[mesh.Node]
	manager := plan.admission.Role == "manager"
	if !manager {
		public.SetInventoryFollower()
	}
	if manager {
		var local atomic.Pointer[mesh.EdgeInventory]
		source := func() (mesh.EdgeInventory, bool) {
			if current := local.Load(); current != nil {
				return *current, true
			}
			return mesh.EdgeInventory{}, false
		}
		inventory.Store(&source)
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-swarmReady:
			}
			syncEdgeInventory(ctx, *state, plan.region, func(current mesh.EdgeInventory) {
				local.Store(&current)
				if node := meshNode.Load(); node != nil {
					if err := node.PublishEdgeInventory(*state, current); err != nil {
						slog.WarnContext(ctx, "edge inventory publication failed", "error", err)
					}
				}
			})
		}()
	}
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
	err = runSingleHost(ctx, *state, output, plan, probation, swarmReady, func(ctx context.Context, service string) releasepush.HealthResult {
		result := releasepush.HealthResult{Service: regionhealth.Serving(ctx, *state, service)}
		if node := meshNode.Load(); node != nil {
			result.Mesh = node.ReleaseHealth(ctx)
		} else {
			result.Mesh = errors.New("mesh not started")
		}
		readiness := public.Readiness(ctx)
		result.Edge = readiness.InfraErr()
		return result
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
	for {
		if client, conn, err := swarmruntime.DialSingleHost(state); err == nil {
			if list, err := client.ListServices(ctx, &api.ListServicesRequest{}); err == nil {
				web, postgres, services := edgeRouteTables(list.Services, region)
				ref, err := edgeProofRef(list.Services)
				if err != nil {
					slog.WarnContext(ctx, "edge request proof reference invalid", "error", err)
				}
				publish(mesh.EdgeInventory{Web: web, Postgres: postgres, Services: services, Readiness: edgeReadinessRoutes(list.Services, region), ProofRef: ref})
			} else {
				slog.WarnContext(ctx, "edge route sync failed", "error", err)
			}
			_ = conn.Close()
		} else {
			slog.WarnContext(ctx, "edge control socket unavailable", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// edgeRoutes maps every hostname a service declares to its published port,
// and every postgres hostname to its postgres port. The oldest service keeps
// a hostname another service also claims, so a later spec cannot take over
// traffic (apply refuses that too). On a host in region, every declared web
// or postgres hostname H also routes <region>.H, so each region's edge serves its own
// regional names with no per-region spec; a declared hostname wins over a
// derived one, and H whose first label already names a catalog region
// derives nothing.
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
		first, _, _ := strings.Cut(host, ".")
		if _, regional := catalog.LookupName(strings.ToLower(first)); region != "" && !regional {
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
		port, _ := strconv.Atoi(labels[swarmruntime.LabelPort]) // a spec using ${PORT} publishes none
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

func RunChild(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: terrascale-orchestrator child command")
	}
	command := args[0]
	if command == "bootstrap-credential-check" {
		if len(args) != 1 {
			return errors.New("bootstrap credential check accepts no arguments")
		}
		return bootstrapstart.RunCredentialValidationChild(os.Stdin, func(request bootstrapstart.CredentialChildRequest) error {
			if _, err := readPrivateKey(request.ResponseKeyFile); err != nil {
				return fmt.Errorf("controller response key: %w", err)
			}
			cfg := Config{NATS: request.Config, Controller: ControllerConfig{BrokerTicketKeyFile: request.BrokerTicketKeyFile}}
			_, _, err := brokerTicketKeys(cfg)
			return err
		})
	}
	if command == "bootstrap-admit-initial" || command == "bootstrap-admit-restart" {
		if len(args) != 1 {
			return errors.New("bootstrap admission child accepts no arguments")
		}
		return runControllerAdmissionChild(ctx, command, os.Stdin)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "JSON role configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", command)
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if command == "identity-rekey-completion-check" {
		return checkControllerIdentityRekeyCompletion(ctx, cfg)
	}
	return fmt.Errorf("unknown command %q", command)
}

var hostClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private identity key file is required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be a regular file readable only by its owner")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("private key must be owned by this process user")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("private key must contain 64 Ed25519 bytes")
	}
	return ed25519.PrivateKey(decoded), nil
}

// hostRollouts makes a production host agent take part in the cell's
// orchestrator rollouts; the node's self-update watchdog applies the steps
// it spools, with the same rule (selfupdate/cli).
func hostRollouts(cfg Config, identity ed25519.PrivateKey, controller ed25519.PublicKey,
) func(context.Context, host.RolloutSession) {
	return followHostRollouts(hostRollout{cell: cfg.NATS.Cell, node: cfg.Host.Node, identity: identity,
		controller: controller, spool: rolloutexec.HostSpoolDir, stateRoot: cfg.Host.StateRoot,
		layout: selfupdate.NewLayout(cmp.Or(cfg.Host.SelfUpdateRoot, selfupdate.DefaultRoot))})
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("expected a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}
