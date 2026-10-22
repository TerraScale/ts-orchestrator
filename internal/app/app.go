// Package app composes the controller, host, and regional operator runtime.
package app

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
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
	plan, err := planHost(ctx, *state, output)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	edgeDone := make(chan error, 1)
	var public *edge.Edge // nil on a joiner, which serves no edge
	if plan.joiner() {
		// shortcut: a worker serves no edge (it has no control socket for routes; the founder's edge serves the region) and receives no release push (CI pushes only deploy/m1/regions.json hosts).
		edgeDone <- nil
	} else {
		public = edge.New(*state)
		go func() {
			err := public.Run(ctx)
			cancel() // a failed edge stops the node, so systemd restarts both
			edgeDone <- err
		}()
		go syncEdgeRoutes(ctx, *state, public)
	}
	// The mesh never stops local serving; it retries until it reaches Vault and peers.
	meshDone := make(chan struct{})
	if plan.joiner() && plan.address == "" {
		close(meshDone) // a worker without IMDS stays out of the region's NATS cluster
	} else {
		go func() {
			mesh.Run(ctx, *state, meshCluster(plan), func(node *mesh.Node) {
				if public != nil {
					public.SetMesh(node)
				}
			})
			close(meshDone)
		}()
	}
	err = runSingleHost(ctx, *state, output, plan)
	cancel()
	<-meshDone
	return errors.Join(err, <-edgeDone)
}

func syncEdgeRoutes(ctx context.Context, state string, public *edge.Edge) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		// Dial errors are expected until the node opens its control socket.
		if client, conn, err := swarmruntime.DialSingleHost(state); err == nil {
			if list, err := client.ListServices(ctx, &api.ListServicesRequest{}); err == nil {
				public.SetRoutes(edgeRoutes(list.Services))
			} else {
				slog.WarnContext(ctx, "edge route sync failed", "error", err)
			}
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// edgeRoutes maps every hostname a service declares to its published port.
// The oldest service keeps a hostname another service also claims, so a later
// spec cannot take over traffic (apply refuses that too).
func edgeRoutes(services []*api.Service) map[string]int {
	services = slices.Clone(services)
	slices.SortStableFunc(services, func(a, b *api.Service) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	routes := map[string]int{}
	for _, svc := range services {
		hosts := svc.Spec.Annotations.Labels[swarmruntime.LabelHostnames]
		if hosts == "" || svc.Spec.Endpoint == nil || len(svc.Spec.Endpoint.Ports) == 0 {
			continue
		}
		for host := range strings.SplitSeq(hosts, ",") {
			if _, owned := routes[host]; !owned {
				routes[host] = int(svc.Spec.Endpoint.Ports[0].PublishedPort)
			}
		}
	}
	return routes
}

func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: terrascale-orchestrator <bootstrap-controller|run|host|check|operator|identity-new|netbird-enroll|netbird-agent> --config FILE")
	}
	command := args[0]
	if command == "runtime-worker-admission-source" {
		return runRuntimeWorkerAdmissionSource(ctx, args[1:], os.Stdin, output)
	}
	if command == runtimeControllerHostSourceCommand {
		return runRuntimeControllerHostAdmissionSource(ctx, args[1:], os.Stdin, output)
	}
	if command == "runtime-worker-membership-source" {
		return runRuntimeWorkerMembershipSource(ctx, args[1:], os.Stdin, output)
	}
	if command == runtimeRegistrySourceCommand {
		return runRuntimeRegistrySource(ctx, args[1:], os.Stdin, output)
	}
	if command == "netbird-agent" {
		return runNetBirdAgent(ctx, args[1:])
	}
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
	if command == "identity-new" {
		return newIdentity(args[1:], output)
	}
	if command == "netbird-enroll" {
		return runNetBirdEnroll(ctx, args[1:], output)
	}
	if command == "install-controller-config" {
		return runInstallControllerConfig(ctx, args[1:])
	}
	if command == "identity-rekey" {
		return runIdentityRekey(ctx, args[1:], output)
	}
	if command == "host-setup" {
		return runHostSetup(ctx, args[1:], output)
	}
	if command == "restore-controller-material" {
		return runRestoreControllerMaterial(ctx, args[1:], output)
	}
	if command == "host-volume-init" {
		return runHostVolumeInit(ctx, args[1:])
	}
	if command == "operator" {
		return runOperator(ctx, args[1:], output)
	}
	if command == "service" {
		return runService(ctx, args[1:], output)
	}
	if command == "get" || command == "diff" || command == "apply" {
		return runSpec(ctx, command, args[1:], output)
	}
	if command == "rollout" {
		return runRollout(ctx, args[1:], output)
	}
	if command == "node" {
		return runNode(ctx, args[1:], output)
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
	switch command {
	case "bootstrap-controller":
		return controllerBootstrapCommand(ctx, cfg)
	case "run":
		return runController(ctx, cfg, output)
	case "host":
		return runHost(ctx, cfg, *configPath, output)
	case "check":
		return check(ctx, cfg, output)
	case "identity-rekey-completion-check":
		return checkControllerIdentityRekeyCompletion(ctx, cfg)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

var hostClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

func runHost(ctx context.Context, cfg Config, configPath string, output io.Writer) error {
	ctx, restart := context.WithCancelCause(ctx)
	defer restart(nil)
	memoryRuntime, layout, release := hostMemoryRuntime(cfg)
	if !memoryRuntime && release != "" {
		go restartWhenKnownGood(ctx, layout, release, restart)
	}
	notifier := sdnotify.FromEnvironment()
	if cfg.NATS.Embedded != nil {
		return errors.New("host role cannot start the regional NATS server")
	}
	cfg.NATS.ClientRole = "host"
	telemetry, err := startRuntimeObservability(ctx, cfg, "host", cfg.Host.Node)
	if err != nil {
		return fmt.Errorf("start host observability: %w", err)
	}
	defer telemetry.close()
	key, err := readPrivateKey(cfg.Host.IdentityKeyFile)
	if err != nil {
		return err
	}
	controllerKey, err := decodePublicKey(cfg.Host.ControllerPublicKey)
	if err != nil {
		return fmt.Errorf("controller response public key: %w", err)
	}
	natsUserPublicKey, err := hostNATSUserPublicKey(cfg.NATS)
	if err != nil {
		return fmt.Errorf("host NATS user public key: %w", err)
	}
	if !filepath.IsAbs(cfg.Host.StateRoot) {
		return errors.New("host state root must be absolute")
	}
	identity := host.WorkloadIdentity{UID: cfg.Host.WorkloadUID, GID: cfg.Host.WorkloadGID}
	if err := host.ValidateWorkloadPaths(cfg.Host.InstallRoot, cfg.Host.StateRoot, identity); err != nil {
		return fmt.Errorf("host workload paths: %w", err)
	}
	if err := host.ValidatePrivateHostState(cfg.Host.StateRoot, cfg.NATS.Cell, cfg.Host.Node); err != nil {
		return fmt.Errorf("host private state: %w", err)
	}
	if err := host.ValidateManagedRuntimeRoot(cfg.Host.ManagedRuntimeRoot, cfg.Host.InstallRoot, cfg.Host.StateRoot, identity); err != nil {
		return fmt.Errorf("host managed runtime root: %w", err)
	}
	var bakedSystemReserveBytes uint64
	var managedS3Credentials host.ManagedS3CredentialResolver
	var managedBackupDataKeys host.ManagedBackupDataKeyResolver
	if cfg.Host.ManagedRuntimeRoot != "" {
		resolver, resolverErr := host.NewOCIS3CredentialResolver(oci.Region(strings.ToUpper(cfg.NATS.Cell)))
		err = resolverErr
		if err != nil {
			return fmt.Errorf("host managed S3 credentials: %w", err)
		}
		managedS3Credentials = resolver
		managedBackupDataKeys = resolver
		bakedSystemReserveBytes, err = readBakedRuntimePriorityProfile()
		if err != nil {
			return fmt.Errorf("host image runtime priority profile: %w", err)
		}
	}
	clockCheck := controllerClockCheck(hostClockProbe())
	if err := clockCheck(); err != nil {
		return fmt.Errorf("host NTP clock health: %w", err)
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, 15*time.Second)
	err = host.ProbeNativeRuntime(probeCtx, filepath.Join(cfg.Host.StateRoot, cfg.NATS.Cell, cfg.Host.Node), identity)
	stopProbe()
	if err != nil {
		return fmt.Errorf("host native runtime probe: %w", err)
	}
	if configPath != "" {
		cfg.NATS.ReloadClientMaterial = hostCredentialReloader(configPath, cfg, key)
	}
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	agent, err := host.NewAgent(host.AgentConfig{
		Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Environment: cfg.Host.Environment,
		Roles: cfg.Host.Roles, Conn: runtime.Conn(), Identity: key, NATSUserPublicKey: natsUserPublicKey, ControllerPublicKey: controllerKey,
		InstallRoot: cfg.Host.InstallRoot, StateRoot: cfg.Host.StateRoot,
		ManagedRuntimeRoot:      cfg.Host.ManagedRuntimeRoot,
		TerraBaseRoot:           cfg.Host.TerraBaseRoot,
		TSAuthRoot:              cfg.Host.TSAuthRoot,
		RoleMemoryMaxBytes:      cfg.Host.RoleMemoryMaxBytes,
		SecretResolver:          vaultsecret.ReadRefs,
		NATSURL:                 cfg.NATS.URL,
		NATSCAFile:              cfg.NATS.TLS.CAFile,
		TerraBaseDataVolume:     cfg.Host.TerraBaseDataVolume,
		TerraBaseDataVolumeID:   cfg.Host.TerraBaseDataVolumeID,
		ManagedS3Credentials:    managedS3Credentials,
		ManagedBackupDataKeys:   managedBackupDataKeys,
		BakedSystemReserveBytes: bakedSystemReserveBytes,
		MemoryRuntime:           memoryRuntime,
		WorkloadIdentity:        identity,
		PollInterval:            time.Duration(cfg.Host.PollMillis) * time.Millisecond,
		ClockCheck:              clockCheck,
		FollowRollouts:          hostRollouts(cfg, key, controllerKey),
		FollowNetBird:           hostNetBird(cfg, controllerKey),
		VolumeInitSocket:        "/run/terrascale-orchestrator-volume-init.sock",
		// The activation proof follows native recovery, so a release whose
		// agent cannot recover its workloads is never confirmed.
		Initialized: func() {
			emitSelfUpdateProofWithKey(cfg.Host.SelfUpdateProofFile, cfg.Host.SelfUpdateRoot, key, hostUnit, output)
		},
	})
	if err != nil {
		return err
	}
	filesystems := []observability.FilesystemRole{{Role: "state", Path: cfg.Host.StateRoot},
		{Role: "install", Path: cfg.Host.InstallRoot}}
	if cfg.Host.ManagedRuntimeRoot != "" {
		filesystems = append(filesystems, observability.FilesystemRole{Role: "managed_runtime", Path: cfg.Host.ManagedRuntimeRoot})
	}
	if cfg.Host.TerraBaseRoot != "" {
		filesystems = append(filesystems, observability.FilesystemRole{Role: "terrabase_data", Path: terrabase.Layout(cfg.Host.TerraBaseRoot).Data()})
	}
	if err := telemetry.attachHost(runtime, filesystems); err != nil {
		return fmt.Errorf("attach host observability: %w", err)
	}
	telemetry.markStarted()
	fmt.Fprintf(output, "host %s ready in cell %s\n", cfg.Host.Node, cfg.NATS.Cell)
	// The host connected to its regional cell. It sends no watchdog
	// keepalives: a restart of this process stops every supervised member,
	// so it must never follow from a transient controller outage.
	if err := notifier.Ready("host " + cfg.Host.Node + " connected to cell " + cfg.NATS.Cell); err != nil {
		slog.WarnContext(ctx, "systemd readiness notification failed", "error", err)
	}
	defer func() { _ = notifier.Stopping() }()
	if err := hostRunResult(ctx, agent.Run(ctx)); err != nil {
		return err
	}
	if cause := context.Cause(ctx); errors.Is(cause, errHostMemoryRestart) {
		return cause
	}
	return nil
}

// errHostMemoryRestart ends the host runtime unsuccessfully so systemd starts
// it again under its own release's prepare.
var errHostMemoryRestart = errors.New("this release is known-good: restarting so its prepare mounts the runtime secrets in memory")

// hostMemoryRuntime reports whether a managed host keeps its role files and
// TerraBase member key in memory, which its selfupdate prepare mounts
// (TS-745). It always does, except on the first start of a release that is
// not yet known-good while those directories are still on disk: that start's
// prepare ran the older known-good release, which predates the mounts, and
// the version proof needs the workloads. The existing on-disk layout serves
// that start; release names the running release, and the agent restarts once
// it is known-good, so its own prepare mounts them. Only a missing
// selfupdate.MemoryPrepareMarker shows that older prepare ran: a mount that
// a newer prepare could not make still fails closed.
func hostMemoryRuntime(cfg Config) (bool, selfupdate.Layout, string) {
	layout := selfupdate.NewLayout(selfUpdateRoot(cfg.Host.SelfUpdateRoot))
	if cfg.Host.ManagedRuntimeRoot == "" {
		return false, layout, ""
	}
	dirs := []string{filepath.Join(cfg.Host.ManagedRuntimeRoot, "roles")}
	if cfg.Host.TerraBaseRoot != "" {
		dirs = append(dirs, filepath.Join(cfg.Host.TerraBaseRoot, "tls"))
	}
	onDisk := false
	for _, dir := range dirs {
		if vaultsecret.RequireMemoryFilesystem(dir) != nil {
			onDisk = true
		}
	}
	if _, err := os.Lstat(memoryPrepareMarker); !errors.Is(err, os.ErrNotExist) {
		return true, layout, ""
	}
	current, currentErr := layout.Current()
	knownGood, knownGoodErr := layout.KnownGood()
	if !onDisk || currentErr != nil || knownGoodErr != nil || current == "" || knownGood == "" || knownGood == current {
		return true, layout, ""
	}
	slog.Warn("the prepare before this start predates in-memory runtime secrets; the on-disk layout serves until this release is known-good",
		"release", current, "known_good", knownGood)
	return false, layout, current
}

// memoryPrepareMarker is selfupdate.MemoryPrepareMarker; tests replace it.
var memoryPrepareMarker = selfupdate.MemoryPrepareMarker

// restartWhenKnownGood ends the host runtime once release is known-good, so
// systemd starts it again under release's prepare.
func restartWhenKnownGood(ctx context.Context, layout selfupdate.Layout, release string, restart context.CancelCauseFunc) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if knownGood, err := layout.KnownGood(); err == nil && knownGood == release {
			restart(errHostMemoryRestart)
			return
		}
	}
}

func runHostVolumeInit(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("host-volume-init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "host role configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("host-volume-init accepts no positional arguments")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	key, err := decodePublicKey(cfg.Host.ControllerPublicKey)
	if err != nil {
		return err
	}
	var terraBaseData string
	if cfg.Host.TerraBaseDataVolume {
		if cfg.Host.TerraBaseRoot == "" {
			return errors.New("host.terrabase_data_volume needs host.terrabase_root")
		}
		terraBaseData = terrabase.Layout(cfg.Host.TerraBaseRoot).Data()
	}
	return host.RunVolumeInitializer(ctx, host.VolumeInitConfig{
		Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Environment: cfg.Host.Environment,
		ControllerPublicKey: key, ManagedRuntimeRoot: cfg.Host.ManagedRuntimeRoot,
		StateRoot:             "/var/lib/terrascale-orchestrator-volume-init",
		WorkloadIdentity:      host.WorkloadIdentity{UID: cfg.Host.WorkloadUID, GID: cfg.Host.WorkloadGID},
		TerraBaseDataDir:      terraBaseData,
		TerraBaseDataVolumeID: cfg.Host.TerraBaseDataVolumeID,
		ReadMetadata: func(ctx context.Context) (host.VolumeInitMetadata, error) {
			metadata, err := hostenroll.ReadInstanceMetadata(ctx, hostenroll.NewIMDSClient())
			if err != nil {
				return host.VolumeInitMetadata{}, err
			}
			return host.VolumeInitMetadata{InstanceID: metadata.InstanceID, Descriptor: metadata.Descriptor}, nil
		},
	})
}

// A canceled parent is a normal shutdown. An agent that cancels its own work
// while the parent is live must fail the process so its supervisor restarts it.
func hostRunResult(ctx context.Context, err error) error {
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func check(ctx context.Context, cfg Config, output io.Writer) error {
	connection, err := externalNATS(cfg.NATS)
	if err != nil {
		return err
	}
	runtime, err := natscell.Start(ctx, connection)
	if err != nil {
		return err
	}
	defer runtime.Close()
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runtime.WaitForCluster(probeCtx, cfg.NATS.Replicas); err != nil {
		return err
	}
	fmt.Fprintf(output, "regional NATS and JetStream ready: %s\n", cfg.NATS.Cell)
	return nil
}

func externalNATS(cfg natscell.Config) (natscell.Config, error) {
	if cfg.Embedded == nil {
		return cfg, nil
	}
	embedded := cfg.Embedded
	if embedded.Port < 1 {
		return cfg, errors.New("client command requires a fixed embedded NATS port")
	}
	hostname := embedded.Host
	if hostname == "0.0.0.0" || hostname == "::" {
		hostname = "127.0.0.1"
	}
	scheme := "nats"
	if embedded.TLS.CAFile != "" {
		scheme = "tls"
	}
	cfg.URL = scheme + "://" + net.JoinHostPort(hostname, fmt.Sprint(embedded.Port))
	cfg.Embedded = nil
	return cfg, nil
}

func newIdentity(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("identity-new", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("key", "", "path for new private Ed25519 identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("usage: identity-new --key PRIVATE_KEY_FILE")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private key: %w", err)
	}
	defer file.Close()
	if _, err := io.WriteString(file, base64.StdEncoding.EncodeToString(private)+"\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	fmt.Fprintln(output, base64.StdEncoding.EncodeToString(public))
	return nil
}

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
