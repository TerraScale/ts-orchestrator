// Package app composes the controller, host, and regional operator runtime.
package app

import (
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
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/sdnotify"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
)

func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: terrascale-orchestrator <bootstrap-controller|run|host|check|operator|identity-new|netbird-enroll> --config FILE")
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
	if command == "identity-new" {
		return newIdentity(args[1:], output)
	}
	if command == "netbird-enroll" {
		return runNetBirdEnroll(ctx, args[1:], output)
	}
	if command == "install-controller-config" {
		return runInstallControllerConfig(ctx, args[1:])
	}
	if command == "host-setup" {
		return runHostSetup(ctx, args[1:], output)
	}
	if command == "host-volume-init" {
		return runHostVolumeInit(ctx, args[1:])
	}
	if command == "operator" {
		return runOperator(ctx, args[1:], output)
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
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

var hostClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

// validateLoadTelemetrySeconds checks the integer before it becomes a
// duration, so an enormous value cannot overflow past the agent's bounds
// (for example wrap to zero and silently disable telemetry).
func validateLoadTelemetrySeconds(seconds int) error {
	if seconds != 0 && (seconds < 5 || seconds > 3600) {
		return fmt.Errorf("host load_telemetry_seconds %d must be 0 (off) or within 5..3600", seconds)
	}
	return nil
}

func runHost(ctx context.Context, cfg Config, configPath string, output io.Writer) error {
	notifier := sdnotify.FromEnvironment()
	if cfg.NATS.Embedded != nil {
		return errors.New("host role cannot start the regional NATS server")
	}
	if err := validateLoadTelemetrySeconds(cfg.Host.LoadTelemetrySeconds); err != nil {
		return err
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
		ManagedS3Credentials:    managedS3Credentials,
		ManagedBackupDataKeys:   managedBackupDataKeys,
		BakedSystemReserveBytes: bakedSystemReserveBytes,
		WorkloadIdentity:        identity,
		PollInterval:            time.Duration(cfg.Host.PollMillis) * time.Millisecond, SessionTrace: cfg.Host.SessionTrace,
		ClockCheck:       clockCheck,
		LoadInterval:     time.Duration(cfg.Host.LoadTelemetrySeconds) * time.Second,
		VolumeInitSocket: "/run/terrascale-orchestrator-volume-init.sock",
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
	if err := telemetry.attachHost(runtime, filesystems); err != nil {
		return fmt.Errorf("attach host observability: %w", err)
	}
	telemetry.markStarted()
	fmt.Fprintf(output, "host %s ready in cell %s\n", cfg.Host.Node, cfg.NATS.Cell)
	// The host connected to its regional cell. It sends no watchdog
	// keepalives: a restart of this process stops every supervised member,
	// so it must never follow from a transient controller outage.
	if err := notifier.Ready("host " + cfg.Host.Node + " connected to cell " + cfg.NATS.Cell); err != nil {
		slog.Warn("systemd readiness notification failed", "error", err)
	}
	defer func() { _ = notifier.Stopping() }()
	return hostRunResult(ctx, agent.Run(ctx))
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
	return host.RunVolumeInitializer(ctx, host.VolumeInitConfig{
		Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Environment: cfg.Host.Environment,
		ControllerPublicKey: key, ManagedRuntimeRoot: cfg.Host.ManagedRuntimeRoot,
		StateRoot:        "/var/lib/terrascale-orchestrator-volume-init",
		WorkloadIdentity: host.WorkloadIdentity{UID: cfg.Host.WorkloadUID, GID: cfg.Host.WorkloadGID},
		Grow:             hostvolume.GrowConfig{Enabled: cfg.Host.ManagedVolumeOnlineGrow},
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

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("expected a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}
