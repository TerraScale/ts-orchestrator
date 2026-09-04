// Command ts-node is the D-69 host agent: the only thing that touches a
// host. It runs as root under the system unit cloud-init installs
// (provider.TSNodeCloudInit: sha256-verified binary behind the
// /opt/terrascale/ts-node/current symlink, exactly one unit, no arguments),
// reads its own configuration from one JSON file, watches the local
// manifest for desired components, serves the terrascale.node.v1.* subjects
// of the hostagent package over the control NATS, and publishes host-fact
// heartbeats until SIGINT or SIGTERM.
//
// Root is required: writing systemd SYSTEM units, creating system accounts,
// and driving systemctl is the whole job. Every component it launches runs
// unprivileged under a hardened unit; no container runtime exists anywhere.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// The defaults of ts-node; every one is overridable in the config file and
// none is read from the environment.
const (
	tsNodeDefaultConfigPath     = "/etc/terrascale/ts-node.json"
	tsNodeDefaultManifestPath   = "/etc/terrascale/manifest.json"
	tsNodeDefaultInstallRoot    = "/opt/terrascale"
	tsNodeDefaultUnitDir        = "/etc/systemd/system"
	tsNodeDefaultDataVolumeRoot = "/var/lib/terrascale"
	tsNodeDefaultChronycBinary  = "/usr/bin/chronyc"
	tsNodeDefaultSystemctl      = "/usr/bin/systemctl"
	tsNodeDefaultUseradd        = "/usr/sbin/useradd"
	tsNodeDefaultHeartbeat      = 10 * time.Second
	tsNodeDefaultReconcile      = 30 * time.Second
	tsNodeCommandTimeout        = 2 * time.Minute
)

// tsNodeConfigurationFile is the camelCase JSON shape of the agent's own
// configuration.
type tsNodeConfigurationFile struct {
	NodeId              string `json:"nodeId"`
	NatsURL             string `json:"natsUrl"`
	NatsNkeyFile        string `json:"natsNkeyFile"`
	NatsTlsCaFile       string `json:"natsTlsCaFile"`
	NatsTlsCertFile     string `json:"natsTlsCertFile"`
	NatsTlsKeyFile      string `json:"natsTlsKeyFile"`
	ReleasePublicKey    string `json:"releasePublicKey"`
	ManifestPath        string `json:"manifestPath"`
	InstallRoot         string `json:"installRoot"`
	UnitDir             string `json:"unitDir"`
	DataVolumeRoot      string `json:"dataVolumeRoot"`
	ChronycBinary       string `json:"chronycBinary"`
	SystemctlBinary     string `json:"systemctlBinary"`
	UseraddBinary       string `json:"useraddBinary"`
	HeartbeatIntervalMs int64  `json:"heartbeatIntervalMilliseconds"`
	ReconcileIntervalMs int64  `json:"reconcileIntervalMilliseconds"`
}

// tsNodeConfiguration is the validated runtime configuration.
type tsNodeConfiguration struct {
	NodeId            string
	NatsURL           string
	natsOptions       []nats.Option
	ReleasePublicKey  string
	ManifestPath      string
	InstallRoot       string
	UnitDir           string
	DataVolumeRoot    string
	ChronycBinary     string
	SystemctlBinary   string
	UseraddBinary     string
	HeartbeatInterval time.Duration
	ReconcileInterval time.Duration
}

// parseTsNodeArguments accepts at most one --flag value pair: the config
// path. The cloud-init unit passes no arguments at all.
func parseTsNodeArguments(args []string) (string, error) {
	if len(args) == 0 {
		return tsNodeDefaultConfigPath, nil
	}
	if len(args) != 2 || args[0] != "--config" || args[1] == "" ||
		strings.ContainsAny(args[1], " \t\r\n") {
		return "", errors.New(
			"ts-node: the only supported arguments are --config <path> or none")
	}
	return args[1], nil
}

// loadTsNodeConfiguration reads and validates one configuration file.
func loadTsNodeConfiguration(path string) (tsNodeConfiguration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tsNodeConfiguration{}, fmt.Errorf("ts-node: the configuration %s cannot be read: %s", path, err.Error())
	}
	var file tsNodeConfigurationFile
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: the configuration %s is not the canonical JSON shape: %s", path, err.Error())
	}
	if _, err := hostagent.NewNodeId(file.NodeId); err != nil {
		return tsNodeConfiguration{}, errors.New("ts-node: nodeId must be a lowercase DNS-style token")
	}
	if file.NatsURL == "" {
		return tsNodeConfiguration{}, errors.New("ts-node: natsUrl is required")
	}
	var options []nats.Option
	credentials := []string{file.NatsNkeyFile, file.NatsTlsCaFile, file.NatsTlsCertFile, file.NatsTlsKeyFile}
	supplied := 0
	for _, value := range credentials {
		if value != "" {
			supplied++
		}
	}
	switch {
	case strings.HasPrefix(file.NatsURL, "tls://"):
		if supplied != len(credentials) {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: tls:// NATS requires the NKey, CA, certificate, and key files")
		}
		authentication, err := control.NatsAuthenticationFilesFromNKeyFile(file.NatsNkeyFile)
		if err != nil {
			return tsNodeConfiguration{}, fmt.Errorf("ts-node: NATS authentication is invalid: %s", err.Error())
		}
		tlsFiles, err := control.NatsTlsFilesResolve(
			file.NatsTlsCaFile, file.NatsTlsCertFile, file.NatsTlsKeyFile, "ts-node NATS")
		if err != nil || tlsFiles == nil {
			if err == nil {
				err = errors.New("the TLS identity is missing")
			}
			return tsNodeConfiguration{}, fmt.Errorf("ts-node: NATS TLS is invalid: %s", err.Error())
		}
		options = append(options, authentication.Options()...)
		options = append(options, tlsFiles.Options()...)
	case strings.HasPrefix(file.NatsURL, "nats://"):
		if supplied != 0 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: NATS credential files require a tls:// NATS URL")
		}
	default:
		return tsNodeConfiguration{}, errors.New(
			"ts-node: natsUrl must use nats:// for local use or tls:// for production")
	}
	configuration := tsNodeConfiguration{
		NodeId:            file.NodeId,
		NatsURL:           file.NatsURL,
		natsOptions:       options,
		ReleasePublicKey:  file.ReleasePublicKey,
		ManifestPath:      nonEmptyDefault(file.ManifestPath, tsNodeDefaultManifestPath),
		InstallRoot:       nonEmptyDefault(file.InstallRoot, tsNodeDefaultInstallRoot),
		UnitDir:           nonEmptyDefault(file.UnitDir, tsNodeDefaultUnitDir),
		DataVolumeRoot:    nonEmptyDefault(file.DataVolumeRoot, tsNodeDefaultDataVolumeRoot),
		ChronycBinary:     nonEmptyDefault(file.ChronycBinary, tsNodeDefaultChronycBinary),
		SystemctlBinary:   nonEmptyDefault(file.SystemctlBinary, tsNodeDefaultSystemctl),
		UseraddBinary:     nonEmptyDefault(file.UseraddBinary, tsNodeDefaultUseradd),
		HeartbeatInterval: positiveDefault(file.HeartbeatIntervalMs, tsNodeDefaultHeartbeat),
		ReconcileInterval: positiveDefault(file.ReconcileIntervalMs, tsNodeDefaultReconcile),
	}
	if !isAbsolute(configuration.ManifestPath) || !isAbsolute(configuration.InstallRoot) ||
		!isAbsolute(configuration.UnitDir) || !isAbsolute(configuration.DataVolumeRoot) ||
		!isAbsolute(configuration.ChronycBinary) || !isAbsolute(configuration.SystemctlBinary) ||
		!isAbsolute(configuration.UseraddBinary) {
		return tsNodeConfiguration{}, errors.New("ts-node: every configured path must be absolute")
	}
	if configuration.ReleasePublicKey == "" {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: releasePublicKey is required — the release-signing key is pinned, never fetched")
	}
	return configuration, nil
}

func nonEmptyDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func positiveDefault(milliseconds int64, fallback time.Duration) time.Duration {
	if milliseconds > 0 {
		return time.Duration(milliseconds) * time.Millisecond
	}
	return fallback
}

func isAbsolute(path string) bool { return strings.HasPrefix(path, "/") }

// composeTsNodeAgent composes the host agent from one validated
// configuration.
func composeTsNodeAgent(configuration tsNodeConfiguration) (*hostagent.HostAgent, error) {
	installer, err := hostagent.NewInstaller(hostagent.InstallerConfig{
		InstallRoot:  configuration.InstallRoot,
		PublicKeyHex: configuration.ReleasePublicKey,
		Downloader:   hostagent.InstallClient(),
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the installer is invalid: %s", err.Error())
	}
	systemd, err := hostagent.NewSystemctlController(configuration.SystemctlBinary, tsNodeCommandTimeout)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the systemd controller is invalid: %s", err.Error())
	}
	lifecycle, err := hostagent.NewLifecycle(hostagent.LifecycleConfig{
		InstallRoot: configuration.InstallRoot,
		UnitDir:     configuration.UnitDir,
		Installer:   installer,
		Systemd:     systemd,
		Users: hostagent.UseraddProvisioner{
			UseraddBinary: configuration.UseraddBinary,
			Timeout:       tsNodeCommandTimeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the lifecycle is invalid: %s", err.Error())
	}
	facts, err := hostagent.NewHostFactsSource(hostagent.HostFactsSourceConfig{
		Clock: hostagent.ChronyTrackingSource{
			ChronycBinary: configuration.ChronycBinary,
			Timeout:       tsNodeCommandTimeout,
		},
		Statfs:         hostagent.OsStatfs,
		DataVolumeRoot: configuration.DataVolumeRoot,
		Systemd:        systemd,
		InstallRoot:    configuration.InstallRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the facts source is invalid: %s", err.Error())
	}
	nodeId, err := hostagent.NewNodeId(configuration.NodeId)
	if err != nil {
		return nil, fmt.Errorf("ts-node: --node-id is invalid: %s", err.Error())
	}
	return hostagent.NewHostAgent(hostagent.HostAgentConfig{
		NodeId:            nodeId,
		NatsURL:           configuration.NatsURL,
		NatsOptions:       configuration.natsOptions,
		ConnectTimeout:    5 * time.Second,
		Lifecycle:         lifecycle,
		Facts:             facts,
		ManifestPath:      configuration.ManifestPath,
		ReconcileInterval: configuration.ReconcileInterval,
		HeartbeatInterval: configuration.HeartbeatInterval,
		Now:               time.Now,
	})
}

// runTsNode starts the composed agent and blocks until the start context is
// cancelled or the agent completes on its own, then drains it.
func runTsNode(ctx context.Context, agent *hostagent.HostAgent) error {
	if err := agent.Start(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		_ = agent.Close()
		return ctx.Err()
	case <-agent.Completion():
	}
	return agent.Close()
}

// exitCode: SIGINT-driven cancellation exits 130, a deadline 124, every
// other failure 1.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 124
	}
	return 1
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(os.Stderr,
			"ts-node must run as root under its cloud-init system unit: writing systemd units and accounts is its D-69 job")
		os.Exit(2)
	}
	configPath, err := parseTsNodeArguments(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	configuration, err := loadTsNodeConfiguration(configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	agent, err := composeTsNodeAgent(configuration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := runTsNode(ctx, agent); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}
