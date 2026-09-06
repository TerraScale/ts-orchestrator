// Command ts-node is the D-69 host agent: the only thing that touches a
// host. It runs as root under the shared tsnodebootstrap system unit
// (a verified binary behind the
// /opt/terrascale/ts-node/current symlink, exactly one unit, no arguments),
// reads its own configuration from one JSON file, watches the local
// manifest for desired components, serves the ts.orch.v1 host-agent subjects
// of the hostagent package over the control NATS, and publishes host-fact
// heartbeats until SIGINT or SIGTERM.
//
// Root is required: writing systemd SYSTEM units, creating system accounts,
// and driving systemctl is the whole job. Every component it launches runs
// unprivileged under a hardened unit; no container runtime exists anywhere.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostplatform"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
)

// The defaults of ts-node; every one is overridable in the config file and
// none is read from the environment.
const (
	tsNodeDefaultConfigPath     = "/etc/terrascale/ts-node.json"
	tsNodeDefaultManifestPath   = "/var/lib/terrascale/ts-node/manifest.json"
	tsNodeDefaultInstallRoot    = "/opt/terrascale"
	tsNodeDefaultUnitDir        = "/etc/systemd/system"
	tsNodeDefaultDataVolumeRoot = "/var/lib/terrascale"
	tsNodeDefaultChronycBinary  = "/usr/bin/chronyc"
	tsNodeDefaultSystemctl      = "/usr/bin/systemctl"
	tsNodeDefaultUseradd        = "/usr/sbin/useradd"
	tsNodeDefaultHeartbeat      = 10 * time.Second
	tsNodeDefaultReconcile      = 30 * time.Second
	tsNodeCommandTimeout        = 2 * time.Minute
	tsNodeMaximumConfigBytes    = 64 << 10
)

// tsNodeConfigurationFile is the camelCase JSON shape of the agent's own
// configuration.
type tsNodeCommandTrustFile struct {
	CandidateID   string `json:"candidateId"`
	PublicKeyFile string `json:"publicKeyFile"`
}

type tsNodeConfigurationFile struct {
	EngineObservation      *tbep.FileConfig           `json:"engineObservation,omitempty"`
	AuthorityReader        nodeauthority.ReaderConfig `json:"authorityReader"`
	BootstrapBeforeNATS    bool                       `json:"bootstrapBeforeNats"`
	BootstrapGrantFile     string                     `json:"bootstrapGrantFile"`
	BootstrapPublicKeyFile string                     `json:"bootstrapPublicKeyFile"`
	AuthorityBucket        string                     `json:"authorityBucket"`
	CommandTrustKeys       []tsNodeCommandTrustFile   `json:"commandTrustKeys"`
	NodeId                 string                     `json:"nodeId"`
	NatsURL                string                     `json:"natsUrl"`
	NatsNkeyFile           string                     `json:"natsNkeyFile"`
	NatsTlsCaFile          string                     `json:"natsTlsCaFile"`
	NatsTlsCertFile        string                     `json:"natsTlsCertFile"`
	NatsTlsKeyFile         string                     `json:"natsTlsKeyFile"`
	ReleasePublicKey       string                     `json:"releasePublicKey"`
	ManifestPath           string                     `json:"manifestPath"`
	InstallRoot            string                     `json:"installRoot"`
	UnitDir                string                     `json:"unitDir"`
	DataVolumeRoot         string                     `json:"dataVolumeRoot"`
	ChronycBinary          string                     `json:"chronycBinary"`
	SystemctlBinary        string                     `json:"systemctlBinary"`
	UseraddBinary          string                     `json:"useraddBinary"`
	HeartbeatIntervalMs    int64                      `json:"heartbeatIntervalMilliseconds"`
	ReconcileIntervalMs    int64                      `json:"reconcileIntervalMilliseconds"`
}

// tsNodeConfiguration is the validated runtime configuration.
type tsNodeConfiguration struct {
	EngineObservation      *tbep.FileConfig
	AuthorityReader        nodeauthority.ReaderConfig
	BootstrapBeforeNATS    bool
	BootstrapGrantFile     string
	BootstrapPublicKeyFile string
	AuthorityBucket        string
	CommandTrustKeys       []tsNodeCommandTrustFile
	NodeId                 string
	NatsURL                string
	natsOptions            []nats.Option
	ReleasePublicKey       string
	ManifestPath           string
	InstallRoot            string
	UnitDir                string
	DataVolumeRoot         string
	ChronycBinary          string
	SystemctlBinary        string
	UseraddBinary          string
	HeartbeatInterval      time.Duration
	ReconcileInterval      time.Duration
}

// parseTsNodeArguments accepts at most one --flag value pair: the config
// path. The cloud-init unit passes no arguments at all.
func parseTsNodeArguments(args []string) (string, error) {
	if len(args) == 0 {
		return tsNodeDefaultConfigPath, nil
	}
	if len(args) != 2 || args[0] != "--config" || args[1] == "" ||
		strings.ContainsAny(args[1], " \t\r\n") || !isAbsolute(args[1]) {
		return "", errors.New(
			"ts-node: the only supported arguments are --config <path> or none")
	}
	return args[1], nil
}

// loadTsNodeConfiguration reads and validates one configuration file.
func loadTsNodeConfiguration(path string) (tsNodeConfiguration, error) {
	data, err := readTsNodeConfigurationFile(path)
	if err != nil {
		return tsNodeConfiguration{}, fmt.Errorf("ts-node: the configuration %s cannot be read: %s", path, err.Error())
	}
	if err := validateTsNodeConfigurationJSON(data); err != nil {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: the configuration %s is not the canonical JSON shape: %s", path, err.Error())
	}
	var file tsNodeConfigurationFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: the configuration %s is not the canonical JSON shape: %s", path, err.Error())
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: the configuration %s must be exactly one JSON document", path)
	}
	if _, err := hostagent.NewNodeId(file.NodeId); err != nil {
		return tsNodeConfiguration{}, errors.New("ts-node: nodeId must be a lowercase DNS-style token")
	}
	if file.NatsURL == "" {
		return tsNodeConfiguration{}, errors.New("ts-node: natsUrl is required")
	}
	if file.HeartbeatIntervalMs < 0 || file.ReconcileIntervalMs < 0 ||
		file.HeartbeatIntervalMs > int64((1<<63-1)/int64(time.Millisecond)) ||
		file.ReconcileIntervalMs > int64((1<<63-1)/int64(time.Millisecond)) {
		return tsNodeConfiguration{}, errors.New("ts-node: configured intervals must be non-negative bounded milliseconds")
	}
	if file.AuthorityBucket == "" || len(file.CommandTrustKeys) == 0 || len(file.CommandTrustKeys) > 4 {
		return tsNodeConfiguration{}, errors.New("ts-node: authorityBucket and candidate-bound commandTrustKeys are required")
	}
	for _, key := range file.CommandTrustKeys {
		if key.CandidateID == "" || !isAbsolute(key.PublicKeyFile) {
			return tsNodeConfiguration{}, errors.New("ts-node: each command trust key requires candidateId and an absolute publicKeyFile")
		}
	}
	if file.BootstrapBeforeNATS && file.BootstrapGrantFile == "" {
		return tsNodeConfiguration{}, errors.New("ts-node: bootstrapBeforeNats requires a signed bootstrap grant")
	}
	if (file.BootstrapGrantFile == "") != (file.BootstrapPublicKeyFile == "") || file.BootstrapGrantFile != "" && (!isAbsolute(file.BootstrapGrantFile) || !isAbsolute(file.BootstrapPublicKeyFile)) {
		return tsNodeConfiguration{}, errors.New("ts-node: bootstrapGrantFile and bootstrapPublicKeyFile must be absolute paths supplied together")
	}
	if err := file.AuthorityReader.Validate(); err != nil {
		return tsNodeConfiguration{}, err
	}
	if file.AuthorityReader.NKeySeedFile == file.NatsNkeyFile || file.AuthorityReader.KeyFile == file.NatsTlsKeyFile {
		return tsNodeConfiguration{}, errors.New("ts-node: authority reader credentials must be separate from transport")
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
		if err := validateTsNodeReaderIdentity(file.AuthorityReader, authentication.PublicKey, tlsFiles.CertificateFile); err != nil {
			return tsNodeConfiguration{}, err
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
	options = append(options, nats.ReconnectBufSize(-1))
	configuration := tsNodeConfiguration{EngineObservation: file.EngineObservation, AuthorityReader: file.AuthorityReader,
		BootstrapBeforeNATS: file.BootstrapBeforeNATS,
		BootstrapGrantFile:  file.BootstrapGrantFile, BootstrapPublicKeyFile: file.BootstrapPublicKeyFile,
		AuthorityBucket: file.AuthorityBucket, CommandTrustKeys: file.CommandTrustKeys,
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
	production := tsnodebootstrap.ProductionConfig()
	if configuration.InstallRoot != production.InstallRoot {
		return tsNodeConfiguration{}, errors.New("ts-node: installRoot must match the production bootstrap writable root")
	}
	if configuration.UnitDir != production.UnitDirectory {
		return tsNodeConfiguration{}, errors.New("ts-node: unitDir must match the production bootstrap unit directory")
	}
	dataRelative, err := filepath.Rel(production.DataVolumeRoot, configuration.DataVolumeRoot)
	if err != nil || dataRelative == ".." || strings.HasPrefix(dataRelative, ".."+string(filepath.Separator)) {
		return tsNodeConfiguration{}, errors.New("ts-node: dataVolumeRoot must be within the production bootstrap writable root")
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

func isAbsolute(path string) bool {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, " \t\x00\r\n\\") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return false
		}
	}
	clean := filepath.Clean(path)
	return clean != string(filepath.Separator) && clean == path
}

func readTsNodeConfigurationFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if info.Size() > tsNodeMaximumConfigBytes {
		return nil, errors.New("configuration exceeds its size bound")
	}
	data, err := io.ReadAll(io.LimitReader(file, tsNodeMaximumConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > tsNodeMaximumConfigBytes {
		return nil, errors.New("configuration exceeds its size bound")
	}
	return data, nil
}

func validateTsNodeConfigurationJSON(data []byte) error {
	allowed := map[string]struct{}{
		"engineObservation": {}, "authorityReader": {}, "authorityBucket": {}, "commandTrustKeys": {}, "bootstrapGrantFile": {}, "bootstrapPublicKeyFile": {}, "bootstrapBeforeNats": {},
		"nodeId": {}, "natsUrl": {}, "natsNkeyFile": {}, "natsTlsCaFile": {},
		"natsTlsCertFile": {}, "natsTlsKeyFile": {}, "releasePublicKey": {},
		"manifestPath": {}, "installRoot": {}, "unitDir": {}, "dataVolumeRoot": {},
		"chronycBinary": {}, "systemctlBinary": {}, "useraddBinary": {},
		"heartbeatIntervalMilliseconds": {}, "reconcileIntervalMilliseconds": {},
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("configuration must be an object: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("configuration must be a non-null object")
	}
	seen := make(map[string]bool, len(allowed))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("configuration field name: %w", err)
		}
		name, ok := nameToken.(string)
		if !ok {
			return errors.New("configuration field name is invalid")
		}
		if _, known := allowed[name]; !known {
			return fmt.Errorf("configuration contains unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("configuration contains duplicate field %q", name)
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("configuration.%s: %w", name, err)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("configuration.%s must not be null", name)
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("configuration object is incomplete: %w", err)
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return errors.New("configuration object is incomplete")
	}
	for _, required := range []string{"nodeId", "natsUrl", "releasePublicKey", "authorityReader"} {
		if !seen[required] {
			return fmt.Errorf("configuration is missing field %q", required)
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("configuration contains trailing data")
	}
	return nil
}

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
	systemd, err := hostplatform.NewSystemctlController(configuration.SystemctlBinary, tsNodeCommandTimeout)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the systemd controller is invalid: %s", err.Error())
	}
	lifecycle, err := hostagent.NewLifecycle(hostagent.LifecycleConfig{
		InstallRoot:     configuration.InstallRoot,
		UnitDir:         configuration.UnitDir,
		DataVolumeRoot:  configuration.DataVolumeRoot,
		Installer:       installer,
		Systemd:         systemd,
		SystemctlBinary: configuration.SystemctlBinary,
		Users: hostagent.UseraddProvisioner{
			UseraddBinary: configuration.UseraddBinary,
			Timeout:       tsNodeCommandTimeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the lifecycle is invalid: %s", err.Error())
	}
	var engineSample func(context.Context) (hostagent.EngineFacts, error)
	if configuration.EngineObservation != nil {
		observer, err := configuration.EngineObservation.Open()
		if err != nil {
			return nil, fmt.Errorf("ts-node: engine observation configuration: %w", err)
		}
		if err := observer.Close(); err != nil {
			return nil, err
		}
		engineSample = hostagent.SampleEngine(*configuration.EngineObservation)
	}
	metrics, err := hostagent.NewOSHostMetrics(filepath.Join(configuration.DataVolumeRoot, hostmanifest.TsNodeComponentName, "metrics-sequence"))
	if err != nil {
		return nil, fmt.Errorf("ts-node: host metrics configuration: %w", err)
	}
	facts, err := hostagent.NewHostFactsSource(hostagent.HostFactsSourceConfig{
		Engine:  engineSample,
		Metrics: metrics.Sample,
		Clock: hostplatform.ChronyTrackingSource{
			ChronycBinary: configuration.ChronycBinary,
			Timeout:       tsNodeCommandTimeout,
		},
		Statfs:         hostagent.OsStatfs,
		DataVolumeRoot: configuration.DataVolumeRoot,
		Systemd:        systemd,
		InstallRoot:    configuration.InstallRoot,
		Installer:      installer,
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the facts source is invalid: %s", err.Error())
	}
	nodeId, err := hostagent.NewNodeId(configuration.NodeId)
	if err != nil {
		return nil, fmt.Errorf("ts-node: --node-id is invalid: %s", err.Error())
	}
	paths := make([]string, 0, len(configuration.CommandTrustKeys))
	candidates := map[string]string{}
	for _, key := range configuration.CommandTrustKeys {
		paths = append(paths, key.PublicKeyFile)
		data, err := os.ReadFile(key.PublicKeyFile)
		if err != nil || len(data) > 32*1024 {
			return nil, errors.New("ts-node: command trust key cannot be read")
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, errors.New("ts-node: command trust key must be public SPKI PEM")
		}
		sum := sha256.Sum256(block.Bytes)
		keyID := hex.EncodeToString(sum[:])
		if _, exists := candidates[keyID]; exists {
			return nil, errors.New("ts-node: duplicate command trust key")
		}
		candidates[keyID] = key.CandidateID
	}
	trust, err := security.LoadCommandSignatureVerifierPEM(paths)
	if err != nil {
		return nil, errors.New("ts-node: command trust configuration is invalid")
	}
	var bootstrapPublic, bootstrapGrant []byte
	if configuration.BootstrapGrantFile != "" {
		bootstrapPublic, err = readBootstrapConfigFile(configuration.BootstrapPublicKeyFile, 32<<10)
		if err != nil {
			return nil, err
		}
		bootstrapGrant, err = readBootstrapConfigFile(configuration.BootstrapGrantFile, 2<<20)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(bootstrapPublic)
		if block == nil {
			return nil, errors.New("ts-node: invalid bootstrap public key")
		}
		fingerprint := sha256.Sum256(block.Bytes)
		if _, shared := candidates[hex.EncodeToString(fingerprint[:])]; shared {
			return nil, errors.New("ts-node: bootstrap key must be independent from regional command keys")
		}
		if _, err = hostagent.VerifyBootstrapGrant(configuration.NodeId, bootstrapPublic, bootstrapGrant); err != nil {
			return nil, err
		}
		proof, err := initialgrant.VerifyProof(configuration.NodeId, bootstrapPublic, bootstrapGrant)
		if err != nil {
			return nil, err
		}
		if proof != nil && proof.Config().AuthorityReader != configuration.AuthorityReader {
			return nil, errors.New("ts-node: authority reader differs from owner-granted scope")
		}
	}
	return hostagent.NewHostAgent(hostagent.HostAgentConfig{
		RequireManifestAdmission: true,
		CommandAuthorityFactory: func(connection hostagent.NatsConnection) (nodeauthority.CommandAuthorizer, error) {
			regional, err := nodeauthority.NewLazyRegionalCommandAuthorizer(configuration.AuthorityReader, configuration.NodeId, configuration.AuthorityBucket, trust, candidates)
			if err != nil {
				return nil, err
			}
			if len(bootstrapGrant) > 0 {
				wrapped, err := hostagent.NewBootstrapAuthority(regional, configuration.NodeId, bootstrapPublic, bootstrapGrant)
				if err != nil {
					regional.Close()
					return nil, err
				}
				return wrapped, nil
			}
			return regional, nil
		},
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
			"ts-node must run as root under its bootstrap system unit: writing systemd units and accounts is its D-69 job")
		os.Exit(2)
	}
	configPath, err := parseTsNodeArguments(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := provisionTsNodeSecrets(ctx, configPath); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
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
	if err := activateTsNodeBeforeNATS(ctx, configuration, agent.Lifecycle()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
	if err := runTsNode(ctx, agent); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

// Compare public identities, not paths or certificate encodings. A renewed
// certificate can carry the same private key under different PEM bytes.
func validateTsNodeReaderIdentity(reader nodeauthority.ReaderConfig, transportNKey, transportCertificate string) error {
	invalid := errors.New("ts-node: authority reader key identities must be separate from transport")
	seed, err := initialgrant.ReadMaterialFile(reader.NKeySeedFile, 4096, true)
	if err != nil {
		return invalid
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	if err != nil {
		return invalid
	}
	defer pair.Wipe()
	publicNKey, err := pair.PublicKey()
	if err != nil || publicNKey != reader.PublicNKey {
		return invalid
	}
	if publicNKey == transportNKey {
		return invalid
	}
	var public [][]byte
	for index, entry := range []struct{ path, digest string }{{reader.CertificateFile, reader.CertificateSHA256}, {transportCertificate, ""}} {
		data, err := initialgrant.ReadMaterialFile(entry.path, 64<<10, false)
		if err != nil {
			return invalid
		}
		if entry.digest != "" {
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != entry.digest {
				return invalid
			}
		}
		if index == 0 {
			key, err := initialgrant.ReadMaterialFile(reader.KeyFile, 64<<10, true)
			if err != nil {
				return invalid
			}
			_, err = tls.X509KeyPair(data, key)
			clear(key)
			if err != nil {
				return invalid
			}
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return invalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return invalid
		}
		public = append(public, cert.RawSubjectPublicKeyInfo)
	}
	if bytes.Equal(public[0], public[1]) {
		return invalid
	}
	return nil
}
