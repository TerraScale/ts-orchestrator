package netbird

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	netbirdBinary   = "/usr/local/bin/netbird"
	netbirdConfig   = "/var/lib/netbird/config.json"
	enrollmentLimit = 2 * time.Minute
	commandLimit    = 40 * time.Second
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type keyReader func(context.Context, Config) ([]byte, error)

type enroller struct {
	run         commandRunner
	readKey     keyReader
	hostname    func() (string, error)
	hostsPath   string
	runtimePath string
	poll        time.Duration
}

// Enroll connects the persistent daemon identity and verifies management and
// signal connectivity. No setup key is read for an already connected server.
func Enroll(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("netbird-enroll must run as root")
	}
	return (enroller{
		run: runCommand, readKey: readOCISetupKey, hostname: os.Hostname,
		hostsPath: "/etc/hosts", runtimePath: "/run/terrascale-netbird", poll: time.Second,
	}).enroll(ctx, cfg)
}

func (e enroller) enroll(ctx context.Context, cfg Config) (result error) {
	cfg, err := cfg.normalized()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, enrollmentLimit)
	defer cancel()
	lock, err := lockRuntime(e.runtimePath)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := removeSetupKey(e.runtimePath); err != nil {
		return err
	}
	if err := updateHosts(e.hostsPath, cfg.ManagementIP); err != nil {
		return err
	}
	current, err := e.status(ctx)
	if err != nil {
		return err
	}
	managerMatches := current.managerMatches(cfg.ManagementURL)
	if managerMatches && current.DaemonStatus == "Connected" {
		safe, err := e.safeConfiguration(ctx, cfg.ManagementURL)
		if err != nil {
			return err
		}
		if safe && current.ready(cfg.ManagementURL) {
			return nil
		}
		if !safe {
			// NetBird's up command returns early while already connected. Bring
			// the saved identity down once to apply management-only settings.
			if _, err := e.command(ctx, "down"); err != nil {
				return errors.New("cannot apply management-only NetBird configuration")
			}
		}
	}
	hostname, err := e.hostname()
	if err != nil || hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "\x00\r\n\t ") {
		return errors.New("cannot determine a valid server hostname for NetBird")
	}
	args := []string{"up", "--config", netbirdConfig, "--management-url", cfg.ManagementURL,
		"--hostname", hostname, "--disable-dns", "--disable-client-routes", "--disable-server-routes",
		"--disable-auto-connect=false", "--allow-server-ssh=false", "--no-browser"}
	if managerMatches && !current.needsLogin() {
		// Login with the saved WireGuard identity first. A network outage must
		// not consume a new setup key or replace an existing registration.
		_, upErr := e.command(ctx, args...)
		current, err = e.status(ctx)
		if err != nil {
			return err
		}
		if !current.needsLogin() {
			if upErr != nil && !current.Management.Connected {
				return errors.New("NetBird could not reconnect its saved identity")
			}
			return e.waitReady(ctx, cfg.ManagementURL)
		}
	}
	key, err := e.readKey(ctx, cfg)
	if err != nil {
		clear(key)
		return errors.New("cannot retrieve NetBird setup key from OCI Vault")
	}
	defer clear(key)
	if !validSetupKey(key) {
		return errors.New("OCI Vault returned an invalid NetBird setup key")
	}
	path, err := writeSetupKey(e.runtimePath, key)
	if err != nil {
		return err
	}
	clear(key)
	defer func() {
		if err := removeSetupKey(e.runtimePath); err != nil {
			result = errors.Join(result, err)
		}
	}()
	if !managerMatches && current.Management.URL != "" {
		if _, err := e.command(ctx, "down"); err != nil {
			return errors.New("cannot disconnect NetBird from its previous manager")
		}
	}
	if _, err := e.command(ctx, append(args, "--setup-key-file", path)...); err != nil {
		return errors.New("NetBird setup-key enrollment failed")
	}
	return e.waitReady(ctx, cfg.ManagementURL)
}

type daemonStatus struct {
	DaemonStatus string `json:"daemonStatus"`
	Management   struct {
		URL       string `json:"url"`
		Connected bool   `json:"connected"`
	} `json:"management"`
	Signal struct {
		Connected bool `json:"connected"`
	} `json:"signal"`
}

func (status daemonStatus) managerMatches(manager string) bool {
	configured, err := normalizeManagerURL(status.Management.URL)
	return err == nil && configured == manager
}

func (status daemonStatus) ready(manager string) bool {
	return status.DaemonStatus == "Connected" && status.managerMatches(manager) && status.Management.Connected && status.Signal.Connected
}

func (status daemonStatus) needsLogin() bool {
	// NetBird also uses LoginFailed for network/IO errors. Only an explicit
	// authentication state warrants consuming a fresh setup key.
	return status.DaemonStatus == "NeedsLogin" || status.DaemonStatus == "SessionExpired"
}

func (e enroller) status(ctx context.Context) (daemonStatus, error) {
	wire, err := e.command(ctx, "status", "--json", "--config", netbirdConfig)
	if err != nil {
		return daemonStatus{}, errors.New("cannot query NetBird daemon status")
	}
	defer clear(wire)
	var status daemonStatus
	if len(wire) > 1<<20 || json.Unmarshal(wire, &status) != nil {
		return daemonStatus{}, errors.New("NetBird daemon returned invalid status JSON")
	}
	switch status.DaemonStatus {
	case "Idle", "Connecting", "Connected", "NeedsLogin", "LoginFailed", "SessionExpired":
		return status, nil
	default:
		return daemonStatus{}, errors.New("NetBird daemon returned an unknown connection state")
	}
}

func (e enroller) waitReady(ctx context.Context, manager string) error {
	readyCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		status, err := e.status(readyCtx)
		if err != nil {
			return err
		}
		if status.ready(manager) {
			safe, err := e.safeConfiguration(readyCtx, manager)
			if err != nil {
				return err
			}
			if !safe {
				return errors.New("NetBird management-only configuration was not applied")
			}
			return nil
		}
		if status.needsLogin() {
			return errors.New("NetBird enrollment still requires authentication")
		}
		select {
		case <-readyCtx.Done():
			return errors.New("NetBird management and signal connectivity did not become ready")
		case <-time.After(e.poll):
		}
	}
}

func (e enroller) safeConfiguration(ctx context.Context, manager string) (bool, error) {
	wire, err := e.command(ctx, "debug", "config")
	if err != nil {
		return false, errors.New("cannot query effective NetBird configuration")
	}
	defer clear(wire)
	var cfg struct {
		ManagementURL       string `json:"managementUrl"`
		DisableDNS          *bool  `json:"disableDns"`
		DisableClientRoutes *bool  `json:"disableClientRoutes"`
		DisableServerRoutes *bool  `json:"disableServerRoutes"`
		DisableAutoConnect  *bool  `json:"disableAutoConnect"`
		ServerSSHAllowed    *bool  `json:"serverSSHAllowed"`
	}
	if len(wire) > 1<<20 || json.Unmarshal(wire, &cfg) != nil || cfg.DisableDNS == nil || cfg.DisableClientRoutes == nil ||
		cfg.DisableServerRoutes == nil || cfg.DisableAutoConnect == nil || cfg.ServerSSHAllowed == nil {
		return false, errors.New("NetBird daemon returned invalid effective configuration")
	}
	configuredManager, err := normalizeManagerURL(cfg.ManagementURL)
	return err == nil && configuredManager == manager && *cfg.DisableDNS && *cfg.DisableClientRoutes &&
		*cfg.DisableServerRoutes && !*cfg.DisableAutoConnect && !*cfg.ServerSSHAllowed, nil
}

func (e enroller) command(ctx context.Context, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandLimit)
	defer cancel()
	wire, err := e.run(commandCtx, netbirdBinary, append(args,
		"--daemon-addr", "unix:///var/run/netbird.sock", "--log-file", "console", "--log-level", "error")...)
	if args[0] != "status" && !(args[0] == "debug" && args[1] == "config") || err != nil {
		clear(wire)
		return nil, err
	}
	return wire, nil
}
