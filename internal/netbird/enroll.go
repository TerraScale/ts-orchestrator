package netbird

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	netbirdBinary   = "/usr/local/bin/netbird"
	netbirdConfig   = "/var/lib/netbird/config.json"
	netbirdSocket   = "/var/run/netbird.sock"
	enrollmentLimit = 2 * time.Minute
	commandLimit    = 40 * time.Second
	// daemonLimit bounds the wait for netbird.service's control socket.
	daemonLimit = 15 * time.Second
	// pendingLimit bounds the wait for a boot-time saved-identity reconnect.
	pendingLimit = 15 * time.Second
	readyLimit   = 45 * time.Second
	// Polls start at enroller.poll and double up to maxPoll.
	maxPoll = time.Second
)

var errDaemonUnreachable = errors.New("cannot query NetBird daemon status")

// serverSettings keep servers off NetBird DNS and routing while serving NetBird
// SSH. Sessions require the operator's IdP identity (JWT) and a manager
// policy; local forwarding reaches loopback-only tools, remote forwarding is
// refused.
var serverSettings = []struct {
	flag string
	key  string
	want bool
}{
	{"--disable-dns", "disableDns", true},
	{"--disable-client-routes", "disableClientRoutes", true},
	{"--disable-server-routes", "disableServerRoutes", true},
	{"--disable-auto-connect", "disableAutoConnect", false},
	{"--allow-server-ssh", "serverSSHAllowed", true},
	{"--enable-ssh-root", "enableSSHRoot", true},
	{"--enable-ssh-sftp", "enableSSHSFTP", true},
	{"--enable-ssh-local-port-forwarding", "enableSSHLocalPortForwarding", true},
	{"--enable-ssh-remote-port-forwarding", "enableSSHRemotePortForwarding", false},
	{"--disable-ssh-auth", "disableSSHAuth", false},
}

func upSettings() []string {
	args := make([]string, 0, len(serverSettings))
	for _, setting := range serverSettings {
		args = append(args, setting.flag+"="+strconv.FormatBool(setting.want))
	}
	return args
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type keyReader func(context.Context, Config) ([]byte, error)

type enroller struct {
	run         commandRunner
	readKey     keyReader
	hostname    func() (string, error)
	hostsPath   string
	runtimePath string
	// socketPath is the daemon control socket; empty skips the socket probe.
	socketPath string
	poll       time.Duration
	pending    time.Duration
}

// Enroll connects the persistent daemon identity and verifies management and
// signal connectivity. No setup key is read for an already connected server.
func Enroll(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("netbird-enroll must run as root")
	}
	return (enroller{
		run: runCommand, readKey: readOCISetupKey, hostname: os.Hostname,
		hostsPath: "/etc/hosts", runtimePath: "/run/terrascale-netbird", socketPath: netbirdSocket,
		poll: 100 * time.Millisecond, pending: pendingLimit,
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
	current, err := e.awaitDaemon(ctx)
	if err != nil {
		return err
	}
	if current.managerMatches(cfg.ManagementURL) && current.DaemonStatus == "Connecting" {
		// At boot the daemon is already reconnecting its saved identity. A
		// second up cannot speed that up; let it settle before deciding.
		current, _, err = e.observe(ctx, e.pending, nil, func(status daemonStatus) bool {
			return status.DaemonStatus != "Connecting"
		})
		if err != nil {
			return err
		}
	}
	managerMatches := current.managerMatches(cfg.ManagementURL)
	if managerMatches && current.DaemonStatus == "Connected" {
		applied, err := e.settingsApplied(ctx, cfg.ManagementURL)
		if err != nil {
			return err
		}
		if applied && current.ready(cfg.ManagementURL) {
			return nil
		}
		if !applied {
			// NetBird's up command returns early while already connected. Bring
			// the saved identity down once to apply the server settings.
			if _, err := e.command(ctx, "down"); err != nil {
				return errors.New("cannot apply TerraScale NetBird server settings")
			}
		}
	}
	hostname, err := e.hostname()
	if err != nil || hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "\x00\r\n\t ") {
		return errors.New("cannot determine a valid server hostname for NetBird")
	}
	args := append([]string{"up", "--config", netbirdConfig, "--management-url", cfg.ManagementURL,
		"--hostname", hostname, "--no-browser"}, upSettings()...)
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
			return e.waitReady(ctx, cfg.ManagementURL, &current)
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
	if !managerMatches && current.Management.URL != "" && current.engineActive() {
		if _, err := e.command(ctx, "down"); err != nil {
			return errors.New("cannot disconnect NetBird from its previous manager")
		}
	}
	if _, err := e.command(ctx, append(args, "--setup-key-file", path)...); err != nil {
		return errors.New("NetBird setup-key enrollment failed")
	}
	return e.waitReady(ctx, cfg.ManagementURL, nil)
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

// engineActive reports whether the daemon may hold a running or retrying
// client. A fresh daemon (NeedsLogin: v0.79 does not connect a just-created
// configuration) or a stopped one (Idle) has nothing to bring down, so the
// first enrollment skips the extra down.
func (status daemonStatus) engineActive() bool {
	return status.DaemonStatus != "NeedsLogin" && status.DaemonStatus != "Idle"
}

// awaitDaemon returns the first daemon status. netbird.service is Type=simple,
// so this unit can start before the control socket exists; a bounded wait
// replaces a failed start and the unit's restart delay. Only an unreachable
// daemon is retried; an invalid answer fails at once.
func (e enroller) awaitDaemon(ctx context.Context) (daemonStatus, error) {
	waitCtx, cancel := context.WithTimeout(ctx, daemonLimit)
	defer cancel()
	delay := e.poll
	for {
		if e.socketReady() {
			status, err := e.status(waitCtx)
			if !errors.Is(err, errDaemonUnreachable) {
				return status, err
			}
		}
		select {
		case <-waitCtx.Done():
			return daemonStatus{}, errDaemonUnreachable
		case <-time.After(delay):
		}
		delay = min(2*delay, maxPoll/2)
	}
}

func (e enroller) socketReady() bool {
	if e.socketPath == "" {
		return true
	}
	info, err := os.Lstat(e.socketPath)
	return err == nil && info.Mode().Type() == os.ModeSocket
}

func (e enroller) status(ctx context.Context) (daemonStatus, error) {
	wire, err := e.command(ctx, "status", "--json", "--config", netbirdConfig)
	if err != nil {
		return daemonStatus{}, errDaemonUnreachable
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

// waitReady polls until management and signal are connected, then checks the
// effective server settings once. first, when set, is a status observed just
// before the call and saves one daemon query.
func (e enroller) waitReady(ctx context.Context, manager string, first *daemonStatus) error {
	status, done, err := e.observe(ctx, readyLimit, first, func(status daemonStatus) bool {
		return status.ready(manager) || status.needsLogin()
	})
	if err != nil {
		return err
	}
	if !done {
		return errors.New("NetBird management and signal connectivity did not become ready")
	}
	if status.needsLogin() {
		return errors.New("NetBird enrollment still requires authentication")
	}
	applied, err := e.settingsApplied(ctx, manager)
	if err != nil {
		return err
	}
	if !applied {
		return errors.New("NetBird server settings were not applied")
	}
	return nil
}

// observe polls daemon status with exponential backoff from e.poll to maxPoll
// until done holds or limit elapses, and returns the last observation. Each
// poll forks the NetBird CLI once, so the backoff keeps a slow connect cheap
// while a fast one is seen within e.poll.
func (e enroller) observe(ctx context.Context, limit time.Duration, first *daemonStatus, done func(daemonStatus) bool) (daemonStatus, bool, error) {
	deadline := time.Now().Add(limit)
	delay := e.poll
	for {
		var status daemonStatus
		if first != nil {
			status, first = *first, nil
		} else {
			var err error
			if status, err = e.status(ctx); err != nil {
				return daemonStatus{}, false, err
			}
		}
		if done(status) {
			return status, true, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return status, false, nil
		}
		select {
		case <-ctx.Done():
			return status, false, nil
		case <-time.After(min(delay, remaining)):
		}
		delay = min(2*delay, maxPoll)
	}
}

// settingsApplied reports whether the daemon's effective configuration
// matches the same serverSettings used to construct the enrollment flags.
func (e enroller) settingsApplied(ctx context.Context, manager string) (bool, error) {
	wire, err := e.command(ctx, "debug", "config")
	if err != nil {
		return false, errors.New("cannot query effective NetBird configuration")
	}
	defer clear(wire)
	var cfg map[string]jsontext.Value
	if len(wire) > 1<<20 || json.Unmarshal(wire, &cfg) != nil {
		return false, errors.New("NetBird daemon returned invalid effective configuration")
	}
	applied := true
	for _, setting := range serverSettings {
		var value *bool
		if json.Unmarshal(cfg[setting.key], &value) != nil || value == nil {
			return false, errors.New("NetBird daemon returned invalid effective configuration")
		}
		applied = applied && *value == setting.want
	}
	var managementURL string
	if json.Unmarshal(cfg["managementUrl"], &managementURL) != nil {
		return false, errors.New("NetBird daemon returned invalid effective configuration")
	}
	configuredManager, err := normalizeManagerURL(managementURL)
	return applied && err == nil && configuredManager == manager, nil
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
