package manager

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const serverUsage = `Usage: ts-orch netbird server --dir DIR

On every M1 host, as root, with the instance principal, keep the pinned NetBird
client installed, running and enrolled with the servers' setup key, read from
the Vault of the host's fleet document entry (production: gru-vault's
gru-1-netbird-setup-key). On the host
whose node declares the netbird-server service, also create the
server's generated secrets in Vault once, write DIR/config.yaml (mode 0600, owned by the
container user) for the netbird-server service, wait for it on ` + ServerURL + `, claim the owner and
keep the admin PAT and setup keys in Vault, then re-sync GRU() every 10 minutes.
`

// runServer is the long-running ts-orch side of the netbird-server service.
func runServer(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("netbird server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "the netbird-server data directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		_, _ = io.WriteString(stdout, serverUsage)
		return errors.New("netbird server: invalid arguments")
	}
	if !filepath.IsAbs(*dir) {
		_, _ = io.WriteString(stdout, serverUsage)
		return errors.New("netbird server requires an absolute --dir")
	}
	if os.Geteuid() != 0 {
		return errors.New("netbird server runs as root: its config holds secrets")
	}
	region, err := mesh.OwnRegion(ctx)
	if err != nil {
		return fmt.Errorf("netbird server: %w", err)
	}
	environment := mesh.EnvironmentOf(region)
	setupKey := environment.Secret("netbird-setup-key")
	factory, err := ociclient.InstancePrincipal(environment.VaultRegion)
	if err != nil {
		return err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return err
	}
	vault := ServerVault{Target: environment.Vault,
		Management: management, Versions: management, Bundles: bundles}
	logf := func(format string, args ...any) { fmt.Fprintf(stdout, "netbird server: "+format+"\n", args...) }
	for {
		// systemd restarts this companion onto the pushed binary too. The
		// main ts-orch process can update while this long-lived loop sleeps.
		if changed, err := serverBinaryChanged(); err != nil {
			logf("check installed binary: %v", err)
		} else if changed {
			return errors.New("installed ts-orch changed; restarting NetBird reconciler")
		}
		err := serveOnce(ctx, vault, setupKey, *dir)
		if err != nil {
			logf("%v", err)
		}
		wait := 10 * time.Minute
		if err != nil {
			wait = 15 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// serveOnce converges config and manager state on the host that runs the
// netbird-server service, and this host's client everywhere; each step is
// idempotent.
func serveOnce(ctx context.Context, vault ServerVault, setupKey, dir string) error {
	server := false
	if !regionWorker(admissionFile) { // a worker has no control socket and never runs the server
		var err error
		if server, err = runsServer(ctx); err != nil {
			return err
		}
	}
	if server {
		if err := runServerSide(ctx, vault, dir); err != nil {
			return err
		}
	}
	if err := ensureClient(ctx); err != nil {
		return err
	}
	return enrollHost(ctx, vault, setupKey)
}

const admissionFile = "/var/lib/ts-orch/swarm/admission.json"

// regionWorker reports whether this host joined its region's cluster as a
// worker: its stored admission names another host as the founder.
func regionWorker(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var admission struct{ HostID, FounderID string }
	return json.Unmarshal(data, &admission) == nil && admission.HostID != "" && admission.HostID != admission.FounderID
}

func runsServer(ctx context.Context) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	// manager cannot import swarmruntime (import cycle); ask ts-orch itself.
	output, err := exec.CommandContext(ctx, self, "service", "ls").Output()
	if err != nil {
		return false, fmt.Errorf("ts-orch service ls: %w", err)
	}
	for line := range strings.Lines(string(output)) {
		if strings.HasPrefix(line, netbird.ServerServiceName+" ") {
			return true, nil
		}
	}
	return false, nil
}

func runServerSide(ctx context.Context, vault ServerVault, dir string) error {
	if err := PrepareServer(ctx, vault); err != nil {
		return err
	}
	config, _, err := vaultsecret.Render(ctx, vault.Bundles, vault.Target.VaultID, "gru-1", []byte(ServerConfigTemplate))
	if err != nil {
		return err
	}
	defer clear(config)
	if err := writePrivate(dir, "config.yaml", config); err != nil {
		return err
	}
	if err := reconcileServerConfig(ctx, config); err != nil {
		return err
	}
	return BootstrapServer(ctx, vault, ServerURL)
}

const clientBinary = "/usr/local/bin/netbird"

// ensureClient keeps this host's pinned NetBird client installed, its daemon
// enabled and running, and restarts it after an upgrade.
func ensureClient(ctx context.Context) error {
	archive, err := clientPin.Archive(runtime.GOARCH)
	if err != nil {
		return err
	}
	upgraded := false
	if current, err := client.SHA256(clientBinary); err != nil || current != archive.BinarySHA256 {
		if err := client.Fetch(ctx, clientPin, runtime.GOARCH, clientBinary, "", &http.Client{Timeout: 5 * time.Minute}); err != nil {
			return fmt.Errorf("install NetBird client %s: %w", clientPin.Version, err)
		}
		// Fetch writes the binary owner-only; the CLI must run for every user.
		if err := os.Chmod(clientBinary, 0o755); err != nil {
			return err
		}
		upgraded = true
	}
	// The daemon must run the pinned binary, not a distribution package's.
	unit, _ := exec.CommandContext(ctx, "systemctl", "show", "--property", "ExecStart", "--value", "netbird").Output()
	if !strings.Contains(string(unit), clientBinary) {
		_ = exec.CommandContext(ctx, clientBinary, "service", "uninstall").Run()
		if output, err := exec.CommandContext(ctx, clientBinary, "service", "install").CombinedOutput(); err != nil {
			return fmt.Errorf("netbird service install: %w: %s", err, strings.TrimSpace(string(output)))
		}
		upgraded = true
	}
	action := "start"
	if upgraded {
		action = "restart"
	}
	for _, args := range [][]string{{"enable", "netbird"}, {action, "netbird"}} {
		if output, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

// enrollHost joins this host's NetBird daemon with the servers' setup key
// unless it is connected. The key reaches netbird only on stdin.
func enrollHost(ctx context.Context, vault ServerVault, setupKey string) error {
	var status struct {
		Management struct {
			Connected bool `json:"connected"`
		} `json:"management"`
	}
	output, err := exec.CommandContext(ctx, clientBinary, "status", "--json").Output()
	connected := err == nil && json.Unmarshal(output, &status) == nil && status.Management.Connected
	if connected {
		applied, err := serverSSHApplied(ctx)
		if err != nil || applied {
			return err
		}
		if output, err := exec.CommandContext(ctx, clientBinary, "down").CombinedOutput(); err != nil {
			return fmt.Errorf("netbird down: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	args := []string{"up", "--management-url", DefaultManagementURL}
	for _, setting := range serverSSHSettings {
		args = append(args, setting.flag+"="+strconv.FormatBool(setting.want))
	}
	up := exec.CommandContext(ctx, clientBinary, args...)
	if !connected {
		key, err := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, setupKey)
		if err != nil {
			return err
		}
		up.Args = append(up.Args, "--setup-key-file", "/dev/stdin")
		up.Stdin = strings.NewReader(key)
	}
	if output, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("netbird up: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

var serverSSHSettings = []struct {
	flag string
	key  string
	want bool
}{
	{"--allow-server-ssh", "serverSSHAllowed", false},
}

func serverSSHApplied(ctx context.Context) (bool, error) {
	output, err := exec.CommandContext(ctx, clientBinary, "debug", "config").Output()
	defer clear(output)
	if err != nil {
		return false, fmt.Errorf("netbird debug config: %w", err)
	}
	var config map[string]jsontext.Value
	if err := json.Unmarshal(output, &config); err != nil {
		return false, fmt.Errorf("netbird debug config: %w", err)
	}
	for _, setting := range serverSSHSettings {
		var value bool
		if err := json.Unmarshal(config[setting.key], &value); err != nil {
			return false, fmt.Errorf("netbird debug config %s: %w", setting.key, err)
		}
		if value != setting.want {
			return false, nil
		}
	}
	return true, nil
}

const containerUser = 65532

// writePrivate replaces dir/name atomically with a 0600 file of the container
// user, leaving an unchanged file alone so netbird-server never sees a rewrite.
func writePrivate(dir, name string, data []byte) error {
	if err := errors.Join(os.MkdirAll(dir, 0o700), os.Chown(dir, containerUser, containerUser)); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if current, err := os.ReadFile(path); err == nil && string(current) == string(data) {
		clear(current)
		return nil
	}
	file, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := errors.Join(file.Chmod(0o600), file.Chown(containerUser, containerUser), file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
