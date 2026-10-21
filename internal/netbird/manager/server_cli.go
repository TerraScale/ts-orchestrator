package manager

import (
	"context"
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
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const serverUsage = `Usage: ts-orch netbird server --vault-id OCID --key-id OCID --compartment-id OCID --dir DIR

On ts-gru-1, as root, with the instance principal: create the NetBird server's
generated secrets in Vault once, write DIR/config.yaml (mode 0600, owned by the
container user) for the netbird-server service, wait for it on ` + ServerURL + `, claim the owner and
keep the admin PAT and setup keys in Vault, then re-sync GRU() every 10 minutes.
`

// runServer is the long-running ts-orch side of the netbird-server service.
func runServer(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("netbird server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	vaultID := flags.String("vault-id", "", "the Vault OCID")
	keyID := flags.String("key-id", "", "the Vault master key OCID")
	compartmentID := flags.String("compartment-id", "", "the compartment of the secrets")
	dir := flags.String("dir", "", "the netbird-server data directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		_, _ = io.WriteString(stdout, serverUsage)
		return errors.New("netbird server: invalid arguments")
	}
	parts := strings.Split(*vaultID, ".")
	if len(parts) < 5 || parts[1] != "vault" || *keyID == "" || *compartmentID == "" || !filepath.IsAbs(*dir) {
		_, _ = io.WriteString(stdout, serverUsage)
		return errors.New("netbird server requires --vault-id, --key-id, --compartment-id and an absolute --dir")
	}
	if os.Geteuid() != 0 {
		return errors.New("netbird server runs as root: its config holds secrets")
	}
	factory, err := ociclient.InstancePrincipal(parts[3])
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
	vault := ServerVault{Target: vaultsecret.Target{CompartmentID: *compartmentID, VaultID: *vaultID, KeyID: *keyID},
		Management: management, Versions: management, Bundles: bundles}
	logf := func(format string, args ...any) { fmt.Fprintf(stdout, "netbird server: "+format+"\n", args...) }
	for {
		err := serveOnce(ctx, vault, *dir)
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

// serveOnce converges config and manager state; each step is idempotent.
func serveOnce(ctx context.Context, vault ServerVault, dir string) error {
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
	if err := BootstrapServer(ctx, vault, ServerURL); err != nil {
		return err
	}
	if err := ensureClient(ctx); err != nil {
		return err
	}
	return enrollHost(ctx, vault)
}

// clientPin is the NetBird client every TerraScale host runs, the same
// release as the server image.
var clientPin = func() client.Pin {
	p := client.Pin{Version: "0.81.3"}
	p.Archives.Arm64 = client.Archive{URL: "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_arm64.tar.gz",
		Bytes: 14607827, SHA256: "980eef938177108bdfa7d802566b6309123592a58631349a78f11cd97c76c22d",
		BinarySHA256: "da0c759ba50c0e1fd652d6f584587db3d3523dcc6bd18c11fab479969a3057ce"}
	p.Archives.AMD64 = client.Archive{URL: "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_amd64.tar.gz",
		Bytes: 15954874, SHA256: "cbdea310068e35449f034544d5137fefee8f6d948fffd020883ffc8b3bab63b1",
		BinarySHA256: "2bef5a5a44249443c0c492883e1b243ff5bc9d835266a8c5644a2a664bb3b846"}
	return p
}()

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
	if exec.CommandContext(ctx, "systemctl", "is-enabled", "--quiet", "netbird").Run() != nil {
		if output, err := exec.CommandContext(ctx, clientBinary, "service", "install").CombinedOutput(); err != nil {
			return fmt.Errorf("netbird service install: %w: %s", err, strings.TrimSpace(string(output)))
		}
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
func enrollHost(ctx context.Context, vault ServerVault) error {
	var status struct {
		Management struct {
			Connected bool `json:"connected"`
		} `json:"management"`
	}
	output, err := exec.CommandContext(ctx, clientBinary, "status", "--json").Output()
	if err == nil && json.Unmarshal(output, &status) == nil && status.Management.Connected {
		return nil
	}
	key, err := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, serversKeySecret)
	if err != nil {
		return err
	}
	up := exec.CommandContext(ctx, clientBinary, "up", "--management-url", DefaultManagementURL, "--setup-key-file", "/dev/stdin")
	up.Stdin = strings.NewReader(key)
	if output, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("netbird up: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// containerUser is the uid:gid every single-host service runs as
// (swarmruntime.ServiceSpec).
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
