package tsauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

const cliUsage = `Usage: ts-orch ts-auth <command> [flags]

  secrets              --plan FILE
      Generate TS_AUTH_MASTER_KEY, TS_AUTH_AUDIT_SIGNING_KEY and TS_AUTH_OPERATOR_KEY
      once into the cell's Vault (operator ~/.oci/config). Existing secrets are kept.
  terrabase-bootstrap  --plan FILE --client-url URL --admin-url URL --member NODE
                       --member-ca FILE --dashboard-credential-file FILE
      Find or create ts-auth's organization terrascale-internal, project auth and
      database auth in the production TerraBase through one member's Management
      and admin APIs; store TS_AUTH_TERRASCALE_PROJECT_ID and, unless the Vault
      holds one, a newly issued TS_AUTH_TERRASCALE_API_KEY in the cell's Vault;
      read both back and check the key reaches the database. Prints the tenant IDs.
  env-file             --host-config FILE --vault-id OCID
      On a ts-auth host, as root: read the secrets with the instance principal and
      write <ts_auth_root>/ts-auth.env, mode 0600, owned by the workload user.
  metadata-rules
      Render host nftables rules reserving instance metadata for root and the controller.
`

// Run dispatches the ts-auth operator commands. Output never carries a secret.
// The CLI supplies validated plan parsing to avoid a host/provisioning import cycle.
func Run(ctx context.Context, args []string, output io.Writer, loadPlan func(string) (map[string]any, error)) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, cliUsage)
		return err
	}
	flags := flag.NewFlagSet("ts-auth "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.String("plan", "", "reviewed cell plan (deploy/oci-region/plan.json)")
	clientURL := flags.String("client-url", "", "TerraBase member client listener, for example https://127.0.0.1:19465")
	adminURL := flags.String("admin-url", "", "TerraBase member admin listener, for example http://127.0.0.1:19464")
	member := flags.String("member", "", "TerraBase member node the client listener belongs to, for example gru-1-db-1")
	memberCA := flags.String("member-ca", "", "the cell's TerraBase member-ca.pem")
	credential := flags.String("dashboard-credential-file", "", "owner-only file holding the member's dashboard credential")
	hostConfig := flags.String("host-config", "", "the host agent's host.json")
	vaultID := flags.String("vault-id", "", "the cell's Vault OCID")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected ts-auth arguments")
	}
	switch args[0] {
	case "metadata-rules":
		_, err := io.WriteString(output, metadataRules)
		return err
	case "secrets":
		if *plan == "" {
			return errors.New("secrets requires --plan")
		}
		cell, target, client, _, err := operatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		for _, key := range Generated {
			stored, err := Ensure(ctx, client, target, cell, key, Generate)
			if err != nil {
				return err
			}
			if err := json.MarshalWrite(output, stored); err != nil {
				return err
			}
			fmt.Fprintln(output)
		}
		return nil
	case "terrabase-bootstrap":
		if *plan == "" || *clientURL == "" || *adminURL == "" || *member == "" || *memberCA == "" || *credential == "" {
			return errors.New("terrabase-bootstrap requires --plan, --client-url, --admin-url, --member, --member-ca and --dashboard-credential-file")
		}
		terraBase, err := memberClient(*clientURL, *adminURL, *member, *memberCA, *credential)
		if err != nil {
			return err
		}
		cell, target, client, bundles, err := operatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		return bootstrap(ctx, terraBase, client, bundles, target, cell, output)
	case "env-file":
		if *hostConfig == "" || *vaultID == "" {
			return errors.New("env-file requires --host-config and --vault-id")
		}
		host, err := readHostConfig(*hostConfig)
		if err != nil {
			return err
		}
		parts := strings.Split(*vaultID, ".")
		if len(parts) < 5 || parts[1] != "vault" || !catalog.IsOCIRegion(parts[3]) {
			return errors.New("--vault-id must be a regional Vault OCID")
		}
		factory, err := ociclient.InstancePrincipal(parts[3])
		if err != nil {
			return err
		}
		secrets, err := ocisecrets.NewSecretsClientWithConfigurationProvider(factory.Provider())
		if err != nil {
			return err
		}
		secrets.SetRegion(factory.Region())
		factory.Configure(&secrets.BaseClient, ociclient.ServiceVault)
		path, err := WriteEnvFile(ctx, secrets, *vaultID, host)
		if err != nil {
			return err
		}
		return json.MarshalWrite(output, map[string]any{"env_file": path, "keys": Secrets})
	default:
		_, _ = io.WriteString(output, cliUsage)
		return fmt.Errorf("unknown ts-auth command %q", args[0])
	}
}

// bootstrap prepares ts-auth's TerraBase tenant, stores its project ID and
// API key in the Vault, and prints {"tenant":...,"secrets":[...]}. A key is
// issued only when the Vault holds none. It then reads both back: a project
// ID or key of an earlier run must still name this tenant and reach its
// database, or the command fails instead of reporting a stale tenant.
func bootstrap(ctx context.Context, terraBase TerraBase, client VaultClient, bundles BundleClient, target Target, cell string, output io.Writer) error {
	tenant, err := terraBase.EnsureTenant(ctx)
	if err != nil {
		return err
	}
	project, err := Ensure(ctx, client, target, cell, EnvProjectID, func(context.Context) (string, error) {
		return tenant.ProjectID, nil
	})
	if err != nil {
		return err
	}
	// A stale project ID must stop the command before a key is issued:
	// TerraBase cannot revoke one.
	projectID, err := readBack(ctx, bundles, target.VaultID, cell, EnvProjectID, project.Created || project.Provisioning)
	if err != nil {
		return err
	}
	if projectID != tenant.ProjectID {
		return fmt.Errorf("Vault secret %s names project %s, TerraBase has %s; inspect both before rerunning", project.Secret, projectID, tenant.ProjectID)
	}
	key, err := Ensure(ctx, client, target, cell, EnvAPIKey, func(ctx context.Context) (string, error) {
		return terraBase.IssueKey(ctx, tenant)
	})
	if err != nil {
		return err
	}
	apiKey, err := readBack(ctx, bundles, target.VaultID, cell, EnvAPIKey, key.Created || key.Provisioning)
	if err != nil {
		return err
	}
	if err := terraBase.CheckKey(ctx, tenant, apiKey); err != nil {
		return fmt.Errorf("Vault secret %s does not reach database %s: %w", key.Secret, tenant.Database, err)
	}
	if err := json.MarshalWrite(output, map[string]any{"tenant": tenant, "secrets": []Stored{project, key}}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output)
	return err
}

// readBack reads a secret that may have been created a moment ago: a new
// secret can take some seconds to become readable.
func readBack(ctx context.Context, bundles BundleClient, vaultID, cell, key string, created bool) (string, error) {
	for attempt := 1; ; attempt++ {
		value, err := readSecret(ctx, bundles, vaultID, cell, key)
		if err == nil || !created || attempt == 30 {
			return value, err
		}
		if !retrySecretRead(err) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// operatorVault reads the cell and its Vault from the reviewed plan and opens
// the Vault with the operator's ~/.oci/config DEFAULT profile.
func operatorVault(planPath string, loadPlan func(string) (map[string]any, error)) (string, Target, VaultClient, BundleClient, error) {
	if loadPlan == nil {
		return "", Target{}, nil, nil, errors.New("validated plan loader is required")
	}
	plan, err := loadPlan(planPath)
	if err != nil {
		return "", Target{}, nil, nil, err
	}
	cell, err := naming.RegionCell(fmt.Sprint(plan["cell"])).Name()
	if err != nil {
		return "", Target{}, nil, nil, err
	}
	ids, _ := plan["resource_ids"].(map[string]any)
	target := Target{}
	for field, id := range map[*string]any{&target.CompartmentID: ids["control_compartment"], &target.VaultID: ids["vault"], &target.KeyID: ids["key"]} {
		if *field, _ = id.(string); *field == "" {
			return "", Target{}, nil, nil, errors.New("plan resource_ids must name the control compartment, Vault and key of phase 1")
		}
	}
	factory, err := ociclient.OperatorConfig(fmt.Sprint(plan["region"]))
	if err != nil {
		return "", Target{}, nil, nil, err
	}
	client, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return "", Target{}, nil, nil, err
	}
	// The constructors take the profile's region; the plan names the Vault's.
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return "", Target{}, nil, nil, err
	}
	bundles.SetRegion(factory.Region())
	factory.Configure(&bundles.BaseClient, ociclient.ServiceVault)
	return cell, target, client, bundles, nil
}

// terraBaseRequestTimeout bounds each TerraBase request, its body included.
const terraBaseRequestTimeout = 30 * time.Second

// memberClient reaches one TerraBase member through the operator's SSH
// forwards: its client listener presents the member certificate, which names
// the member node, signed by the cell's member CA.
func memberClient(clientURL, adminURL, member, caFile, credentialFile string) (TerraBase, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return TerraBase{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return TerraBase{}, errors.New("--member-ca holds no PEM certificate")
	}
	credential, err := readOwnerOnly(credentialFile, 4096)
	if err != nil {
		return TerraBase{}, fmt.Errorf("--dashboard-credential-file: %w", err)
	}
	if !strings.HasPrefix(clientURL, "https://") || !strings.HasPrefix(adminURL, "http://") {
		return TerraBase{}, errors.New("--client-url must be https:// and --admin-url http://")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: member, MinVersion: tls.VersionTLS12}
	// A member or forward that accepts but stalls must not hang the command.
	return TerraBase{HTTP: &http.Client{Transport: transport, Timeout: terraBaseRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ClientURL: strings.TrimSuffix(clientURL, "/"),
		AdminURL: strings.TrimSuffix(adminURL, "/"), Credential: strings.TrimSpace(string(credential))}, nil
}

// readOwnerOnly reads a regular file that only its owner can read.
func readOwnerOnly(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, errors.New("must be a regular owner-only file")
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

// HostConfig is the part of host.json that places ts-auth's files.
type HostConfig struct {
	Cell          string `json:"-"`
	Root          string `json:"ts_auth_root"`
	InstallRoot   string `json:"install_root"`
	StateRoot     string `json:"state_root"`
	TerraBaseRoot string `json:"terrabase_root"`
	UID           uint32 `json:"workload_uid"`
	GID           uint32 `json:"workload_gid"`
}

func readHostConfig(path string) (HostConfig, error) {
	data, err := readOwnerOnly(path, 1<<20)
	if err != nil {
		return HostConfig{}, fmt.Errorf("host config: %w", err)
	}
	var config struct {
		NATS struct {
			Cell string `json:"cell"`
		} `json:"nats"`
		Host HostConfig `json:"host"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return HostConfig{}, fmt.Errorf("host config: %w", err)
	}
	cell, err := naming.RegionCell(config.NATS.Cell).Name()
	if err != nil {
		return HostConfig{}, fmt.Errorf("host config cell: %w", err)
	}
	if config.Host.Root == "" || config.Host.UID == 0 || config.Host.GID == 0 || config.Host.InstallRoot == "" || config.Host.StateRoot == "" {
		return HostConfig{}, errors.New("host config requires ts_auth_root, install_root, state_root and a non-root workload identity")
	}
	if err := config.Host.validateRoots(); err != nil {
		return HostConfig{}, err
	}
	config.Host.Cell = cell
	return config.Host, nil
}

// validateRoots runs before Vault access or any directory permission change.
func (host HostConfig) validateRoots() error {
	if !filepath.IsAbs(host.Root) || filepath.Clean(host.Root) != host.Root || host.Root == "/" {
		return errors.New("ts_auth_root must be a clean absolute path other than /")
	}
	for _, other := range []string{host.InstallRoot, host.StateRoot, host.TerraBaseRoot} {
		if other == "" {
			continue
		}
		if !filepath.IsAbs(other) || filepath.Clean(other) != other {
			return errors.New("host roots must be clean absolute paths")
		}
		if other == "/" || host.Root == other || strings.HasPrefix(host.Root, other+"/") || strings.HasPrefix(other, host.Root+"/") {
			return errors.New("ts_auth_root must be separate from the install, state and other workload roots")
		}
	}
	return nil
}

// WriteEnvFile reads ts-auth's secrets from the Vault and atomically replaces
// the host's env file with them: mode 0600, owned by the workload user. It
// creates the ts-auth root like the host agent does (root, workload group,
// 0750). Every path component is opened by descriptor without following a
// symlink, each ancestor must be a directory only root or this user can
// change (or sticky), and every change goes through a descriptor, so no
// privileged effect follows a path someone else can swap.
func WriteEnvFile(ctx context.Context, client BundleClient, vaultID string, host HostConfig) (string, error) {
	if err := host.validateRoots(); err != nil {
		return "", err
	}
	secrets, err := ReadSecrets(ctx, client, vaultID, host.Cell)
	if err != nil {
		return "", err
	}
	data, err := RenderEnvFile(secrets)
	if err != nil {
		return "", err
	}
	defer clear(data)
	root, err := openRoot(host.Root)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	if err := unix.Fchown(root, os.Geteuid(), int(host.GID)); err != nil {
		return "", err
	}
	if err := unix.Fchmod(root, 0o750); err != nil {
		return "", err
	}
	name := filepath.Base(Layout(host.Root).EnvFile())
	temporary := "." + name + "." + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(root, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer unix.Unlinkat(root, temporary, 0)
	err = unix.Fchmod(fd, 0o600)
	if err == nil {
		err = unix.Fchown(fd, int(host.UID), int(host.GID))
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat(root, temporary, root, name)
	}
	if err == nil {
		err = unix.Fsync(root)
	}
	return Layout(host.Root).EnvFile(), err
}

// openRoot opens path as a directory, creating its last component, by
// walking it from / one descriptor at a time without following a symlink.
// Like the host agent's workload roots, nobody but root or this user may add
// entries to the root's parent, even a sticky one such as /tmp, so nobody
// else can create or swap the root; and the root itself must be owned by
// root or this user before anything changes it.
func openRoot(path string) (int, error) {
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		last := index == len(components)-1
		if err := checkDirectory(dir, !last); err != nil {
			unix.Close(dir)
			return -1, fmt.Errorf("ts_auth_root %s: %w", path, err)
		}
		if last {
			if err := unix.Mkdirat(dir, component, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(dir)
				return -1, err
			}
		}
		next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return -1, fmt.Errorf("ts_auth_root %s must be a path of directories, not symlinks: %w", path, err)
		}
		dir = next
	}
	if err := checkOwner(dir); err != nil {
		unix.Close(dir)
		return -1, fmt.Errorf("ts_auth_root %s: %w", path, err)
	}
	return dir, nil
}

// checkDirectory accepts a directory that only root or this user own and
// that nobody else can add entries to; a sticky one such as /tmp is accepted
// only as a farther ancestor, whose entries others cannot rename.
func checkDirectory(dir int, stickyAllowed bool) error {
	if err := checkOwner(dir); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil {
		return err
	}
	if stat.Mode&0o022 != 0 && (!stickyAllowed || stat.Mode&unix.S_ISVTX == 0) {
		return errors.New("an ancestor lets another user add or replace its entries")
	}
	return nil
}

// checkOwner accepts a directory owned by root or this user.
func checkOwner(dir int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("a directory is owned by uid %d, not root or this user", stat.Uid)
	}
	return nil
}
