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
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const cliUsage = `Usage: ts-orch ts-auth <command> [flags]

  secrets              --plan FILE
      Generate TS_AUTH_MASTER_KEY, TS_AUTH_AUDIT_SIGNING_KEY, TS_AUTH_OPERATOR_KEY and
      TS_AUTH_DASHBOARD_CLIENT_SECRET once into the cell's Vault (operator
      ~/.oci/config). Existing secrets are kept.
  metadata-rules
      Render host nftables rules reserving instance metadata for root and the controller.

ts-orch ouroboros bootstrap stores TS_AUTH_TERRASCALE_PROJECT_ID and
TS_AUTH_TERRASCALE_API_KEY.
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
		cell, target, client, _, err := OperatorVault(*plan, loadPlan)
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
	default:
		_, _ = io.WriteString(output, cliUsage)
		return fmt.Errorf("unknown ts-auth command %q", args[0])
	}
}

// OperatorVault reads the cell and its Vault from the reviewed plan and opens
// the Vault with the operator's ~/.oci/config DEFAULT profile.
func OperatorVault(planPath string, loadPlan func(string) (map[string]any, error)) (string, Target, VaultClient, BundleClient, error) {
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
