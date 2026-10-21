package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// The shared mesh secret lives in the gru Vault (compartment gru-1-control);
// every region reads it cross-region with its instance principal.
const (
	vaultRegion   = "sa-saopaulo-1"
	vaultID       = "ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq"
	vaultKeyID    = "ocid1.key.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr57gu27ray2ukib2irijktpd6eqa6ou5zeqstsmasvqcr7hmfu2ia"
	compartmentID = "ocid1.compartment.oc1..aaaaaaaaypdff62jbchkojfli5i22ybzm3qnptwwsbg3aa2t5ali6te52nzq"
	secretName    = "ts-orch-mesh-key"
	retryEvery    = 30 * time.Second
)

// Run serves this host's region on the mesh until ctx ends. A missing Vault
// secret, IMDS answer or peer never stops local serving: Run logs and retries,
// and gateways reconnect on their own.
func Run(ctx context.Context, state string) {
	for {
		node, err := startHost(ctx, state)
		if err == nil {
			slog.InfoContext(ctx, "mesh started", "region", node.cfg.region, "server", node.cfg.server)
			node.run(ctx)
			node.Close()
			return
		}
		slog.WarnContext(ctx, "mesh start failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryEvery):
		}
	}
}

func startHost(ctx context.Context, state string) (*Node, error) {
	region, err := ownRegion(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := loadSecret(ctx)
	if err != nil {
		return nil, err
	}
	ca, err := DeriveCA(secret)
	clear(secret)
	if err != nil {
		return nil, err
	}
	name, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	gateways := map[string]string{}
	for _, peer := range Regions() {
		if peer != region {
			gateways[peer] = fmt.Sprintf("nats://%s.%s:%d", peer, Domain, GatewayPort)
		}
	}
	return start(config{
		region: region, server: name, dir: filepath.Join(state, "mesh"), host: "0.0.0.0",
		clientPort: PublicPort, gatewayPort: GatewayPort, localPort: LocalPort,
		gateways: gateways, ca: ca, applier: swarmApplier{state: state}, every: antiEntropyEvery, logs: true,
	})
}

// ownRegion maps the instance's OCI region to its ordered region token.
func ownRegion(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/opc/v2/instance/canonicalRegionName", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := hostenroll.NewIMDSClient().Do(request)
	if err != nil {
		return "", fmt.Errorf("read OCI region from IMDS: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil || response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read OCI region from IMDS: status %d", response.StatusCode)
	}
	entry, ok := catalog.CellForOCIRegion(strings.TrimSpace(string(body)))
	if !ok || !slices.Contains(Regions(), entry.Name()) {
		return "", fmt.Errorf("OCI region %q is not an ordered region", strings.TrimSpace(string(body)))
	}
	return entry.Name(), nil
}

// loadSecret reads the shared mesh secret, creating it once when the Vault
// has none. The value is never logged.
func loadSecret(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	factory, err := ociclient.InstancePrincipalContext(ctx, vaultRegion)
	if err != nil {
		return nil, err
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, err
	}
	value, err := vaultsecret.Read(ctx, bundles, vaultID, secretName)
	if err != nil {
		management, clientErr := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
		if clientErr != nil {
			return nil, clientErr
		}
		management.SetRegion(factory.Region())
		factory.Configure(&management.BaseClient, ociclient.ServiceVault)
		// Ensure creates only when absent; a concurrent creator wins and we re-read.
		if _, ensureErr := vaultsecret.Ensure(ctx, &management, vaultsecret.Target{CompartmentID: compartmentID, VaultID: vaultID, KeyID: vaultKeyID},
			secretName, "ts-orch mesh CA seed", func(context.Context) (string, error) {
				seed := make([]byte, 32)
				_, err := rand.Read(seed)
				return hex.EncodeToString(seed), err
			}); ensureErr != nil {
			return nil, errors.Join(err, ensureErr)
		}
		if value, err = vaultsecret.Read(ctx, bundles, vaultID, secretName); err != nil {
			return nil, err
		}
	}
	secret, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("Vault secret %s is not 32 hex-encoded bytes", secretName)
	}
	return secret, nil
}

// swarmApplier drives the single-host SwarmKit node in state.
type swarmApplier struct{ state string }

func (a swarmApplier) rows(ctx context.Context, name string, do func(row swarmruntime.ServiceSpecStatus, found bool, client api.ControlClient) error) error {
	client, conn, err := swarmruntime.DialSingleHost(a.state)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := swarmruntime.ListServiceSpecs(ctx, client)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Name == name {
			return do(row, true, client)
		}
	}
	return do(swarmruntime.ServiceSpecStatus{}, false, client)
}

func (a swarmApplier) Apply(ctx context.Context, spec swarmruntime.ServiceSpec) (changed bool, err error) {
	err = a.rows(ctx, spec.Name, func(row swarmruntime.ServiceSpecStatus, found bool, client api.ControlClient) error {
		if found && row.Generation == spec.Generation {
			return nil
		}
		changed = true
		_, err := swarmruntime.ApplyServiceSpec(ctx, client, spec)
		return err
	})
	return changed, err
}

func (a swarmApplier) Remove(ctx context.Context, name string) (removed bool, err error) {
	err = a.rows(ctx, name, func(_ swarmruntime.ServiceSpecStatus, found bool, client api.ControlClient) error {
		if !found {
			return nil
		}
		removed = true
		return swarmruntime.RemoveServiceSpec(ctx, client, name)
	})
	return removed, err
}

func (a swarmApplier) Running(ctx context.Context, name string) (running bool, err error) {
	err = a.rows(ctx, name, func(row swarmruntime.ServiceSpecStatus, found bool, _ api.ControlClient) error {
		running = found && row.Replicas > 0 && row.Running >= row.Replicas
		return nil
	})
	return running, err
}
