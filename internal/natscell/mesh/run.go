package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// The shared mesh secret lives in the gru-vault (compartment gru-1-control);
// every region reads it cross-region with its instance principal.
const (
	vaultRegion   = "sa-saopaulo-1"
	vaultID       = vaultsecret.SharedVault
	vaultKeyID    = "ocid1.key.oc1.sa-saopaulo-1.ffvnrldqaaexa.abtxeljr2bdwyvlua7oi6gpg7gl72ln6t2l2fb63tl2cvhllvokc4l2afeeq"
	compartmentID = "ocid1.compartment.oc1..aaaaaaaaypdff62jbchkojfli5i22ybzm3qnptwwsbg3aa2t5ali6te52nzq"
	secretName    = "ts-orch-mesh-key"
	// TerraBaseTokenSecret is TerraBase's mesh NATS token; its service spec
	// delivers the same secret as TERRABASE_NATS_TOKEN_FILE.
	TerraBaseTokenSecret = "gru-1-terrabase-nats-token"
	retryEvery           = 30 * time.Second
)

// Run serves this host's region on the mesh until ctx ends, calling started
// once the node runs. A missing Vault secret, IMDS answer or peer never stops
// local serving: Run logs and retries, and gateways reconnect on their own.
func Run(ctx context.Context, state string, cluster Cluster, started func(*Node)) {
	for {
		admission, stored, err := swarmruntime.StoredAdmission(state)
		if err == nil && stored {
			cluster.Worker = admission.Role != "manager"
		}
		runCtx, cancel := context.WithCancel(ctx)
		var node *Node
		if err == nil {
			node, err = startHost(runCtx, state, cluster)
		}
		if err == nil {
			slog.InfoContext(ctx, "mesh started", "region", node.cfg.region, "server", node.cfg.server)
			started(node)
			go node.servePeerMetrics(node.ctx)
			go watchHostRole(runCtx, state, cluster.Worker, cancel)
			node.Run(runCtx)
			roleChanged := runCtx.Err() != nil
			cancel()
			node.Close()
			if ctx.Err() != nil {
				return
			}
			if roleChanged {
				continue
			}
			err = errors.New("mesh node stopped")
		}
		cancel()
		slog.WarnContext(ctx, "mesh start failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryEvery):
		}
	}
}

func watchHostRole(ctx context.Context, state string, worker bool, cancel context.CancelFunc) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			admission, stored, err := swarmruntime.StoredAdmission(state)
			if err != nil {
				slog.WarnContext(ctx, "mesh host role unavailable", "error", err)
				continue
			}
			if stored && (admission.Role != "manager") != worker {
				cancel()
				return
			}
		}
	}
}

func startHost(ctx context.Context, state string, cluster Cluster) (*Node, error) {
	region, err := ownRegion(ctx)
	if err != nil {
		return nil, err
	}
	if err := releasepush.OpenTCP(ctx, ClusterPort); err != nil {
		slog.WarnContext(ctx, "mesh cluster firewall", "error", err)
	}
	secret, err := loadSecret(ctx, secretName, "ts-orch mesh CA seed")
	if err != nil {
		return nil, err
	}
	terrabaseToken, err := loadSecret(ctx, TerraBaseTokenSecret, "TerraBase mesh NATS token")
	if err != nil {
		clear(secret)
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
	return Start(ctx, state, region, name, ca, hex.EncodeToString(terrabaseToken), cluster)
}

func Start(ctx context.Context, state, region, name string, ca *CA, terrabaseToken string, cluster Cluster) (*Node, error) {
	var routes []string
	var err error
	if cluster.Routes != nil {
		if routes, err = cluster.Routes(ctx, region); err != nil {
			return nil, err
		}
	}
	seeds := map[string][]string{}
	for _, peer := range Regions() {
		if peer == region {
			continue
		}
		seeds[peer] = nil
		for _, manager := range []string{"1", "2", "3"} {
			name := fmt.Sprintf("ts-%s-%s.%s", peer, manager, netBirdDomain)
			lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
			addresses, err := net.DefaultResolver.LookupHost(lookup, name)
			cancel()
			if err != nil || len(addresses) == 0 {
				slog.InfoContext(ctx, "mesh seed skipped; name does not resolve", "host", name)
				continue
			}
			seeds[peer] = append(seeds[peer], fmt.Sprintf("nats://%s:%d", name, ClusterPort))
		}
	}
	var advertise string
	if address, err := NetBirdAddress(); err == nil {
		advertise = net.JoinHostPort(address, strconv.Itoa(ClusterPort))
	} else {
		slog.WarnContext(ctx, "mesh cluster advertises no NetBird address", "error", err)
	}
	return StartRegionalHost(RegionalHost{State: state, Region: region, Server: name, CA: ca,
		TerraBaseToken: terrabaseToken, Seeds: seeds, Routes: routes,
		ClusterAddress: advertise, Address: NetBirdAddress, Worker: cluster.Worker})
}

// ownRegion maps the instance's OCI region to its catalog region token.
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
	if !ok {
		return "", fmt.Errorf("OCI region %q is not a catalog region", strings.TrimSpace(string(body)))
	}
	return entry.Name(), nil
}

// loadSecret reads a shared mesh secret of 32 random bytes, creating it once
// when the Vault has none. The value is never logged.
func loadSecret(ctx context.Context, secretName, description string) ([]byte, error) {
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
			secretName, description, func(context.Context) (string, error) {
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
type swarmApplier struct {
	state    string
	region   string
	client   api.ControlClient
	revision func(context.Context, string, string) (string, error)
}

func (a swarmApplier) control() (api.ControlClient, func(), error) {
	if a.client != nil {
		return a.client, func() {}, nil
	}
	client, conn, err := swarmruntime.DialSingleHost(a.state)
	if err != nil {
		return nil, nil, err
	}
	return client, func() { _ = conn.Close() }, nil
}

func (a swarmApplier) rows(ctx context.Context, name string, do func(row swarmruntime.ServiceSpecStatus, found bool, client api.ControlClient) error) error {
	client, close, err := a.control()
	if err != nil {
		return err
	}
	defer close()
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

func (a swarmApplier) Apply(ctx context.Context, spec swarmruntime.ServiceSpec) (changed bool, original *api.Service, err error) {
	err = a.rows(ctx, spec.Name, func(_ swarmruntime.ServiceSpecStatus, _ bool, client api.ControlClient) error {
		changed = true
		var err error
		original, err = swarmruntime.ApplyServiceSpec(ctx, client, spec)
		return err
	})
	return changed, original, err
}

func (a swarmApplier) Ready(ctx context.Context) (map[string]ServingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, servingProbeBudget)
	defer cancel()
	client, done, err := a.control()
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := swarmruntime.ListServiceSpecs(ctx, client)
	if err != nil {
		return nil, err
	}
	type observation struct {
		name   string
		result ServingResult
	}
	results := make(chan observation, len(rows))
	for _, row := range rows {
		go func() {
			probe, stop := context.WithTimeout(ctx, servingProbeBudget)
			defer stop()
			result := ServingResult{Generation: row.Generation}
			result.Serving = row.Replicas > 0 && row.Running == row.Replicas && swarmruntime.ServingService(probe, client, row.Name) == nil && probe.Err() == nil
			result.At = time.Now()
			results <- observation{row.Name, result}
		}()
	}
	ready := make(map[string]ServingResult, len(rows))
	for range rows {
		result := <-results
		ready[result.name] = result.result
	}
	return ready, nil
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

func (a swarmApplier) PrePull(ctx context.Context, spec swarmruntime.ServiceSpec) error {
	swarm, err := spec.SwarmSpec()
	if err != nil {
		return err
	}
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, a.state)
	if err != nil {
		return err
	}
	defer executor.Close()
	// The same pull authority `ts-orch single-host` installs for its tasks.
	if err := executor.SetRegistryResolver(swarmruntime.GHCRResolver(vaultsecret.ReadGHCRPullToken)); err != nil {
		return err
	}
	return executor.PrePull(ctx, spec.Image, swarm.Annotations.Labels)
}

func (a swarmApplier) Wait(ctx context.Context, spec swarmruntime.ServiceSpec, original *api.Service) (swarmruntime.ServiceRollout, error) {
	client, close, err := a.control()
	if err != nil {
		return swarmruntime.ServiceRollout{}, err
	}
	defer close()
	if err := swarmruntime.CompleteServiceSpec(ctx, client, spec, original); err != nil {
		return swarmruntime.ServiceRollout{}, err
	}
	rollout, err := swarmruntime.WaitServiceSpecExact(ctx, client, spec)
	if err != nil {
		return rollout, err
	}
	revision := a.revision
	if revision == nil {
		revision = swarmruntime.ImageRevision
	}
	rollout.Revision, err = revision(ctx, swarmruntime.HostContainerdSocket, spec.Image)
	return rollout, err
}
