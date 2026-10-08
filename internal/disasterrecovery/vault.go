package disasterrecovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

const vaultReplicaTimeout = 10 * time.Minute

var vaultReplicaOCID = regexp.MustCompile(`^ocid1\.vault\.oc1\.([a-z0-9-]+)\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

// VaultReplicaReport contains public metadata only. VaultID identifies the
// source: OCI's replica summary exposes no separate replica vault OCID.
type VaultReplicaReport struct {
	VaultID        string `json:"vaultId"`
	TargetRegion   string `json:"targetRegion"`
	Status         string `json:"status"` // MISSING, CREATING, or CREATED.
	CryptoEndpoint string `json:"cryptoEndpoint,omitempty"`
}

type vaultReplicaClient interface {
	GetVault(context.Context, keymanagement.GetVaultRequest) (keymanagement.GetVaultResponse, error)
	ListVaultReplicas(context.Context, keymanagement.ListVaultReplicasRequest) (keymanagement.ListVaultReplicasResponse, error)
	CreateVaultReplica(context.Context, keymanagement.CreateVaultReplicaRequest) (keymanagement.CreateVaultReplicaResponse, error)
}

// EnsureVaultReplica plans, reuses, or creates the one supported cross-region
// replica. It never deletes or replaces a vault. Calls, including polling, are
// bounded to ten minutes or the caller's earlier deadline.
func EnsureVaultReplica(ctx context.Context, factory *ociclient.Factory, vaultID, targetRegion string, apply bool) (VaultReplicaReport, error) {
	if factory == nil {
		return VaultReplicaReport{}, errors.New("vault replication requires an OCI client factory")
	}
	if err := validateVaultReplicaTarget(ctx, vaultID, factory.Region(), targetRegion); err != nil {
		return VaultReplicaReport{}, err
	}
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return VaultReplicaReport{}, fmt.Errorf("create OCI KMS Vault client: %w", err)
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	return ensureVaultReplica(ctx, client, vaultID, factory.Region(), targetRegion, apply)
}

func validateVaultReplicaTarget(ctx context.Context, vaultID, sourceRegion, targetRegion string) error {
	if ctx == nil {
		return errors.New("vault replication requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !(sourceRegion == "sa-saopaulo-1" && targetRegion == "us-sanjose-1" ||
		sourceRegion == "us-sanjose-1" && targetRegion == "sa-saopaulo-1") {
		return errors.New("vault replication supports only sa-saopaulo-1 <-> us-sanjose-1")
	}
	match := vaultReplicaOCID.FindStringSubmatch(vaultID)
	if len(match) != 2 || match[1] != sourceRegion {
		return errors.New("source vault OCID must match the OCI factory region")
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return fmt.Errorf("vault replication refuses to run while %s is set", name)
		}
	}
	return nil
}

func ensureVaultReplica(ctx context.Context, client vaultReplicaClient, vaultID, sourceRegion, targetRegion string, apply bool) (VaultReplicaReport, error) {
	report := VaultReplicaReport{VaultID: vaultID, TargetRegion: targetRegion, Status: "MISSING"}
	if err := validateVaultReplicaTarget(ctx, vaultID, sourceRegion, targetRegion); err != nil {
		return report, err
	}
	if client == nil {
		return report, errors.New("vault replication requires a KMS Vault client")
	}
	ctx, cancel := context.WithTimeout(ctx, vaultReplicaTimeout)
	defer cancel()
	source, err := client.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: common.String(vaultID)})
	if err != nil {
		return report, fmt.Errorf("read source vault: %w", err)
	}
	replicationID, err := validateVaultReplicaSource(source.Vault, vaultID)
	if err != nil {
		return report, err
	}
	replica, err := readVaultReplica(ctx, client, vaultID, targetRegion)
	if err != nil {
		return report, err
	}
	if replica != nil {
		switch replica.Status {
		case keymanagement.VaultReplicaSummaryStatusCreated:
		case keymanagement.VaultReplicaSummaryStatusCreating, "":
			// An interrupted run can leave the replica mid-creation.
			report.Status = "CREATING"
			return report, fmt.Errorf("existing vault replica is still being created (%q); re-run once it reaches CREATED", replica.Status)
		default:
			return report, fmt.Errorf("existing vault replica is %q; expected CREATED", replica.Status)
		}
		report.CryptoEndpoint, err = vaultReplicaEndpoint(replica.CryptoEndpoint, targetRegion)
		if err == nil {
			report.Status = "CREATED"
		}
		return report, err
	}
	if replicationID != "" {
		return report, errors.New("source vault has a replication ID but no listed replica")
	}
	if !apply {
		return report, nil
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Status = "CREATING"
	_, err = client.CreateVaultReplica(ctx, keymanagement.CreateVaultReplicaRequest{
		VaultId: common.String(vaultID), IfMatch: source.Etag,
		CreateVaultReplicaDetails: keymanagement.CreateVaultReplicaDetails{ReplicaRegion: common.String(targetRegion)},
		OpcRetryToken:             common.String(common.RetryToken()),
	})
	if err != nil {
		return report, fmt.Errorf("create vault replica (inspect before retrying): %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return report, fmt.Errorf("wait for vault replica: %w", err)
		}
		source, err := client.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: common.String(vaultID)})
		if err != nil {
			return report, fmt.Errorf("read source vault after replica creation: %w", err)
		}
		currentID, err := validateVaultReplicaSource(source.Vault, vaultID)
		if err != nil {
			return report, err
		}
		if replicationID != "" && currentID != replicationID {
			return report, errors.New("source vault replication ID changed while polling")
		}
		replicationID = currentID
		replica, err := readVaultReplica(ctx, client, vaultID, targetRegion)
		if err != nil {
			return report, err
		}
		if replica != nil {
			switch replica.Status {
			case keymanagement.VaultReplicaSummaryStatusCreated:
				report.CryptoEndpoint, err = vaultReplicaEndpoint(replica.CryptoEndpoint, targetRegion)
				if err == nil {
					report.Status = "CREATED"
				}
				return report, err
			// OCI first lists a new replica with no status (seen 2026-10-08).
			case keymanagement.VaultReplicaSummaryStatusCreating, "":
			default:
				return report, fmt.Errorf("vault replica entered unexpected state %q", replica.Status)
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return report, fmt.Errorf("wait for vault replica: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func validateVaultReplicaSource(vault keymanagement.Vault, vaultID string) (string, error) {
	if vault.Id == nil || *vault.Id != vaultID {
		return "", errors.New("OCI returned a different source vault ID")
	}
	if vault.LifecycleState != keymanagement.VaultLifecycleStateActive {
		return "", fmt.Errorf("source vault is %q; expected ACTIVE", vault.LifecycleState)
	}
	if vault.IsVaultReplicable == nil || !*vault.IsVaultReplicable {
		return "", errors.New("source vault is not replicable; existing keys cannot be moved to a replacement vault")
	}
	if vault.IsPrimary != nil && !*vault.IsPrimary {
		return "", errors.New("source vault is itself a replica")
	}
	if vault.ReplicaDetails != nil {
		if vault.ReplicaDetails.ReplicationId == nil || *vault.ReplicaDetails.ReplicationId == "" {
			return "", errors.New("source vault has inconsistent replication details")
		}
		return *vault.ReplicaDetails.ReplicationId, nil
	}
	return "", nil
}

func readVaultReplica(ctx context.Context, client vaultReplicaClient, vaultID, targetRegion string) (*keymanagement.VaultReplicaSummary, error) {
	var replica *keymanagement.VaultReplicaSummary
	var page *string
	pages := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := client.ListVaultReplicas(ctx, keymanagement.ListVaultReplicasRequest{VaultId: common.String(vaultID), Page: page})
		if err != nil {
			return nil, fmt.Errorf("list vault replicas: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, item := range response.Items {
			if item.Region == nil || *item.Region != targetRegion {
				return nil, errors.New("existing vault replica region differs from the requested target")
			}
			if replica != nil {
				return nil, errors.New("OCI returned multiple vault replicas; operator inspection required")
			}
			replica = &item
		}
		page = response.OpcNextPage
		if page == nil || *page == "" {
			return replica, nil
		}
		if pages[*page] {
			return nil, errors.New("OCI repeated a vault replica pagination token")
		}
		pages[*page] = true
	}
}

func vaultReplicaEndpoint(endpoint *string, region string) (string, error) {
	return kmsEndpoint(endpoint, region, "crypto")
}
