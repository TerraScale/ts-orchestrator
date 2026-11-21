package mesh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type Records interface {
	Read(ctx context.Context, name string) (value string, version int64, err error)
	Exists(ctx context.Context, name string) (bool, error)
	Create(ctx context.Context, name, value string) error
	Swap(ctx context.Context, name string, version int64, value string) error
}

var errRecordMoved = errors.New("mesh record changed since it was read")

func VaultRecords() Records { return vaultRecords{} }

type vaultRecords struct{}

type vaultClients struct {
	factory    *ociclient.Factory
	bundles    vaultsecret.BundleClient
	management *ocivault.VaultsClient
}

func openVault(ctx context.Context) (vaultClients, error) {
	factory, err := ociclient.InstancePrincipalContext(ctx, vaultRegion)
	if err != nil {
		return vaultClients{}, err
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return vaultClients{}, err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return vaultClients{}, err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	return vaultClients{factory: factory, bundles: bundles, management: &management}, nil
}

func (vaultRecords) current(ctx context.Context, name string) (vaultClients, vaultsecret.Current, error) {
	clients, err := openVault(ctx)
	if err != nil {
		return vaultClients{}, vaultsecret.Current{}, err
	}
	current, err := vaultsecret.ReadCurrent(ctx, clients.bundles, vaultsecret.Ref{Vault: vaultID, Name: name})
	return clients, current, err
}

func (r vaultRecords) Read(ctx context.Context, name string) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	clients, current, err := r.current(ctx, name)
	if vaultsecret.Absent(err) {
		exists, listErr := vaultsecret.Exists(ctx, clients.management, SharedVault, name)
		if listErr != nil {
			return "", 0, listErr
		}
		if exists {
			return "", 0, fmt.Errorf("%s exists but this host's Vault grants do not let it read it", name)
		}
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	return current.Value(), current.Version, nil
}

func (vaultRecords) Exists(ctx context.Context, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	clients, err := openVault(ctx)
	if err != nil {
		return false, err
	}
	return vaultsecret.Exists(ctx, clients.management, SharedVault, name)
}

func (vaultRecords) Create(ctx context.Context, name, value string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	clients, err := openVault(ctx)
	if err != nil {
		return err
	}
	_, err = vaultsecret.Ensure(ctx, clients.management, SharedVault, name, "ts-orch mesh record",
		func(context.Context) (string, error) { return value, nil })
	return err
}

func (r vaultRecords) Swap(ctx context.Context, name string, version int64, value string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	clients, current, err := r.current(ctx, name)
	if err != nil {
		return err
	}
	if current.Version != version {
		return errRecordMoved
	}
	_, err = vaultsecret.Publish(ctx, clients.factory, vaultsecret.Ref{Vault: vaultID, Name: name}, current.ID, version, []byte(value))
	return err
}
