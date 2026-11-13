package callerkey

import (
	"context"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type vaultStore struct{}

func (vaultStore) Read(ctx context.Context, t Target, name string) (Snapshot, error) {
	factory, err := ociclient.OperatorConfig(strings.Split(t.Vault, ".")[3])
	if err != nil {
		return Snapshot{}, errors.New("caller-key operator credentials unavailable")
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return Snapshot{}, errors.New("caller-key Vault client unavailable")
	}
	current, err := vaultsecret.ReadCurrent(ctx, bundles, vaultsecret.Ref{Vault: t.Vault, Name: name})
	if vaultsecret.Absent(err) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{ID: current.ID, Version: current.Version, Value: []byte(current.Value())}, nil
}

func (vaultStore) Write(ctx context.Context, t Target, name string, previous Snapshot, value []byte) error {
	factory, err := ociclient.OperatorConfig(strings.Split(t.Vault, ".")[3])
	if err != nil {
		return errors.New("caller-key operator credentials unavailable")
	}
	if previous.Version > 0 {
		_, err := vaultsecret.Publish(ctx, factory, vaultsecret.Ref{Vault: t.Vault, Name: name}, previous.ID, previous.Version, value)
		return err
	}
	client, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return errors.New("caller-key Vault client unavailable")
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return errors.New("caller-key Vault bundle client unavailable")
	}
	_, err = vaultsecret.Put(ctx, client, bundles, vaultsecret.Target{VaultID: t.Vault, KeyID: t.Key, CompartmentID: t.Compartment}, name, value)
	return err
}
