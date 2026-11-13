package callerkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
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

func (vaultStore) Regions(ctx context.Context) ([]string, error) {
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.Bootstrap))
	if err != nil {
		return nil, errors.New("caller-key operator credentials unavailable")
	}
	resolver, err := region.DiscoverCurrentFoundation(ctx, factory)
	if err != nil {
		return nil, err
	}
	approved, err := resolver.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return nil, err
	}
	cells := make([]string, 0, len(approved.Regions))
	for _, intent := range approved.Regions {
		cell, ok := intent.Plan["cell"].(string)
		if !ok {
			return nil, errors.New("authenticated footprint has an invalid cell")
		}
		cells = append(cells, cell)
	}
	return cells, nil
}

func vaultClients(t Target) (ocivault.VaultsClient, ocisecrets.SecretsClient, error) {
	factory, err := ociclient.OperatorConfig(strings.Split(t.Vault, ".")[3])
	if err != nil {
		return ocivault.VaultsClient{}, ocisecrets.SecretsClient{}, errors.New("caller-key operator credentials unavailable")
	}
	client, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return client, ocisecrets.SecretsClient{}, errors.New("caller-key Vault client unavailable")
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	return client, bundles, err
}

func (vaultStore) Private(ctx context.Context, t Target, name string) (PrivateState, error) {
	client, bundles, err := vaultClients(t)
	if err != nil {
		return PrivateState{}, err
	}
	ctx = ociclient.RequestContext(ctx)
	current, err := vaultsecret.ReadCurrent(ctx, bundles, vaultsecret.Ref{Vault: t.Vault, Name: name})
	if vaultsecret.Absent(err) {
		return PrivateState{}, nil
	}
	if err != nil {
		return PrivateState{}, err
	}
	state := PrivateState{Current: Snapshot{ID: current.ID, Version: current.Version, Value: []byte(current.Value())}}
	complete := false
	defer func() {
		if !complete {
			state.Clear()
		}
	}()
	before, err := client.GetSecret(ctx, ocivault.GetSecretRequest{SecretId: new(current.ID)})
	if err != nil || before.Id == nil || *before.Id != current.ID || before.VaultId == nil || *before.VaultId != t.Vault || before.SecretName == nil || *before.SecretName != name || before.LifecycleState != ocivault.SecretLifecycleStateActive || before.CurrentVersionNumber == nil || *before.CurrentVersionNumber != current.Version || before.Etag == nil || *before.Etag == "" {
		return PrivateState{}, errors.New("caller-key private metadata differs from the current regional secret")
	}
	state.Etag = *before.Etag
	var page *string
	foundCurrent := false
	for {
		versions, err := client.ListSecretVersions(ctx, ocivault.ListSecretVersionsRequest{SecretId: new(current.ID), Page: page})
		if err != nil {
			return PrivateState{}, errors.New("caller-key private version inventory unavailable")
		}
		for _, v := range versions.Items {
			if v.SecretId == nil || *v.SecretId != current.ID || v.VersionNumber == nil || *v.VersionNumber < 1 {
				return PrivateState{}, errors.New("caller-key private version inventory invalid")
			}
			bundle, err := bundles.GetSecretBundle(ctx, ocisecrets.GetSecretBundleRequest{SecretId: new(current.ID), VersionNumber: v.VersionNumber})
			if err != nil || bundle.SecretId == nil || *bundle.SecretId != current.ID || bundle.VersionNumber == nil || *bundle.VersionNumber != *v.VersionNumber {
				return PrivateState{}, errors.New("caller-key private version content unavailable")
			}
			value, err := privateBundle(bundle.SecretBundle)
			if err != nil {
				return PrivateState{}, err
			}
			pending := slices.Contains(v.Stages, ocivault.SecretVersionSummaryStagesPending)
			state.Versions = append(state.Versions, KeyVersion{Snapshot: Snapshot{ID: current.ID, Version: *v.VersionNumber, Value: value}, Pending: pending})
			if *v.VersionNumber == current.Version {
				if !bytes.Equal(value, state.Current.Value) || !slices.Contains(v.Stages, ocivault.SecretVersionSummaryStagesCurrent) {
					return PrivateState{}, errors.New("caller-key current version changed during inventory")
				}
				foundCurrent = true
			}
		}
		page = versions.OpcNextPage
		if page == nil || *page == "" {
			break
		}
	}
	after, err := client.GetSecret(ctx, ocivault.GetSecretRequest{SecretId: new(current.ID)})
	if err != nil || after.Etag == nil || *after.Etag != state.Etag || !foundCurrent {
		return PrivateState{}, errors.New("caller-key private versions changed during inventory; reread before writing")
	}
	complete = true
	return state, nil
}

func privateBundle(bundle ocisecrets.SecretBundle) ([]byte, error) {
	var content *string
	switch value := bundle.SecretBundleContent.(type) {
	case ocisecrets.Base64SecretBundleContentDetails:
		content = value.Content
	case *ocisecrets.Base64SecretBundleContentDetails:
		if value != nil {
			content = value.Content
		}
	}
	if content == nil || len(*content) > base64.StdEncoding.EncodedLen(16384) {
		return nil, errors.New("caller-key private bundle content invalid")
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*content)
	if err != nil {
		return nil, errors.New("caller-key private bundle encoding invalid")
	}
	return value, nil
}

func (s vaultStore) Stage(ctx context.Context, t Target, name string, before PrivateState, value []byte) error {
	client, _, err := vaultClients(t)
	if err != nil {
		return err
	}
	if before.Current.Version < 1 || before.Etag == "" {
		return errors.New("pending publication requires an existing current secret")
	}
	content := base64.StdEncoding.EncodeToString(value)
	_, err = client.UpdateSecret(ociclient.RequestContext(ctx), ocivault.UpdateSecretRequest{
		SecretId: new(before.Current.ID), IfMatch: new(before.Etag),
		UpdateSecretDetails: ocivault.UpdateSecretDetails{SecretContent: ocivault.Base64SecretContentDetails{Content: new(content), Stage: ocivault.SecretContentDetailsStagePending}},
	})
	if err != nil {
		return errors.New("caller-key pending publication failed; reread before writing")
	}
	after, err := s.Private(ctx, t, name)
	if err != nil {
		return err
	}
	defer after.Clear()
	matched := false
	for _, version := range after.Versions {
		if version.Pending && bytes.Equal(version.Value, value) {
			matched = true
		}
	}
	if after.Current.Version != before.Current.Version || !bytes.Equal(after.Current.Value, before.Current.Value) || !matched {
		return errors.New("caller-key pending publication readback differs; reread before writing")
	}
	return nil
}

func (s vaultStore) Activate(ctx context.Context, t Target, name string, before PrivateState, version int64) error {
	client, _, err := vaultClients(t)
	if err != nil {
		return err
	}
	var expected []byte
	for _, v := range before.Versions {
		if v.Version == version && v.Pending {
			expected = v.Value
		}
	}
	if before.Etag == "" || len(expected) == 0 {
		return errors.New("activation requires a pending version and conditional metadata")
	}
	_, err = client.UpdateSecret(ociclient.RequestContext(ctx), ocivault.UpdateSecretRequest{
		SecretId: new(before.Current.ID), IfMatch: new(before.Etag),
		UpdateSecretDetails: ocivault.UpdateSecretDetails{CurrentVersionNumber: new(version)},
	})
	if err != nil {
		return errors.New("caller-key activation failed; reread before writing")
	}
	after, err := s.Private(ctx, t, name)
	if err != nil {
		return err
	}
	defer after.Clear()
	if after.Current.Version != version || !bytes.Equal(after.Current.Value, expected) {
		return errors.New("caller-key activation readback differs; reread before writing")
	}
	return nil
}
