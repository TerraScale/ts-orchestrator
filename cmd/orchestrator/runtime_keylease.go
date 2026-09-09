package main

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/byokauthority"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

const (
	keyLeaseSocketEnvironment  = "TS_ORCH_KEY_LEASE_SOCKET_FILE"
	keyLeaseCatalogEnvironment = "TS_ORCH_KEY_LEASE_CATALOG_FILE"
	keyLeaseEnvironment        = "TS_ORCH_KEY_LEASE_ENVIRONMENT"
	keyLeaseUIDEnvironment     = "TS_ORCH_KEY_LEASE_PEER_UID"
	keyLeaseGIDEnvironment     = "TS_ORCH_KEY_LEASE_SOCKET_GID"
	byokRoleEnvironment        = "TS_ORCH_BYOK_ROLE_ARN"
	byokTokenEnvironment       = "TS_ORCH_BYOK_OIDC_TOKEN_FILE"
	byokKeyIDEnvironment       = "TS_ORCH_BYOK_KEY_ID"
	byokKeyRegionEnvironment   = "TS_ORCH_BYOK_KEY_REGION"
	byokKeyEndpointEnvironment = "TS_ORCH_BYOK_KEY_ENDPOINT"
	byokProviderEnvironment    = "TS_ORCH_BYOK_PROVIDER"
)

func configuredKeyProvisioner(lookup envLookup) func(context.Context, string, []keylease.ProvisionTarget) error {
	return func(ctx context.Context, path string, targets []keylease.ProvisionTarget) error {
		if len(targets) == 0 || targets[0].Provider != "aws-kms" {
			return keylease.Provision(ctx, path, targets)
		}
		role, _ := lookup(byokRoleEnvironment)
		token, _ := lookup(byokTokenEnvironment)
		keyID, _ := lookup(byokKeyIDEnvironment)
		keyRegion, _ := lookup(byokKeyRegionEnvironment)
		if role == "" || token == "" || keyID == "" || keyRegion == "" {
			return keylease.ErrUnavailable
		}
		authority, err := byokauthority.New(ctx, byokauthority.Config{Region: keyRegion, RoleARN: role, OIDCTokenFile: token, KeyARN: keyID, SessionName: "terrascale-key-provision"})
		if err != nil {
			return keylease.ErrUnavailable
		}
		return keylease.ProvisionWithWrap(ctx, path, targets, func(ctx context.Context, target keylease.ProvisionTarget, key []byte) (string, error) {
			return authority.Wrap(ctx, byokauthority.Binding{Environment: target.Binding.Environment, TenantID: target.Binding.TenantID, ProjectID: target.Binding.ProjectID, DatabaseID: target.Binding.DatabaseID, KeyVersion: target.Binding.KeyVersion, Region: target.Binding.Region, Purpose: target.Binding.Purpose}, key)
		})
	}
}

type customerAuthorityAdapter struct{ authority *byokauthority.Authority }

func (a customerAuthorityAdapter) Unwrap(ctx context.Context, binding keylease.Binding, ciphertext string) (*hostsecrets.DataKey, error) {
	return a.authority.Unwrap(ctx, byokauthority.Binding{Environment: binding.Environment, TenantID: binding.TenantID, ProjectID: binding.ProjectID, DatabaseID: binding.DatabaseID, KeyVersion: binding.KeyVersion, Region: binding.Region, Purpose: binding.Purpose}, ciphertext)
}

func startConfiguredKeyLease(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (*keylease.Server, error) {
	if options.Cell == "local" {
		return nil, nil
	}
	socket, _ := lookup(keyLeaseSocketEnvironment)
	catalog, _ := lookup(keyLeaseCatalogEnvironment)
	environment, _ := lookup(keyLeaseEnvironment)
	peer, _ := lookup(keyLeaseUIDEnvironment)
	group, _ := lookup(keyLeaseGIDEnvironment)
	gid, gidErr := strconv.ParseUint(group, 10, 32)
	uid, err := strconv.ParseUint(peer, 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != peer || gidErr != nil || strconv.FormatUint(gid, 10) != group || socket == "" || catalog == "" || environment == "" {
		return nil, errors.New("orchestrator: local Vault key lease configuration unavailable")
	}
	keyConfig := keylease.Config{SocketPath: socket, CatalogPath: catalog, Environment: environment, Region: strings.ToUpper(options.Cell), AllowedUID: uint32(uid), SocketGID: uint32(gid)}
	role, _ := lookup(byokRoleEnvironment)
	if role != "" {
		token, _ := lookup(byokTokenEnvironment)
		keyID, _ := lookup(byokKeyIDEnvironment)
		keyRegion, _ := lookup(byokKeyRegionEnvironment)
		endpoint, _ := lookup(byokKeyEndpointEnvironment)
		provider, _ := lookup(byokProviderEnvironment)
		if provider != "aws-kms" || token == "" || keyID == "" || keyRegion == "" || endpoint == "" {
			return nil, errors.New("orchestrator: customer BYOK requires explicit AWS configuration")
		}
		authority, authorityErr := byokauthority.New(ctx, byokauthority.Config{Region: keyRegion, RoleARN: role, OIDCTokenFile: token, KeyARN: keyID, SessionName: "terrascale-keylease"})
		if authorityErr != nil {
			return nil, errors.New("orchestrator: customer BYOK authority unavailable")
		}
		keyConfig.Customer = &keylease.CustomerConfig{Authority: customerAuthorityAdapter{authority: authority}, Provider: provider, KeyID: keyID, KeyRegion: keyRegion, KeyEndpoint: endpoint}
	}
	service, err := keylease.Start(ctx, keyConfig)
	if err != nil {
		return nil, errors.New("orchestrator: local Vault key lease service unavailable")
	}
	return service, nil
}
