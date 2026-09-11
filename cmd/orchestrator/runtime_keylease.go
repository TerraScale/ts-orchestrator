package main

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/byokauthority"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

const (
	keyLeaseSocketEnvironment      = "TS_ORCH_KEY_LEASE_SOCKET_FILE"
	keyLeaseCatalogEnvironment     = "TS_ORCH_KEY_LEASE_CATALOG_FILE"
	keyLeaseEnvironment            = "TS_ORCH_KEY_LEASE_ENVIRONMENT"
	keyLeaseUIDEnvironment         = "TS_ORCH_KEY_LEASE_PEER_UID"
	keyLeaseGIDEnvironment         = "TS_ORCH_KEY_LEASE_SOCKET_GID"
	byokRoleEnvironment            = "TS_ORCH_BYOK_ROLE_ARN"
	byokTokenEnvironment           = "TS_ORCH_BYOK_OIDC_TOKEN_FILE"
	byokKeyIDEnvironment           = "TS_ORCH_BYOK_KEY_ID"
	byokKeyRegionEnvironment       = "TS_ORCH_BYOK_KEY_REGION"
	byokKeyEndpointEnvironment     = "TS_ORCH_BYOK_KEY_ENDPOINT"
	byokProviderEnvironment        = "TS_ORCH_BYOK_PROVIDER"
	byokS3RoleEnvironment          = "TS_ORCH_BYOK_S3_ROLE_ARN"
	byokS3TokenEnvironment         = "TS_ORCH_BYOK_S3_OIDC_TOKEN_FILE"
	byokS3EndpointEnvironment      = "TS_ORCH_BYOK_S3_ENDPOINT"
	byokS3BucketEnvironment        = "TS_ORCH_BYOK_S3_BUCKET"
	byokS3RegionEnvironment        = "TS_ORCH_BYOK_S3_REGION"
	byokS3RevisionEnvironment      = "TS_ORCH_BYOK_S3_PLACEMENT_REVISION"
	byokS3TenantEnvironment        = "TS_ORCH_BYOK_S3_TENANT_ID"
	byokS3ProjectEnvironment       = "TS_ORCH_BYOK_S3_PROJECT_ID"
	byokS3DatabaseEnvironment      = "TS_ORCH_BYOK_S3_DATABASE_ID"
	byokS3ExternalIDEnvironment    = "TS_ORCH_BYOK_S3_EXTERNAL_ID"
	byokRenewalEndpointEnvironment = "TS_ORCH_BYOK_RENEWAL_POLICY_URL"
	byokRenewalKeyEnvironment      = "TS_ORCH_BYOK_RENEWAL_POLICY_KEY"
)

type workloadIssuerAdapter struct{ issuer *byokauthority.WorkloadIssuer }

func (a workloadIssuerAdapter) Issue(ctx context.Context, scope keylease.WorkloadIdentityScope) (keylease.WorkloadIdentityCredentials, error) {
	value, err := a.issuer.Issue(ctx, byokauthority.WorkloadScope{Environment: scope.Environment, TenantID: scope.TenantID, ProjectID: scope.ProjectID, DatabaseID: scope.DatabaseID, Role: scope.Role, ExternalID: scope.ExternalID, Endpoint: scope.Endpoint, Bucket: scope.Bucket, Region: scope.Region, PlacementRevision: scope.PlacementRevision})
	if err != nil {
		return keylease.WorkloadIdentityCredentials{}, err
	}
	return keylease.WorkloadIdentityCredentials{AccessKey: value.AccessKey, SecretKey: value.SecretKey, SessionToken: value.SessionToken, ExpiresAtUnixSeconds: value.ExpiresAtUnixSeconds}, nil
}

func configuredKeyProvisioner(lookup envLookup) func(context.Context, string, []keylease.ProvisionTarget) error {
	return func(ctx context.Context, path string, targets []keylease.ProvisionTarget) error {
		if len(targets) == 0 {
			return keylease.Provision(ctx, path, targets)
		}
		provider := targets[0].Provider
		for _, target := range targets {
			if target.Provider != provider || provider != "" && provider != "aws-kms" {
				return keylease.ErrUnavailable
			}
		}
		if provider == "" {
			return keylease.Provision(ctx, path, targets)
		}
		role, _ := lookup(byokRoleEnvironment)
		token, _ := lookup(byokTokenEnvironment)
		keyID, _ := lookup(byokKeyIDEnvironment)
		keyRegion, _ := lookup(byokKeyRegionEnvironment)
		keyEndpoint, _ := lookup(byokKeyEndpointEnvironment)
		if role == "" || token == "" || keyID == "" || keyRegion == "" {
			return keylease.ErrUnavailable
		}
		if keyEndpoint != "" && !validKeyAuthorityEndpoint(keyEndpoint) {
			return keylease.ErrUnavailable
		}
		for _, target := range targets {
			if target.Provider != "aws-kms" || target.KeyID != keyID || target.KeyRegion != keyRegion || target.KeyEndpoint != keyEndpoint {
				return keylease.ErrUnavailable
			}
		}
		authority, err := byokauthority.New(ctx, byokauthority.Config{Region: keyRegion, RoleARN: role, OIDCTokenFile: token, KeyARN: keyID, Endpoint: keyEndpoint, SessionName: "terrascale-key-provision"})
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
	token, _ := lookup(byokTokenEnvironment)
	keyID, _ := lookup(byokKeyIDEnvironment)
	keyRegion, _ := lookup(byokKeyRegionEnvironment)
	endpoint, _ := lookup(byokKeyEndpointEnvironment)
	provider, _ := lookup(byokProviderEnvironment)
	if role != "" || token != "" || keyID != "" || keyRegion != "" || endpoint != "" || provider != "" {
		if provider != "aws-kms" || role == "" || token == "" || keyID == "" || keyRegion == "" || (endpoint != "" && !validKeyAuthorityEndpoint(endpoint)) {
			return nil, errors.New("orchestrator: customer BYOK requires explicit AWS configuration")
		}
		authority, authorityErr := byokauthority.New(ctx, byokauthority.Config{Region: keyRegion, RoleARN: role, OIDCTokenFile: token, KeyARN: keyID, Endpoint: endpoint, SessionName: "terrascale-keylease"})
		if authorityErr != nil {
			return nil, errors.New("orchestrator: customer BYOK authority unavailable")
		}
		keyConfig.Customer = &keylease.CustomerConfig{Authority: customerAuthorityAdapter{authority: authority}, Provider: provider, KeyID: keyID, KeyRegion: keyRegion, KeyEndpoint: endpoint}
		renewalEndpoint, _ := lookup(byokRenewalEndpointEnvironment)
		renewalKey, _ := lookup(byokRenewalKeyEnvironment)
		checker, checkerErr := newRenewalPolicyChecker(renewalEndpoint, renewalKey)
		if checkerErr != nil {
			return nil, errors.New("orchestrator: customer BYOK renewal policy unavailable")
		}
		keyConfig.RenewalPolicy = checker
	}
	s3Role, _ := lookup(byokS3RoleEnvironment)
	s3Token, _ := lookup(byokS3TokenEnvironment)
	s3Endpoint, _ := lookup(byokS3EndpointEnvironment)
	s3Bucket, _ := lookup(byokS3BucketEnvironment)
	s3Region, _ := lookup(byokS3RegionEnvironment)
	s3Revision, _ := lookup(byokS3RevisionEnvironment)
	s3Tenant, _ := lookup(byokS3TenantEnvironment)
	s3Project, _ := lookup(byokS3ProjectEnvironment)
	s3Database, _ := lookup(byokS3DatabaseEnvironment)
	s3ExternalID, _ := lookup(byokS3ExternalIDEnvironment)
	s3Configured := s3Role != "" || s3Token != "" || s3Endpoint != "" || s3Bucket != "" || s3Region != "" || s3Revision != "" || s3Tenant != "" || s3Project != "" || s3Database != "" || s3ExternalID != ""
	if role != "" || token != "" || keyID != "" || keyRegion != "" || endpoint != "" || provider != "" {
		if !s3Configured {
			return nil, errors.New("orchestrator: customer BYOK requires explicit S3 workload identity configuration")
		}
	}
	if s3Configured {
		if s3Role == "" || s3Token == "" || s3Endpoint == "" || s3Bucket == "" || s3Region == "" || s3Revision == "" || s3Tenant == "" || s3Project == "" || s3Database == "" || !validKeyAuthorityEndpoint(s3Endpoint) {
			return nil, errors.New("orchestrator: customer S3 workload identity requires explicit scope")
		}
		var externalID *string
		if s3ExternalID != "" {
			externalID = &s3ExternalID
		}
		issuer, issuerErr := byokauthority.NewWorkloadIssuer(ctx, byokauthority.WorkloadConfig{Region: s3Region, RoleARN: s3Role, OIDCTokenFile: s3Token, SessionName: "terrascale-s3-workload", Allowed: byokauthority.WorkloadScope{Environment: environment, TenantID: s3Tenant, ProjectID: s3Project, DatabaseID: s3Database, Role: s3Role, ExternalID: externalID, Endpoint: s3Endpoint, Bucket: s3Bucket, Region: s3Region, PlacementRevision: s3Revision}})
		if issuerErr != nil {
			return nil, errors.New("orchestrator: customer S3 workload issuer unavailable")
		}
		keyConfig.WorkloadIdentity = workloadIssuerAdapter{issuer: issuer}
		if keyConfig.RenewalPolicy == nil {
			renewalEndpoint, _ := lookup(byokRenewalEndpointEnvironment)
			renewalKey, _ := lookup(byokRenewalKeyEnvironment)
			checker, checkerErr := newRenewalPolicyChecker(renewalEndpoint, renewalKey)
			if checkerErr != nil {
				return nil, errors.New("orchestrator: customer S3 renewal policy unavailable")
			}
			keyConfig.RenewalPolicy = checker
		}
	}
	service, err := keylease.Start(ctx, keyConfig)
	if err != nil {
		return nil, errors.New("orchestrator: local Vault key lease service unavailable")
	}
	return service, nil
}

func validKeyAuthorityEndpoint(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
