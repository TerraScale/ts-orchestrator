package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorizationlease"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
)

type productionRotationEdgeFile struct {
	AuthorizationLeaseAudience string          `json:"authorization_lease_audience"`
	AuthorizationLeaseKeysFile string          `json:"authorization_lease_keys_file"`
	AccountID                  string          `json:"account_id"`
	ZoneID                     string          `json:"zone_id"`
	TokenFile                  string          `json:"token_file"`
	TemplateFile               string          `json:"template_file"`
	TemplateService            string          `json:"template_service"`
	SnippetName                string          `json:"snippet_name"`
	Zone                       cloudflare.Zone `json:"zone"`
	ProbeURLs                  []string        `json:"probe_urls"`
	JournalBucket              string          `json:"journal_bucket"`
	JournalKey                 string          `json:"journal_key"`
}

type productionRotationFile struct {
	Issuer      keyrotation.OCIIdentityIssuerFileConfig   `json:"issuer"`
	Vault       keyrotation.OCICapabilityVaultFileConfig  `json:"vault"`
	OriginVault keyrotation.OCIOriginProofVaultFileConfig `json:"origin_vault"`
	Members     keyrotation.MemberGatewayFileConfig       `json:"members"`
	Reloaders   keyrotation.MemberGatewayFileConfig       `json:"reloaders"`
	Edge        productionRotationEdgeFile                `json:"edge"`
	Regions     []string                                  `json:"regions"`
}

func (f productionRotationFile) Admit() error {
	if err := f.Issuer.Validate(); err != nil {
		return fmt.Errorf("rotation issuer: %w", err)
	}
	if err := f.Vault.Validate(); err != nil {
		return fmt.Errorf("rotation vault: %w", err)
	}
	if err := f.OriginVault.Validate(); err != nil {
		return fmt.Errorf("rotation origin-proof vault: %w", err)
	}
	if err := f.admitPrincipals(); err != nil {
		return err
	}
	if err := f.Members.Validate(); err != nil {
		return fmt.Errorf("rotation members: %w", err)
	}
	if err := f.Reloaders.Validate(); err != nil {
		return fmt.Errorf("rotation reloaders: %w", err)
	}
	return f.Edge.admit()
}

// Every issued identity must have exactly one declared consumer. Every region
// must include member and control consumers before a rotation can be scheduled.
func (f productionRotationFile) admitPrincipals() error {
	invalid := errors.New("rotation principals and regional consumers must match exactly")
	regions := map[string]bool{}
	for _, region := range f.Regions {
		if !deliveryScopePart(region) || strings.ToLower(region) != region || regions[region] {
			return invalid
		}
		regions[region] = true
	}
	if len(regions) == 0 {
		return invalid
	}
	principals := map[string]bool{}
	for _, principal := range f.Issuer.Principals {
		principals[principal.ID] = principal.Control
	}
	seen := map[string]bool{}
	for _, group := range []struct {
		control   bool
		endpoints []keyrotation.MemberEndpoint
	}{{false, f.Members.Members}, {true, f.Reloaders.Members}} {
		covered := map[string]bool{}
		for _, endpoint := range group.endpoints {
			control, exists := principals[endpoint.ID]
			if !exists || control != group.control || seen[endpoint.ID] || !regions[endpoint.Region] {
				return invalid
			}
			seen[endpoint.ID], covered[endpoint.Region] = true, true
		}
		if len(covered) != len(regions) {
			return invalid
		}
	}
	if len(seen) != len(principals) {
		return invalid
	}
	return nil
}

func (f productionRotationEdgeFile) read() ([]byte, []byte, error) {
	token, err := bootstrapcredentials.ReadFile(f.TokenFile, true, 4096)
	if err != nil {
		return nil, nil, err
	}
	source, err := bootstrapcredentials.ReadFile(f.TemplateFile, false, 4<<20)
	if err != nil {
		clear(token)
		return nil, nil, err
	}
	if strings.TrimSpace(string(token)) == "" || strings.ContainsAny(strings.TrimSpace(string(token)), "\r\n\x00 \t") {
		clear(token)
		clear(source)
		return nil, nil, errors.New("rotation Cloudflare token is invalid")
	}
	return token, source, nil
}

func (f productionRotationEdgeFile) admit() error {
	if authorizationlease.ValidateAudience(f.AuthorizationLeaseAudience) != nil {
		return authorizationlease.ErrInvalid
	}
	keys, err := authorizationlease.Read(f.AuthorizationLeaseKeysFile)
	if err != nil || !keys.Active(time.Now().Unix()) {
		return authorizationlease.ErrInvalid
	}
	if !rotationCloudflareID(f.AccountID) || !rotationCloudflareID(f.ZoneID) || f.TemplateService != "ts-proxy" || f.SnippetName != cloudflare.GateSnippetName || f.Zone.ZoneName != cloudflare.ZoneName || !rotationJournalName(f.JournalBucket, false) || !rotationJournalName(f.JournalKey, true) {
		return errors.New("rotation edge requires exact provider, template and journal scope")
	}
	token, source, err := f.read()
	if err != nil {
		return err
	}
	defer clear(token)
	defer clear(source)
	return cloudflare.ValidateCapabilityDeployment(source, &f.Zone, f.SnippetName, f.ProbeURLs)
}
func rotationCloudflareID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func rotationJournalName(value string, dots bool) bool {
	if len(value) == 0 || len(value) > 128 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || dots && c == '.') {
			return false
		}
	}
	return true
}

// Construct binds all effects to the current global lease. The returned store
// is also the release promoter: publishing a template must retain the live ring.
func (f productionRotationFile) Construct(ctx context.Context, session globalWorkerSession, artifacts cloudflare.EdgeArtifactSource) (keyrotation.Config, *cloudflare.SnippetCapabilityStore, func() error, error) {
	var config keyrotation.Config
	var cleanup []func() error
	closeAll := sync.OnceValue(func() error {
		var result error
		for i := len(cleanup) - 1; i >= 0; i-- {
			result = errors.Join(result, cleanup[i]())
		}
		return result
	})
	fail := func(err error) (keyrotation.Config, *cloudflare.SnippetCapabilityStore, func() error, error) {
		return keyrotation.Config{}, nil, closeAll, err
	}
	if err := f.Admit(); err != nil {
		return fail(err)
	}
	if ctx == nil || session.check == nil || artifacts == nil || session.Lease.Epoch <= 0 || session.Lease.LeaseId == "" {
		return fail(errors.New("rotation requires live global authority and shared verified artifacts"))
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return fail(err)
	}
	credentials, err := hostsecrets.NewInstanceConfiguration(ctx, f.Vault.Region)
	if err != nil {
		return fail(err)
	}
	vault, err := keyrotation.NewOCICapabilityVault(keyrotation.OCICapabilityVaultConfig{Provider: credentials, Region: f.Vault.Region, CompartmentID: f.Vault.CompartmentID, VaultID: f.Vault.VaultID, KeyID: f.Vault.KeyID, Authority: session.CheckEffectAuthority})
	if err != nil {
		return fail(err)
	}
	originCredentials := credentials
	if f.OriginVault.Region != f.Vault.Region {
		originCredentials, err = hostsecrets.NewInstanceConfiguration(ctx, f.OriginVault.Region)
		if err != nil {
			return fail(err)
		}
	}
	originVault, err := keyrotation.NewOCIOriginProofVault(keyrotation.OCIOriginProofVaultConfig{Provider: originCredentials, Region: f.OriginVault.Region, CompartmentID: f.OriginVault.CompartmentID, VaultID: f.OriginVault.VaultID, KeyID: f.OriginVault.KeyID, Authority: session.CheckEffectAuthority})
	if err != nil {
		return fail(err)
	}
	issuerCredentials := credentials
	if f.Issuer.Region != f.Vault.Region {
		issuerCredentials, err = hostsecrets.NewInstanceConfiguration(ctx, f.Issuer.Region)
		if err != nil {
			return fail(err)
		}
	}
	issuer, err := keyrotation.NewOCIIdentityIssuer(keyrotation.OCIIdentityIssuerConfig{Provider: issuerCredentials, Region: f.Issuer.Region, CompartmentID: f.Issuer.CompartmentID, CertificateAuthorityID: f.Issuer.CertificateAuthorityID, Principals: slices.Clone(f.Issuer.Principals), KeyVault: vault, Authority: session.CheckEffectAuthority})
	if err != nil {
		return fail(err)
	}
	members, err := f.Members.OpenForLease(session.CheckEffectAuthority, uint64(session.Lease.Epoch), session.Lease.LeaseId)
	if err != nil {
		return fail(err)
	}
	cleanup = append(cleanup, members.Close)
	reloaders, err := f.Reloaders.OpenReloaderForLease(session.CheckEffectAuthority, uint64(session.Lease.Epoch), session.Lease.LeaseId)
	if err != nil {
		return fail(err)
	}
	cleanup = append(cleanup, reloaders.Close)
	journal, err := cloudflare.NewNATSCapabilityJournal(ctx, cloudflare.NATSCapabilityJournalConfig{Connection: session.Connection, Bucket: f.Edge.JournalBucket, Key: f.Edge.JournalKey})
	if err != nil {
		return fail(err)
	}
	token, source, err := f.Edge.read()
	if err != nil {
		return fail(err)
	}
	defer clear(token)
	defer clear(source)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 15 * time.Second
	cleanup = append(cleanup, func() error { transport.CloseIdleConnections(); return nil })
	client := cloudflare.NewClient(strings.TrimSpace(string(token)), f.Edge.ZoneID, f.Edge.AccountID)
	guardedTransport := rotationAuthorityTransport{transport: transport, check: session.CheckEffectAuthority}
	client.HTTP = guardedTransport
	cleanup = append(cleanup, func() error { client.Token = ""; return nil })
	leaseKeys, err := authorizationlease.Read(f.Edge.AuthorizationLeaseKeysFile)
	if err != nil {
		return fail(err)
	}
	store, err := cloudflare.NewSnippetCapabilityStore(cloudflare.SnippetCapabilityStoreConfig{AuthorizationLeaseAudience: f.Edge.AuthorizationLeaseAudience, AuthorizationLeaseKeys: leaseKeys, Artifacts: artifacts, TemplateService: f.Edge.TemplateService, Zone: &f.Edge.Zone, Client: client, SnippetName: f.Edge.SnippetName, Source: source, Vault: vault, OriginVault: originVault, Journal: journal, Authorize: session.CheckEffectAuthority, ProbeURLs: f.Edge.ProbeURLs, HTTPClient: &http.Client{Transport: guardedTransport, Timeout: 20 * time.Second}, Now: time.Now})
	if err != nil {
		return fail(err)
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return fail(err)
	}
	config = keyrotation.Config{Issuer: issuer, Vault: vault, OriginProof: originVault, Members: members, Reloader: reloaders, Secrets: store, Regions: slices.Clone(f.Regions), Clock: time.Now}
	return config, store, closeAll, nil
}

// Cloudflare retries pass through the lease check at every network dispatch.
type rotationAuthorityTransport struct {
	transport http.RoundTripper
	check     func(context.Context) error
}

func (r rotationAuthorityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := r.check(request.Context()); err != nil {
		return nil, err
	}
	return r.transport.RoundTrip(request)
}
