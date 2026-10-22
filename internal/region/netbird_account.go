package region

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

const netBirdOwnerPasswordName = "gru-1-netbird-owner-password"
const netBirdAccountPATName = "gru-1-netbird-admin-pat"

// NetBirdAccountAuthority is a separate forward-signed account purpose.
// The original four config-material purposes never imply this authority.
type NetBirdAccountAuthority struct {
	SchemaVersion      int                           `json:"schemaVersion"`
	InstallationID     string                        `json:"installationId"`
	TenancyID          string                        `json:"tenancyId"`
	StoreGeneration    string                        `json:"storeGeneration"`
	ManagerSlotID      string                        `json:"managerSlotId"`
	ManagerOperationID string                        `json:"managerOperationId"`
	Target             bootstrapmaterial.VaultTarget `json:"target"`
	OwnerPasswordName  string                        `json:"ownerPasswordName"`
	ManagementPATName  string                        `json:"managementPatName"`
	OwnerEmail         string                        `json:"ownerEmail"`
	ServiceName        string                        `json:"serviceName"`
}

func newNetBirdAccountAuthority(installation, tenancy string, material NetBirdMaterialAuthority) (NetBirdAccountAuthority, error) {
	if material.validate() != nil || material.Context.InstallationID != installation || material.Context.TenancyID != tenancy {
		return NetBirdAccountAuthority{}, errors.New("NetBird account requires the exact original material context")
	}
	c := material.Context
	return NetBirdAccountAuthority{SchemaVersion: 1, InstallationID: installation, TenancyID: tenancy,
		StoreGeneration: c.StoreGeneration, ManagerSlotID: c.ManagerSlotID, ManagerOperationID: c.ManagerOperationID,
		Target: c.Target, OwnerPasswordName: netBirdOwnerPasswordName, ManagementPATName: netBirdAccountPATName,
		OwnerEmail: "netbird-owner@terrascale.tech", ServiceName: "ts-orchestrator"}, nil
}

func validateFoundationNetBirdAccount(grant FoundationGrant) error {
	for _, regional := range grant.Regions {
		m := regional.NetBirdManager
		if m == nil || m.Account == nil {
			continue
		}
		if grant.SchemaVersion != 3 || grant.Generation != 1 || regional.Plan["cell"] != "GRU" || m.StoreOrigin != "new" || m.Material == nil {
			return errors.New("NetBird account purpose requires a fresh original signed manager")
		}
		expected, err := newNetBirdAccountAuthority(grant.InstallationID, grant.TenancyID, *m.Material)
		if err != nil || *m.Account != expected {
			return errors.New("NetBird account purpose differs from its exact original scope")
		}
	}
	return nil
}

// NetBirdAccountJournal contains references and dispatch evidence, never secrets.
type NetBirdAccountJournal struct {
	Authority  NetBirdAccountAuthority `json:"authority"`
	BornAt     time.Time               `json:"bornAt"`
	Password   NetBirdMaterialCreate   `json:"password"`
	PAT        NetBirdMaterialCreate   `json:"pat"`
	PendingPAT *netBirdPATPublication  `json:"pendingPat,omitempty"`
}

type netBirdPATPublication struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	ContentSHA256   string `json:"contentSha256"`
}

func newNetBirdAccountJournal(a NetBirdAccountAuthority, bornAt time.Time) *NetBirdAccountJournal {
	return &NetBirdAccountJournal{Authority: a, BornAt: bornAt,
		Password: NetBirdMaterialCreate{Name: a.OwnerPasswordName}, PAT: NetBirdMaterialCreate{Name: a.ManagementPATName}}
}

func (j *NetBirdAccountJournal) validate(a *NetBirdAccountAuthority) error {
	if j == nil {
		if a != nil {
			return errors.New("signed NetBird account journal is missing")
		}
		return nil
	}
	if a == nil || j.Authority != *a || j.BornAt.IsZero() || a.SchemaVersion != 1 || a.OwnerPasswordName != netBirdOwnerPasswordName || a.ManagementPATName != netBirdAccountPATName || a.OwnerEmail != "netbird-owner@terrascale.tech" || a.ServiceName != "ts-orchestrator" || a.Target.Validate(foundationHomeRegion) != nil {
		return errors.New("NetBird account journal differs from its original signed authority")
	}
	for index, c := range [2]NetBirdMaterialCreate{j.Password, j.PAT} {
		name := a.OwnerPasswordName
		if index == 1 {
			name = a.ManagementPATName
		}
		if c.Name != name || (c.RequestSHA256 == "") != (c.RetryToken == "") ||
			c.RequestSHA256 != "" && (!validFoundationDigest(c.RequestSHA256) || c.RetryToken != BootstrapRetryToken(a.ManagerOperationID+":"+name, c.RequestSHA256)) ||
			!c.FirstDispatchedAt.IsZero() && (c.RequestSHA256 == "" || c.FirstDispatchedAt.Before(j.BornAt)) ||
			c.SecretID != "" && (c.FirstDispatchedAt.IsZero() || !workerSecretPattern.MatchString(c.SecretID) || !strings.HasPrefix(c.SecretID, "ocid1.vaultsecret.oc1."+foundationHomeRegion+".") || len(c.SecretID) > 512) ||
			c.Version < 0 || c.Version > 0 && (c.SecretID == "" || !validFoundationDigest(c.ContentSHA256)) ||
			c.Version == 0 && c.ContentSHA256 != "" || index == 0 && c.Version > 1 || c.HoldReason != "" {
			return errors.New("NetBird account checkpoint is malformed")
		}
	}
	if j.PendingPAT != nil && (j.PAT.Version < 1 || j.PendingPAT.ExpectedVersion != j.PAT.Version || !validFoundationDigest(j.PendingPAT.ContentSHA256) || j.PendingPAT.ContentSHA256 == j.PAT.ContentSHA256) {
		return errors.New("NetBird pending PAT differs from its retained CURRENT version")
	}
	return nil
}

func retainNetBirdAccount(old, next *NetBirdAccountJournal) error {
	if old == nil {
		if next != nil {
			return errors.New("existing manager cannot gain an account birth")
		}
		return nil
	}
	if next == nil || next.Authority != old.Authority || !next.BornAt.Equal(old.BornAt) || next.validate(&old.Authority) != nil {
		return errors.New("NetBird original account journal cannot be replaced")
	}
	for index, before := range [2]NetBirdMaterialCreate{old.Password, old.PAT} {
		after := [2]NetBirdMaterialCreate{next.Password, next.PAT}[index]
		if before.Name != after.Name || !retainedString(before.RequestSHA256, after.RequestSHA256) || !retainedString(before.RetryToken, after.RetryToken) ||
			!retainedString(before.SecretID, after.SecretID) || !before.FirstDispatchedAt.IsZero() && !before.FirstDispatchedAt.Equal(after.FirstDispatchedAt) ||
			before.Version > after.Version || before.Version == 0 && after.Version > 1 || index == 0 && before.Version > 0 && (before.Version != after.Version || before.ContentSHA256 != after.ContentSHA256) {
			return errors.New("NetBird account checkpoint regressed")
		}
		if index == 1 && before.Version > 0 && before.ContentSHA256 != after.ContentSHA256 &&
			(old.PendingPAT == nil || old.PendingPAT.ContentSHA256 != after.ContentSHA256 || after.Version != before.Version+1 || next.PendingPAT != nil) {
			return errors.New("NetBird PAT replacement lacks its prior durable publication")
		}
		if index == 1 && before.Version > 0 && before.ContentSHA256 == after.ContentSHA256 && before.Version != after.Version {
			return errors.New("NetBird PAT version advanced without a replacement")
		}
	}
	if old.PendingPAT != nil && next.PendingPAT != nil && *old.PendingPAT != *next.PendingPAT {
		return errors.New("NetBird pending PAT cannot change")
	}
	if old.PendingPAT != nil && next.PendingPAT == nil && (next.PAT.Version != old.PAT.Version+1 || next.PAT.ContentSHA256 != old.PendingPAT.ContentSHA256) {
		return errors.New("NetBird pending PAT cannot disappear")
	}
	return nil
}

// NetBirdAccount grants only the two names in the original signed account purpose.
type NetBirdAccount struct{ state *netBirdAccount }
type netBirdAccount struct {
	resolver   FoundationResolver
	reader     *SignedFootprint
	manager    VerifiedNetBirdManager
	material   NetBirdComponents
	authority  NetBirdAccountAuthority
	management vault.VaultsClient
	bundles    secrets.SecretsClient
}

func ReadNetBirdAccount(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager, material NetBirdComponents) (NetBirdAccount, error) {
	if factory == nil || factory.Region() != foundationHomeRegion || factory.Provider() == nil {
		return NetBirdAccount{}, errors.New("NetBird account requires the admitted home OCI provider")
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if os.Getenv(name) != "" {
			return NetBirdAccount{}, errors.New("NetBird account refuses secret-unsafe OCI environment")
		}
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return NetBirdAccount{}, errors.New("NetBird account requires original signed authority")
	}
	// The read below and the first account check verify the foundation once; nothing between writes it.
	ctx = withOriginalNetBirdStateMemo(ctx)
	state, err := reader.originalNetBirdState(ctx, resolver)
	if err != nil {
		return NetBirdAccount{}, err
	}
	if err = validateFoundationNetBirdAccount(state.grant); err != nil {
		return NetBirdAccount{}, err
	}
	a := state.intent.intent.Account
	if a == nil || state.manager == nil || state.manager.Launch == nil || state.manager.Launch.Account == nil || state.manager.Launch.Account.validate(a) != nil || manager.CredentialTarget() != state.target() || manager.StoreGeneration() != a.StoreGeneration {
		return NetBirdAccount{}, errors.New("NetBird account has no original signed birth or exact credential escrow")
	}
	management, err := vault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return NetBirdAccount{}, errors.New("NetBird account Vault unavailable")
	}
	management.SetRegion(foundationHomeRegion)
	factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	bundles, err := factory.SecretsContext(ctx)
	if err != nil {
		return NetBirdAccount{}, errors.New("NetBird account bundle client unavailable")
	}
	s := &netBirdAccount{resolver: resolver, reader: reader, manager: manager, material: material, authority: *a, management: management, bundles: bundles}
	if _, err = s.current(ctx); err != nil {
		return NetBirdAccount{}, err
	}
	return NetBirdAccount{state: s}, nil
}

func (s *netBirdAccount) current(ctx context.Context) (originalNetBirdState, error) {
	// One account check verifies the foundation, manager and material once; a
	// scope created here ends with this call, so callers may mutate the result.
	ctx = withOriginalNetBirdStateMemo(ctx)
	if err := s.manager.Check(ctx); err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.material.Check(ctx); err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.material.RetainReleaseFloors(ctx); err != nil {
		return originalNetBirdState{}, err
	}
	state, err := s.reader.originalNetBirdState(ctx, s.resolver)
	if err != nil {
		return state, err
	}
	if state.intent.intent.Account == nil || *state.intent.intent.Account != s.authority || s.manager.CredentialTarget() != state.target() || state.manager == nil || state.manager.Launch == nil || state.manager.Launch.Account.validate(&s.authority) != nil {
		return state, errors.New("NetBird account original authority changed")
	}
	// This full check is the operation's one request guard pass.
	if scope, _ := ctx.Value(netBirdAccountGuardKey{}).(*netBirdAccountGuardScope); scope != nil {
		scope.mu.Lock()
		scope.passed = true
		scope.mu.Unlock()
	}
	return state, nil
}

type netBirdAccountGuardKey struct{}

type netBirdAccountGuardScope struct {
	mu     sync.Mutex
	passed bool
}

// withNetBirdAccountGuardScope lets one account operation run its full
// request guard once; its later requests reuse that pass until expiry.
func withNetBirdAccountGuardScope(ctx context.Context) context.Context {
	if _, ok := ctx.Value(netBirdAccountGuardKey{}).(*netBirdAccountGuardScope); ok {
		return ctx
	}
	return context.WithValue(ctx, netBirdAccountGuardKey{}, &netBirdAccountGuardScope{})
}

func (s *netBirdAccount) requestContext(base context.Context) context.Context {
	return ociclient.WithRequestGuard(base, func(context.Context) error {
		scope, _ := base.Value(netBirdAccountGuardKey{}).(*netBirdAccountGuardScope)
		if scope != nil {
			scope.mu.Lock()
			passed := scope.passed
			scope.mu.Unlock()
			if passed {
				if !time.Now().Before(s.material.ExpiresAt()) {
					return errNetBirdComponents
				}
				return base.Err()
			}
		}
		_, err := s.current(base)
		return err
	})
}

func (s *netBirdAccount) checkpoint(ctx context.Context, state *originalNetBirdState) error {
	state.record.UpdatedAt = time.Now().UTC()
	etag, err := s.resolver.Store.CompareAndSwap(s.requestContext(ctx), state.record, state.etag)
	if err != nil {
		return errors.New("NetBird account checkpoint uncertain; reobserve original journal")
	}
	state.etag = etag
	return nil
}

// OwnerPassword returns an encoding of bytes generated inside OCI Vault.
func (v NetBirdAccount) OwnerPassword(ctx context.Context) ([]byte, error) {
	ctx = withNetBirdAccountGuardScope(ctx)
	if v.state == nil {
		return nil, errors.New("NetBird account authority absent")
	}
	s := v.state
	state, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	value, err := s.create(ctx, &state, false, nil)
	if err != nil {
		return nil, err
	}
	defer clear(value)
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(password, value)
	return password, nil
}

// CurrentPAT never treats a missing pinned version as permission to regenerate it.
func (v NetBirdAccount) CurrentPAT(ctx context.Context) (vaultsecret.Current, error) {
	ctx = withNetBirdAccountGuardScope(ctx)
	if v.state == nil {
		return vaultsecret.Current{}, errors.New("NetBird account authority absent")
	}
	s := v.state
	state, err := s.current(ctx)
	if err != nil {
		return vaultsecret.Current{}, err
	}
	j := state.manager.Launch.Account
	if j.PAT.Version == 0 {
		return vaultsecret.Current{}, ErrFoundationMissing
	}
	value, err := s.read(ctx, j.PAT, false)
	if err != nil {
		return vaultsecret.Current{}, err
	}
	defer clear(value)
	current, err := vaultsecret.ReadCurrent(ociclient.RequestContext(s.requestContext(ctx)), &s.bundles, vaultsecret.Ref{Vault: s.authority.Target.VaultOCID, Name: s.authority.ManagementPATName})
	if err != nil || current.ID != j.PAT.SecretID || current.Version != j.PAT.Version || !bytes.Equal([]byte(current.Value()), value) {
		return vaultsecret.Current{}, errors.New("NetBird PAT CURRENT differs from its exact pinned escrow")
	}
	return current, nil
}

// PublishPAT retains an issuance before dispatch and reconciles uncertain writes by exact CURRENT.
func (v NetBirdAccount) PublishPAT(ctx context.Context, value []byte) error {
	ctx = withNetBirdAccountGuardScope(ctx)
	if v.state == nil || !netbird.ValidAdminPAT(value) {
		return errors.New("NetBird PAT publication requires finite original account authority")
	}
	s := v.state
	state, err := s.current(ctx)
	if err != nil {
		return err
	}
	j := state.manager.Launch.Account
	if j.PAT.Version == 0 {
		observed, createErr := s.create(ctx, &state, true, value)
		clear(observed)
		return createErr
	}
	digest := netBirdMaterialSHA(value)
	if j.PendingPAT == nil && j.PAT.ContentSHA256 == digest {
		observed, readErr := s.read(ctx, j.PAT, false)
		clear(observed)
		return readErr
	}
	if j.PendingPAT == nil {
		j.PendingPAT = &netBirdPATPublication{ExpectedVersion: j.PAT.Version, ContentSHA256: digest}
		if err = s.checkpoint(ctx, &state); err != nil {
			return err
		}
	} else if j.PendingPAT.ContentSHA256 != digest {
		return errors.New("NetBird PAT has a different unresolved publication")
	}
	readPolicy := common.NoRetryPolicy()
	metadata, err := s.management.GetSecret(ociclient.RequestContext(s.requestContext(ctx)), vault.GetSecretRequest{SecretId: new(j.PAT.SecretID), RequestMetadata: common.RequestMetadata{RetryPolicy: &readPolicy}})
	if err != nil || deref(metadata.Id) != j.PAT.SecretID || !s.metadata(metadata.Secret, false) || metadata.Etag == nil || *metadata.Etag == "" || metadata.CurrentVersionNumber == nil {
		return errors.New("NetBird PAT publication metadata unavailable")
	}
	version := *metadata.CurrentVersionNumber
	if version == j.PAT.Version {
		policy := common.NoRetryPolicy()
		_, err = s.management.UpdateSecret(ociclient.RequestContext(s.requestContext(ctx)), vault.UpdateSecretRequest{SecretId: new(j.PAT.SecretID), IfMatch: metadata.Etag,
			UpdateSecretDetails: vault.UpdateSecretDetails{SecretContent: vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(value)), Stage: vault.SecretContentDetailsStageCurrent}}, RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
		if err != nil {
			return errors.New("NetBird PAT publication uncertain; retain escrow and reobserve CURRENT")
		}
	} else if version != j.PAT.Version+1 {
		return errors.New("NetBird PAT changed outside its retained publication")
	}
	probe := j.PAT
	probe.Version++
	probe.ContentSHA256 = digest
	observed, err := s.read(ctx, probe, false)
	if err != nil {
		return err
	}
	defer clear(observed)
	if !bytes.Equal(value, observed) {
		return errors.New("NetBird PAT published content differs from escrow")
	}
	j.PAT = probe
	j.PendingPAT = nil
	return s.checkpoint(ctx, &state)
}

func (s *netBirdAccount) create(ctx context.Context, state *originalNetBirdState, pat bool, value []byte) ([]byte, error) {
	j := state.manager.Launch.Account
	c := &j.Password
	name := s.authority.OwnerPasswordName
	if pat {
		c = &j.PAT
		name = s.authority.ManagementPATName
	}
	if c.Version > 0 {
		return s.read(ctx, *c, !pat)
	}
	details := vault.CreateSecretDetails{CompartmentId: new(s.authority.Target.CompartmentOCID), VaultId: new(s.authority.Target.VaultOCID), KeyId: new(s.authority.Target.KMSKeyOCID), SecretName: new(name)}
	if pat {
		details.SecretContent = vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(value)), Stage: vault.SecretContentDetailsStageCurrent}
	} else {
		// OCI's fixed vendor field is required for server-side password entropy.
		details.EnableAutoGeneration = new(true)
		details.SecretGenerationContext = vault.BytesGenerationContext{GenerationTemplate: vault.BytesGenerationContextGenerationTemplate512}
	}
	policy := common.NoRetryPolicy()
	request := vault.CreateSecretRequest{CreateSecretDetails: details, RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	digest, err := netBirdMaterialRequestSHA(request)
	if err != nil {
		return nil, err
	}
	if c.RequestSHA256 == "" {
		c.RequestSHA256 = digest
		c.RetryToken = BootstrapRetryToken(s.authority.ManagerOperationID+":"+name, digest)
		if err = s.checkpoint(ctx, state); err != nil {
			return nil, err
		}
	}
	if c.RequestSHA256 != digest {
		return nil, errors.New("NetBird account create differs from retained body")
	}
	if c.SecretID == "" {
		if c.FirstDispatchedAt.IsZero() {
			c.FirstDispatchedAt = time.Now().UTC()
			if err = s.checkpoint(ctx, state); err != nil {
				return nil, err
			}
		}
		if time.Since(c.FirstDispatchedAt) >= 23*time.Hour || time.Now().Before(c.FirstDispatchedAt) {
			return nil, errors.New("NetBird account uncertain create exceeds its original retry lifetime")
		}
		request.OpcRetryToken = new(c.RetryToken)
		response, err := s.management.CreateSecret(ociclient.RequestContext(s.requestContext(ctx)), request)
		if err != nil || response.Id == nil || !workerSecretPattern.MatchString(*response.Id) || !strings.HasPrefix(*response.Id, "ocid1.vaultsecret.oc1."+foundationHomeRegion+".") || len(*response.Id) > 512 {
			return nil, errors.New("NetBird account create uncertain; retain original request and retry token")
		}
		c.SecretID = *response.Id
		if err = s.checkpoint(ctx, state); err != nil {
			return nil, err
		}
	}
	if time.Since(c.FirstDispatchedAt) >= 23*time.Hour || time.Now().Before(c.FirstDispatchedAt) {
		return nil, errors.New("NetBird account unpinned creation exceeds its original retry lifetime")
	}
	probe := *c
	probe.Version = 1
	observed, err := s.read(ctx, probe, !pat)
	if err != nil {
		return nil, err
	}
	if pat && !bytes.Equal(observed, value) {
		clear(observed)
		return nil, errors.New("NetBird PAT creation differs from retained escrow")
	}
	c.Version = 1
	c.ContentSHA256 = netBirdMaterialSHA(observed)
	if err = s.checkpoint(ctx, state); err != nil {
		clear(observed)
		return nil, err
	}
	return observed, nil
}

func (s *netBirdAccount) metadata(m vault.Secret, password bool) bool {
	name := s.authority.ManagementPATName
	if password {
		name = s.authority.OwnerPasswordName
	}
	if deref(m.SecretName) != name || deref(m.CompartmentId) != s.authority.Target.CompartmentOCID || deref(m.VaultId) != s.authority.Target.VaultOCID || deref(m.KeyId) != s.authority.Target.KMSKeyOCID || m.LifecycleState != vault.SecretLifecycleStateActive || m.RotationConfig != nil || m.ReplicationConfig != nil || m.TimeOfDeletion != nil || m.LastRotationTime != nil || m.NextRotationTime != nil || m.TimeOfCurrentVersionExpiry != nil || len(m.SecretRules) != 0 || m.IsReplica != nil && *m.IsReplica {
		return false
	}
	if password {
		g, ok := m.SecretGenerationContext.(vault.BytesGenerationContext)
		return ok && g.GenerationTemplate == vault.BytesGenerationContextGenerationTemplate512 && g.SecretTemplate == nil && m.IsAutoGenerationEnabled != nil && *m.IsAutoGenerationEnabled
	}
	return m.SecretGenerationContext == nil && (m.IsAutoGenerationEnabled == nil || !*m.IsAutoGenerationEnabled)
}

func (s *netBirdAccount) read(ctx context.Context, c NetBirdMaterialCreate, password bool) ([]byte, error) {
	policy := common.NoRetryPolicy()
	m, err := s.management.GetSecret(ociclient.RequestContext(s.requestContext(ctx)), vault.GetSecretRequest{SecretId: new(c.SecretID), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil || deref(m.Id) != c.SecretID || !s.metadata(m.Secret, password) || m.CurrentVersionNumber == nil || *m.CurrentVersionNumber != c.Version {
		return nil, errors.New("NetBird account exact secret metadata changed")
	}
	b, err := s.bundles.GetSecretBundle(ociclient.RequestContext(s.requestContext(ctx)), secrets.GetSecretBundleRequest{SecretId: new(c.SecretID), VersionNumber: new(c.Version), Stage: secrets.GetSecretBundleStageCurrent, RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil || deref(b.SecretId) != c.SecretID || b.VersionNumber == nil || *b.VersionNumber != c.Version || b.TimeOfDeletion != nil || b.TimeOfExpiry != nil {
		return nil, errors.New("NetBird account exact CURRENT bundle unavailable")
	}
	current := false
	for _, stage := range b.Stages {
		current = current || stage == secrets.SecretBundleStagesCurrent
	}
	if !current {
		return nil, errors.New("NetBird account bundle is not CURRENT")
	}
	content, ok := b.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(1024) {
		return nil, errors.New("NetBird account bundle exceeds finite bound")
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || base64.StdEncoding.EncodeToString(value) != *content.Content || password && (len(value) < 64 || len(value) > 128) || !password && (len(value) < 20 || len(value) > 512) || c.ContentSHA256 != "" && netBirdMaterialSHA(value) != c.ContentSHA256 {
		clear(value)
		return nil, errors.New("NetBird account content differs from its pinned identity")
	}
	return value, nil
}
