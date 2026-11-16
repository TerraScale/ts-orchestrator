package region

import (
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
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
