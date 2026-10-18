package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const originalNetBirdRetentionDays int64 = 35
const originalNetBirdRetentionCooling = 14*24*time.Hour + time.Hour

var ErrOriginalNetBirdBackupPending = fmt.Errorf("%w: original NetBird backup protection is not yet locked", ErrOriginalSourceProducerHold)

// NetBirdBackupAuthority is a finite original purpose, independent of serving authority.
type NetBirdBackupAuthority struct {
	SchemaVersion      int                                  `json:"schemaVersion"`
	InstallationID     string                               `json:"installationId"`
	TenancyID          string                               `json:"tenancyId"`
	StoreGeneration    string                               `json:"storeGeneration"`
	ManagerSlotID      string                               `json:"managerSlotId"`
	ManagerOperationID string                               `json:"managerOperationId"`
	HomeStorageDomain  bootstrap.StorageDomain              `json:"homeStorageDomain"`
	Destinations       [2]NetBirdBackupDestinationAuthority `json:"destinations"`
	PublicAccessType   string                               `json:"publicAccessType"`
	StorageTier        string                               `json:"storageTier"`
	Versioning         string                               `json:"versioning"`
	RetentionDays      int64                                `json:"retentionDays"`
	LockDelaySeconds   int64                                `json:"lockDelaySeconds"`
}

type NetBirdBackupDestinationAuthority struct {
	Cell                 string `json:"cell"`
	OCIRegion            string `json:"ociRegion"`
	BucketName           string `json:"bucketName"`
	CompartmentReference string `json:"compartmentReference"`
	VaultReference       string `json:"vaultReference"`
	KMSKeyReference      string `json:"kmsKeyReference"`
}

func newNetBirdBackupAuthority(installation, tenancy string, home bootstrap.StorageDomain) (NetBirdBackupAuthority, error) {
	var a NetBirdBackupAuthority
	if !entityid.Valid(installation) || !strings.HasPrefix(tenancy, "ocid1.tenancy.oc1..") || len(tenancy) > 512 || home.Validate() != nil {
		return a, ErrOriginalSourceProducerHold
	}
	slot := BootstrapSlotID(installation, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	a = NetBirdBackupAuthority{SchemaVersion: 1, InstallationID: installation, TenancyID: tenancy,
		StoreGeneration: entityid.Derive("netbird-foundation-store", installation) + ":1", ManagerSlotID: slot,
		ManagerOperationID: BootstrapOperationID(installation, slot), HomeStorageDomain: home,
		PublicAccessType: "NoPublicAccess", StorageTier: "Standard", Versioning: "Disabled",
		RetentionDays: originalNetBirdRetentionDays, LockDelaySeconds: int64(originalNetBirdRetentionCooling / time.Second)}
	for index, cell := range [2]string{"GRU", "SFO"} {
		d := NetBirdBackupDestinationAuthority{Cell: cell, OCIRegion: [2]string{foundationHomeRegion, "us-sanjose-1"}[index], BucketName: strings.ToLower(cell) + "-1-backup"}
		for key, target := range map[string]*string{"control_compartment": &d.CompartmentReference, "vault": &d.VaultReference, "key": &d.KMSKeyReference} {
			value, err := FoundationResourceReference(cell, key)
			if err != nil {
				return NetBirdBackupAuthority{}, err
			}
			*target = value
		}
		a.Destinations[index] = d
	}
	return a, nil
}

func (a NetBirdBackupAuthority) validate() error {
	expected, err := newNetBirdBackupAuthority(a.InstallationID, a.TenancyID, a.HomeStorageDomain)
	if err != nil || a != expected {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func validateFoundationNetBirdBackup(grant FoundationGrant) error {
	for _, regional := range grant.Regions {
		manager := regional.NetBirdManager
		if manager == nil {
			continue
		}
		if grant.SchemaVersion != 3 {
			if manager.Backup != nil {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		if manager.Backup == nil {
			continue
		}
		if regional.Plan["cell"] != "GRU" || grant.Generation != 1 || manager.Backup.validate() != nil || manager.StoreOrigin != "new" || regional.BootstrapMaterial == nil || regional.BootstrapMaterial.SourceRegistration == nil {
			return ErrOriginalSourceProducerHold
		}
		a := manager.Backup
		if a.InstallationID != grant.InstallationID || a.TenancyID != grant.TenancyID || a.HomeStorageDomain != regional.BootstrapMaterial.SourceRegistration.StorageDomain {
			return ErrOriginalSourceProducerHold
		}
		for _, destination := range a.Destinations {
			found := false
			for _, candidate := range grant.Regions {
				if candidate.Plan["cell"] != destination.Cell {
					continue
				}
				buckets, ok := candidate.Plan["foundation_buckets"].(map[string]any)
				if !ok || buckets["backup"] != destination.BucketName || candidate.Plan["region"] != destination.OCIRegion || !sameOriginalSourceValue(candidate.Plan["bucket_retention_days"], originalNetBirdRetentionDays) {
					return ErrOriginalSourceProducerHold
				}
				found = true
			}
			if !found {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return nil
}

// These envelopes are authenticated by the original bundle verifier; this only bounds its useful lifetime.
func validateNetBirdBackupCoolingInterval(grant FoundationGrant, lockTime time.Time) error {
	if lockTime.IsZero() {
		return ErrOriginalSourceProducerHold
	}
	var wires [][]byte
	for _, release := range grant.ReleaseAuthorities {
		wires = append(wires, release.DelegationWire)
	}
	found := false
	for _, regional := range grant.Regions {
		manager := regional.NetBirdManager
		if manager == nil {
			continue
		}
		found = true
		if manager.Components == nil {
			return ErrOriginalSourceProducerHold
		}
		for _, component := range manager.Components {
			wires = append(wires, component.Release.DelegationWire)
		}
		wires = append(wires, manager.ImageReceiptWire, manager.QualificationWire)
		for _, optional := range [][]byte{manager.ImageDelegationWire, manager.QualificationDelegationWire} {
			if len(optional) != 0 {
				wires = append(wires, optional)
			}
		}
	}
	if !found {
		return ErrOriginalSourceProducerHold
	}
	for _, wire := range wires {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil || !envelope.ExpiresAt.After(lockTime) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
	}
	return nil
}

type OriginalNetBirdBackupCreate struct {
	Pending        *PendingFoundationCreate      `json:"pending,omitempty"`
	Provenance     *FoundationResourceProvenance `json:"provenance,omitempty"`
	ReadbackSHA256 string                        `json:"readbackSha256,omitempty"`
	VerifiedAt     time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason     string                        `json:"holdReason,omitempty"`
}

type OriginalNetBirdBackupBucket struct {
	OriginalNetBirdBackupCreate
	Request objectstorage.CreateBucketDetails `json:"request"`
}

type OriginalNetBirdBackupRetention struct {
	OriginalNetBirdBackupCreate
	Request objectstorage.CreateRetentionRuleDetails `json:"request"`
}

type OriginalNetBirdBackupDestination struct {
	Cell          string                         `json:"cell"`
	OCIRegion     string                         `json:"ociRegion"`
	CompartmentID string                         `json:"compartmentId"`
	VaultID       string                         `json:"vaultId"`
	KMSKeyID      string                         `json:"kmsKeyId"`
	VaultSHA256   string                         `json:"vaultSha256"`
	BucketName    string                         `json:"bucketName"`
	Bucket        OriginalNetBirdBackupBucket    `json:"bucket"`
	Retention     OriginalNetBirdBackupRetention `json:"retention"`
}

// OriginalNetBirdBackupJournal keeps original ownership separate from generic foundation records.
type OriginalNetBirdBackupJournal struct {
	InstallationID  string                              `json:"installationId"`
	StoreGeneration string                              `json:"storeGeneration"`
	OperationID     string                              `json:"operationId"`
	GrantSHA256     string                              `json:"grantSha256"`
	BundleSHA256    string                              `json:"bundleSha256"`
	IntentSHA256    string                              `json:"intentSha256"`
	Namespace       string                              `json:"namespace"`
	Destinations    [2]OriginalNetBirdBackupDestination `json:"destinations"`
	Complete        bool                                `json:"complete,omitzero"`
}

func originalNetBirdBackupJournal(record FoundationRecord) *OriginalNetBirdBackupJournal {
	if record.OriginalFoundationCompartments == nil || record.OriginalFoundationCompartments.Regions[0].NetBirdManager == nil {
		return nil
	}
	return record.OriginalFoundationCompartments.Regions[0].NetBirdManager.Backup
}

func originalNetBirdBackupScope(record FoundationRecord) (OriginalNetBirdBackupJournal, error) {
	var j OriginalNetBirdBackupJournal
	root := record.OriginalFoundationCompartments
	if root == nil || root.Regions[0].NetBirdManager == nil || record.NetBirdMaterial == nil || !record.NetBirdMaterial.Complete {
		return j, ErrOriginalSourceProducerHold
	}
	m := root.Regions[0].NetBirdManager
	a := m.Intent.Backup
	if a == nil || a.validate() != nil || m.GrantSHA256 != root.GrantSHA256 || m.BundleSHA256 != root.BundleSHA256 || m.IntentSHA256 != root.GRUIntentSHA256 || a.InstallationID != record.NetBirdMaterial.Authority.Context.InstallationID || a.TenancyID != record.TenancyID || a.StoreGeneration != record.NetBirdMaterial.Authority.Context.StoreGeneration {
		return j, ErrOriginalSourceProducerHold
	}
	j = OriginalNetBirdBackupJournal{InstallationID: a.InstallationID, StoreGeneration: a.StoreGeneration, OperationID: a.ManagerOperationID,
		GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256, IntentSHA256: root.GRUIntentSHA256, Namespace: a.HomeStorageDomain.Namespace}
	for index, signed := range a.Destinations {
		region := root.Regions[index]
		v := region.Vault
		if region.Cell != signed.Cell || region.OCIRegion != signed.OCIRegion || v == nil || v.Vault.VerifiedAt.IsZero() || v.Key.VerifiedAt.IsZero() || v.Vault.HoldReason != "" || v.Key.HoldReason != "" || region.Compartments[0].VerifiedAt.IsZero() || v.ControlCompartmentID != originalCompartmentID(region.Compartments[0]) {
			return OriginalNetBirdBackupJournal{}, ErrOriginalSourceProducerHold
		}
		wire, err := json.Marshal(v, json.Deterministic(true))
		if err != nil {
			return j, err
		}
		d := OriginalNetBirdBackupDestination{Cell: signed.Cell, OCIRegion: signed.OCIRegion, CompartmentID: v.ControlCompartmentID,
			VaultID: originalVaultID(v.Vault.OriginalFoundationKMSCreate), KMSKeyID: originalVaultID(v.Key.OriginalFoundationKMSCreate), VaultSHA256: digestSource(wire), BucketName: signed.BucketName}
		d.Bucket.Request = objectstorage.CreateBucketDetails{Name: new(d.BucketName), CompartmentId: new(d.CompartmentID), KmsKeyId: new(d.KMSKeyID),
			PublicAccessType: objectstorage.CreateBucketDetailsPublicAccessTypeNopublicaccess, StorageTier: objectstorage.CreateBucketDetailsStorageTierStandard,
			Versioning: objectstorage.CreateBucketDetailsVersioningDisabled}
		d.Retention.Request = objectstorage.CreateRetentionRuleDetails{DisplayName: new("backup-retention"), Duration: &objectstorage.Duration{TimeAmount: new(originalNetBirdRetentionDays), TimeUnit: objectstorage.DurationTimeUnitDays}}
		j.Destinations[index] = d
	}
	return j, nil
}

func (j OriginalNetBirdBackupJournal) scopeOnly() OriginalNetBirdBackupJournal {
	j.Complete = false
	for index := range j.Destinations {
		j.Destinations[index].Bucket.OriginalNetBirdBackupCreate = OriginalNetBirdBackupCreate{}
		j.Destinations[index].Retention.OriginalNetBirdBackupCreate = OriginalNetBirdBackupCreate{}
		j.Destinations[index].Retention.Request.TimeRuleLocked = nil
	}
	return j
}

func originalNetBirdBackupEntry(d *OriginalNetBirdBackupDestination, slot int) *OriginalNetBirdBackupCreate {
	if slot == 0 {
		return &d.Bucket.OriginalNetBirdBackupCreate
	}
	return &d.Retention.OriginalNetBirdBackupCreate
}

func originalNetBirdBackupRequestSHA(j OriginalNetBirdBackupJournal, index, slot int) (string, error) {
	d := j.Destinations[index]
	var request http.Request
	var err error
	if slot == 0 {
		request, err = (objectstorage.CreateBucketRequest{NamespaceName: new(j.Namespace), CreateBucketDetails: d.Bucket.Request}).HTTPRequest(http.MethodPost, "/n/{namespaceName}/b", nil, nil)
	} else {
		request, err = (objectstorage.CreateRetentionRuleRequest{NamespaceName: new(j.Namespace), BucketName: new(d.BucketName), CreateRetentionRuleDetails: d.Retention.Request}).HTTPRequest(http.MethodPost, "/n/{namespaceName}/b/{bucketName}/retention", nil, nil)
	}
	if err != nil || request.Body == nil {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	defer request.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(request.Body, 8193))
	if err != nil || len(wire) > 8192 {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return "", err
	}
	wire, err = json.Marshal(body, json.Deterministic(true))
	return digestSource(wire), err
}

func originalNetBirdBackupIdentity(j OriginalNetBirdBackupJournal, index, slot int, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: "netbird-backup-" + j.Destinations[index].Cell + "-" + [2]string{"bucket", "retention"}[slot], Region: j.Destinations[index].OCIRegion, RequestDigest: digest}
}

var originalNetBirdRetentionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$`)

func originalNetBirdBackupID(d OriginalNetBirdBackupDestination, slot int, id string) bool {
	if slot == 0 {
		return validAuxiliaryID("backup_bucket", id, d.OCIRegion)
	}
	return originalNetBirdRetentionID.MatchString(id)
}

func originalNetBirdBackupReadback(j OriginalNetBirdBackupJournal, index, slot int) (string, error) {
	d := j.Destinations[index]
	entry := originalNetBirdBackupEntry(&d, slot)
	if entry.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	digest, err := originalNetBirdBackupRequestSHA(j, index, slot)
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal([]string{j.Namespace, d.OCIRegion, d.BucketName, d.CompartmentID, d.VaultID, d.KMSKeyID, d.VaultSHA256, digest, entry.Provenance.ResourceID, d.Bucket.Provenance.ResourceID}, json.Deterministic(true))
	return digestSource(wire), err
}

func readOriginalNetBirdBackupResource(ctx context.Context, client objectstorage.ObjectStorageClient, record FoundationRecord, index, slot int) (bool, error) {
	j := originalNetBirdBackupJournal(record)
	if j == nil || j.Destinations[index].Bucket.Provenance == nil {
		return false, ErrOriginalSourceProducerHold
	}
	d := j.Destinations[index]
	entry := originalNetBirdBackupEntry(&d, slot)
	if entry.Provenance == nil || entry.Pending == nil {
		return false, ErrOriginalSourceProducerHold
	}
	if slot == 0 {
		response, err := client.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(j.Namespace), BucketName: new(d.BucketName)})
		if err != nil {
			return false, err
		}
		b := response.Bucket
		if deref(b.Id) != entry.Provenance.ResourceID || deref(b.Name) != d.BucketName || deref(b.Namespace) != j.Namespace || deref(b.CompartmentId) != d.CompartmentID || deref(b.KmsKeyId) != d.KMSKeyID || deref(b.CreatedBy) != record.OriginalFoundationCompartments.UserID || b.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess || b.StorageTier != objectstorage.BucketStorageTierStandard || b.Versioning != objectstorage.BucketVersioningDisabled || b.IsReadOnly != nil && *b.IsReadOnly || b.ReplicationEnabled != nil && *b.ReplicationEnabled {
			return false, ErrOriginalSourceProducerHold
		}
		return true, nil
	}
	response, err := client.GetRetentionRule(ociclient.RequestContext(ctx), objectstorage.GetRetentionRuleRequest{NamespaceName: new(j.Namespace), BucketName: new(d.BucketName), RetentionRuleId: new(entry.Provenance.ResourceID)})
	if err != nil {
		return false, err
	}
	rule := response.RetentionRule
	if deref(rule.Id) != entry.Provenance.ResourceID || deref(rule.DisplayName) != "backup-retention" || !sameOriginalSourceValue(rule.Duration, d.Retention.Request.Duration) || rule.TimeRuleLocked == nil || d.Retention.Request.TimeRuleLocked == nil || !rule.TimeRuleLocked.Time.Equal(d.Retention.Request.TimeRuleLocked.Time) {
		return false, ErrOriginalSourceProducerHold
	}
	return !rule.TimeRuleLocked.Time.After(time.Now()), nil
}

func originalNetBirdBackupPrerequisites(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, error) {
	expected, err := originalCompartmentScope(ctx, authority)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	grant, err := decodeOriginalMaterialGrant(authority.operator.bundle)
	if err != nil || validateFoundationNetBirdBackup(grant) != nil {
		return FoundationRecord{}, "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return record, etag, err
	}
	if record.OriginalFoundationCompartments == nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments.scopeOnly(), expected) {
		return record, etag, ErrOriginalSourceProducerHold
	}
	if _, err := originalNetBirdBackupScope(record); err != nil {
		return record, etag, err
	}
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	found := false
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == "GRU" && regional.NetBirdManager != nil && sameOriginalSourceValue(regional.NetBirdManager, manager.Intent) {
			found = true
		}
	}
	if !found {
		return record, etag, ErrOriginalSourceProducerHold
	}
	if err := readOriginalNetBirdBackupVaults(ctx, authority.factory, record); err != nil {
		return record, etag, err
	}
	return record, etag, nil
}

func readOriginalNetBirdBackupVaults(ctx context.Context, factory *ociclient.Factory, record FoundationRecord) error {
	if factory == nil || factory.Provider() == nil || record.OriginalFoundationCompartments == nil {
		return ErrOriginalSourceProducerHold
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != record.TenancyID {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for _, region := range record.OriginalFoundationCompartments.Regions[:2] {
		regional, err := factory.ForRegion(region.OCIRegion)
		if err != nil {
			return err
		}
		if region.Vault == nil || region.Vault.Key.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
		version, err := readOriginalVaultKey(ctx, sdkcli.NewClient(regional, ""), region.OCIRegion, region.Vault)
		if err != nil || version != region.Vault.Key.CurrentKeyVersion {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
	}
	return nil
}

func retainOriginalNetBirdBackup(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, err := originalNetBirdBackupPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	if originalNetBirdBackupJournal(record) == nil {
		scope, err := originalNetBirdBackupScope(record)
		if err != nil {
			return err
		}
		record.OriginalFoundationCompartments.Regions[0].NetBirdManager.Backup = &scope
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	for index := range 2 {
		for slot := range 2 {
			if err := provisionOriginalNetBirdBackupResource(ctx, authority, index, slot); err != nil {
				return err
			}
		}
	}
	record, etag, err = originalNetBirdBackupPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	j := originalNetBirdBackupJournal(record)
	for _, d := range j.Destinations {
		if d.Retention.VerifiedAt.IsZero() {
			return ErrOriginalNetBirdBackupPending
		}
	}
	if !j.Complete {
		j.Complete = true
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func provisionOriginalNetBirdBackupResource(ctx context.Context, authority *HomeIAMAuthority, index, slot int) error {
	record, etag, err := originalNetBirdBackupPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	j := originalNetBirdBackupJournal(record)
	if j == nil {
		return ErrOriginalSourceProducerHold
	}
	d := &j.Destinations[index]
	entry := originalNetBirdBackupEntry(d, slot)
	if entry.HoldReason != "" || slot == 1 && d.Bucket.VerifiedAt.IsZero() {
		return ErrOriginalSourceProducerHold
	}
	regional, err := authority.factory.ForRegion(d.OCIRegion)
	if err != nil {
		return err
	}
	client, err := regional.ObjectStorage()
	if err != nil {
		return err
	}
	if entry.Provenance == nil {
		// Neither POST supports OCI retry tokens; an uncertain dispatch is never repeated.
		if entry.Pending != nil {
			return ErrOriginalSourceProducerHold
		}
		started := time.Now().UTC()
		lockTime := started.Add(originalNetBirdRetentionCooling)
		grant, err := decodeOriginalMaterialGrant(authority.operator.bundle)
		if err != nil || !authority.operator.deadline.After(lockTime) || validateNetBirdBackupCoolingInterval(grant, lockTime) != nil {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if slot == 1 {
			d.Retention.Request.TimeRuleLocked = &common.SDKTime{Time: lockTime}
		}
		digest, err := originalNetBirdBackupRequestSHA(*j, index, slot)
		if err != nil {
			return err
		}
		entry.Pending = &PendingFoundationCreate{OperationID: j.OperationID, IntentDigest: j.IntentSHA256, FirstAttemptAt: started, Request: originalNetBirdBackupIdentity(*j, index, slot, digest)}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
		guard := func(dispatchCtx context.Context) error {
			saved, _, err := originalNetBirdBackupPrerequisites(ociclient.CheckpointContext(dispatchCtx), authority)
			if err != nil || !sameOriginalSourceValue(originalNetBirdBackupJournal(saved), j) {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			if slot == 1 {
				if _, err := readOriginalNetBirdBackupResource(ociclient.CheckpointContext(dispatchCtx), client, saved, index, 0); err != nil {
					return err
				}
			}
			if !authority.operator.deadline.After(lockTime) || validateNetBirdBackupCoolingInterval(grant, lockTime) != nil {
				return ErrOriginalSourceProducerHold
			}
			return ociclient.LimitAdmission(dispatchCtx, authority.operator.deadline)
		}
		if err := guard(ctx); err != nil {
			return err
		}
		policy := common.NoRetryPolicy()
		metadata := common.RequestMetadata{RetryPolicy: &policy}
		createCtx := ociclient.RequestContext(ociclient.WithAuthority(ctx, guard))
		var id string
		if slot == 0 {
			response, createErr := client.CreateBucket(createCtx, objectstorage.CreateBucketRequest{NamespaceName: new(j.Namespace), CreateBucketDetails: d.Bucket.Request, RequestMetadata: metadata})
			id, err = deref(response.Id), createErr
		} else {
			response, createErr := client.CreateRetentionRule(createCtx, objectstorage.CreateRetentionRuleRequest{NamespaceName: new(j.Namespace), BucketName: new(d.BucketName), CreateRetentionRuleDetails: d.Retention.Request, RequestMetadata: metadata})
			id, err = deref(response.Id), createErr
		}
		if err != nil || !originalNetBirdBackupID(*d, slot, id) {
			entry.HoldReason = "create-unresolved"
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
			}
			return errors.Join(ErrOriginalSourceProducerHold, err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: id, Generation: record.OriginalFoundationCompartments.Generation, GrantSHA256: j.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	locked, err := readOriginalNetBirdBackupResource(ctx, client, record, index, slot)
	if err != nil || !locked {
		return err
	}
	digest, err := originalNetBirdBackupReadback(*j, index, slot)
	if err != nil || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != digest {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = digest, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func (record FoundationRecord) validateOriginalNetBirdBackup() error {
	j := originalNetBirdBackupJournal(record)
	if j == nil {
		return nil
	}
	expected, err := originalNetBirdBackupScope(record)
	if err != nil || !sameOriginalSourceValue(j.scopeOnly(), expected) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	seen := map[string]bool{}
	complete := true
	for index := range j.Destinations {
		d := &j.Destinations[index]
		for slot := range 2 {
			entry := originalNetBirdBackupEntry(d, slot)
			notBefore := record.OriginalFoundationCompartments.Regions[index].Vault.Key.VerifiedAt
			if slot == 1 && d.Bucket.VerifiedAt.After(notBefore) {
				notBefore = d.Bucket.VerifiedAt
			}
			if entry.Pending == nil {
				if entry.Provenance != nil || entry.HoldReason != "" || !entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 != "" || slot == 1 && d.Retention.Request.TimeRuleLocked != nil {
					return ErrOriginalSourceProducerHold
				}
			} else {
				p := entry.Pending
				digest, err := originalNetBirdBackupRequestSHA(*j, index, slot)
				if err != nil || p.OperationID != j.OperationID || p.IntentDigest != j.IntentSHA256 || p.Request != originalNetBirdBackupIdentity(*j, index, slot, digest) || p.FirstAttemptAt.IsZero() || p.FirstAttemptAt.Before(notBefore) || p.FirstAttemptAt.After(record.UpdatedAt) || slot == 1 && (d.Bucket.VerifiedAt.IsZero() || d.Retention.Request.TimeRuleLocked == nil || !d.Retention.Request.TimeRuleLocked.Time.Equal(p.FirstAttemptAt.Add(originalNetBirdRetentionCooling))) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			if entry.HoldReason != "" && (entry.HoldReason != "create-refused" && entry.HoldReason != "create-unresolved" || entry.Provenance != nil) {
				return ErrOriginalSourceProducerHold
			}
			if entry.Provenance != nil {
				p := entry.Provenance
				if entry.Pending == nil || !sameOriginalSourceValue(p.Create, entry.Pending) || p.GrantSHA256 != j.GrantSHA256 || p.Generation != record.OriginalFoundationCompartments.Generation || !originalNetBirdBackupID(*d, slot, p.ResourceID) || seen[p.ResourceID] {
					return ErrOriginalSourceProducerHold
				}
				seen[p.ResourceID] = true
			}
			if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() && (entry.Provenance == nil || entry.VerifiedAt.Before(entry.Pending.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt)) {
				return ErrOriginalSourceProducerHold
			}
			if !entry.VerifiedAt.IsZero() {
				digest, err := originalNetBirdBackupReadback(*j, index, slot)
				if err != nil || digest != entry.ReadbackSHA256 || slot == 1 && entry.VerifiedAt.Before(d.Retention.Request.TimeRuleLocked.Time) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			} else {
				complete = false
			}
		}
	}
	if j.Complete && !complete {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func (next FoundationRecord) retainOriginalNetBirdBackup(previous FoundationRecord) error {
	before, after := originalNetBirdBackupJournal(previous), originalNetBirdBackupJournal(next)
	if before == nil {
		if after == nil {
			return nil
		}
		expected, err := originalNetBirdBackupScope(next)
		if err != nil || !sameOriginalSourceValue(after, expected) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		return nil
	}
	if after == nil || !sameOriginalSourceValue(before.scopeOnly(), after.scopeOnly()) || before.Complete && !after.Complete {
		return ErrOriginalSourceProducerHold
	}
	for index := range before.Destinations {
		for slot := range 2 {
			old := originalNetBirdBackupEntry(&before.Destinations[index], slot)
			current := originalNetBirdBackupEntry(&after.Destinations[index], slot)
			if old.Pending != nil && (!sameOriginalSourceValue(old.Pending, current.Pending) || slot == 1 && !sameOriginalSourceValue(before.Destinations[index].Retention.Request, after.Destinations[index].Retention.Request)) || old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) || old.HoldReason != "" && old.HoldReason != current.HoldReason || !old.VerifiedAt.IsZero() && (!old.VerifiedAt.Equal(current.VerifiedAt) || old.ReadbackSHA256 != current.ReadbackSHA256) || old.Pending == nil && (current.Provenance != nil || !current.VerifiedAt.IsZero()) || old.Provenance == nil && current.Provenance != nil && !current.VerifiedAt.IsZero() {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return nil
}

// readOriginalNetBirdBackup observes retained ownership; it performs no mutation or discovery adoption.
func readOriginalNetBirdBackup(ctx context.Context, factory *ociclient.Factory, record FoundationRecord) error {
	if err := record.validateOriginalNetBirdBackup(); err != nil {
		return err
	}
	j := originalNetBirdBackupJournal(record)
	if j == nil || !j.Complete {
		return ErrOriginalNetBirdBackupPending
	}
	if err := readOriginalNetBirdBackupVaults(ctx, factory, record); err != nil {
		return err
	}
	for index, destination := range j.Destinations {
		regional, err := factory.ForRegion(destination.OCIRegion)
		if err != nil {
			return err
		}
		client, err := regional.ObjectStorage()
		if err != nil {
			return err
		}
		for slot := range 2 {
			locked, err := readOriginalNetBirdBackupResource(ctx, client, record, index, slot)
			if err != nil || !locked {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
		}
	}
	return ctx.Err()
}
