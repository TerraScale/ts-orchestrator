package region

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

const netBirdMaterialDerivation = "netbird-manager-config-hkdf-sha256-v1"

var netBirdMaterialPurposes = [4]string{"root", "NETBIRD_RELAY_AUTH_SECRET", "NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY", "NETBIRD_DATASTORE_ENCRYPTION_KEY"}

type netBirdMaterialContext struct {
	InstallationID     string                        `json:"installationId"`
	TenancyID          string                        `json:"tenancyId"`
	Cell               string                        `json:"cell"`
	Environment        string                        `json:"environment"`
	Architecture       string                        `json:"architecture"`
	StoreGeneration    string                        `json:"storeGeneration"`
	ManagerSlotID      string                        `json:"managerSlotId"`
	ManagerOperationID string                        `json:"managerOperationId"`
	ProducerUserID     string                        `json:"producerUserId"`
	Target             bootstrapmaterial.VaultTarget `json:"target"`
	Derivation         string                        `json:"derivation"`
}

// NetBirdMaterialAuthority is a separate original-user purpose in the root grant.
type NetBirdMaterialAuthority struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Context       netBirdMaterialContext `json:"context"`
	LineageSHA256 string                 `json:"lineageSha256"`
	Names         [4]string              `json:"names"`
}

// NetBirdMaterialCreate retains metadata only, including uncertain dispatches.
type NetBirdMaterialCreate struct {
	Name              string    `json:"name"`
	RequestSHA256     string    `json:"requestSha256,omitempty"`
	RetryToken        string    `json:"retryToken,omitempty"`
	FirstDispatchedAt time.Time `json:"firstDispatchedAt,omitzero"`
	SecretID          string    `json:"secretId,omitempty"`
	Version           int64     `json:"version,omitzero"`
	ContentSHA256     string    `json:"contentSha256,omitempty"`
	HoldReason        string    `json:"holdReason,omitempty"`
}

// NetBirdMaterialJournal never establishes foundation completion or a reader.
type NetBirdMaterialJournal struct {
	Authority            NetBirdMaterialAuthority `json:"authority"`
	OriginalGrantSHA256  string                   `json:"originalGrantSha256"`
	OriginalBundleSHA256 string                   `json:"originalBundleSha256"`
	BornAt               time.Time                `json:"bornAt"`
	Creates              [4]NetBirdMaterialCreate `json:"creates"`
	Complete             bool                     `json:"complete,omitzero"`
}

func netBirdMaterialSHA(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func netBirdMaterialUser(value string) bool {
	return strings.HasPrefix(value, "ocid1.user.oc1..") && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n'\" ") && len(value) > len("ocid1.user.oc1..")
}

func newNetBirdMaterialAuthority(installation, tenancy, producer string, target bootstrapmaterial.VaultTarget) (NetBirdMaterialAuthority, error) {
	if !entityid.Valid(installation) || !strings.HasPrefix(tenancy, "ocid1.tenancy.") || !netBirdMaterialUser(producer) || target.Validate(foundationHomeRegion) != nil {
		return NetBirdMaterialAuthority{}, errors.New("NetBird material requires original installation, authenticated user and exact home escrow")
	}
	slot := BootstrapSlotID(installation, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	context := netBirdMaterialContext{InstallationID: installation, TenancyID: tenancy, Cell: "GRU", Environment: "production", Architecture: "arm64",
		StoreGeneration: entityid.Derive("netbird-foundation-store", installation) + ":1", ManagerSlotID: slot, ManagerOperationID: BootstrapOperationID(installation, slot),
		ProducerUserID: producer, Target: target, Derivation: netBirdMaterialDerivation}
	wire, err := json.Marshal(context, json.Deterministic(true))
	if err != nil {
		return NetBirdMaterialAuthority{}, err
	}
	authority := NetBirdMaterialAuthority{SchemaVersion: 1, Context: context, LineageSHA256: netBirdMaterialSHA(wire)}
	for index, suffix := range [4]string{"root", "relay", "session", "store"} {
		authority.Names[index] = "ts-bootstrap-source-netbird-config-" + authority.LineageSHA256 + "-" + suffix
	}
	return authority, nil
}

func (a NetBirdMaterialAuthority) validate() error {
	expected, err := newNetBirdMaterialAuthority(a.Context.InstallationID, a.Context.TenancyID, a.Context.ProducerUserID, a.Context.Target)
	if err != nil || a != expected {
		return errors.New("NetBird material differs from its fixed original signed context")
	}
	return nil
}

func validateFoundationNetBirdMaterial(grant FoundationGrant) error {
	for _, regional := range grant.Regions {
		manager := regional.NetBirdManager
		if manager == nil {
			continue
		}
		if grant.SchemaVersion != 3 {
			if manager.Material != nil {
				return errors.New("historical NetBird grant cannot gain material authority")
			}
			continue
		}
		if regional.Plan["cell"] != "GRU" || manager.Material == nil || manager.Material.validate() != nil || manager.StoreOrigin != "new" ||
			regional.BootstrapMaterial == nil || grant.Generation != 1 {
			return errors.New("fresh NetBird grant lacks original material purpose")
		}
		a := manager.Material
		if a.Context.InstallationID != grant.InstallationID || a.Context.TenancyID != grant.TenancyID || a.Context.Target != regional.BootstrapMaterial.SourceVaultTarget {
			return errors.New("NetBird material purpose differs from original root-signed escrow")
		}
	}
	return nil
}

func (r FoundationRecord) netBirdMaterialOnly() bool {
	return r.Cell == "GRU" && r.NetBirdMaterial != nil && r.LeaseID == "" && r.CompletedAt.IsZero() && r.BlockedReason == "" &&
		len(r.ResourceIDs) == 0 && len(r.ResourceProvenance) == 0 && len(r.PendingCreates) == 0 && r.FoundationWriter == nil && r.NetBirdManager == nil &&
		len(r.SourcePolicyIDs) == 0 && len(r.WorkerPolicyIDs) == 0 && len(r.OCIRIssuances) == 0 && r.OCIResources == nil && r.CapacityLedger == nil &&
		len(r.CapacityCreates) == 0 && len(r.CapacityPools) == 0 && len(r.PoolChildren) == 0 && len(r.PoolDrains) == 0 && len(r.PoolQuarantines) == 0 &&
		len(r.AuxiliaryIDs) == 2 && r.AuxiliaryIDs["head_bucket"] != "" && r.AuxiliaryIDs["ledger_bucket"] != ""
}

func (r FoundationRecord) validateNetBirdMaterial() error {
	j := r.NetBirdMaterial
	if j == nil {
		return nil
	}
	if r.Cell != "GRU" || j.Authority.validate() != nil || j.Authority.Context.TenancyID != r.TenancyID || !validFoundationDigest(j.OriginalGrantSHA256) ||
		!validFoundationDigest(j.OriginalBundleSHA256) || j.BornAt.IsZero() || j.BornAt.After(r.UpdatedAt) {
		return errors.New("invalid original NetBird material journal")
	}
	complete := true
	for index, create := range j.Creates {
		if create.Name != j.Authority.Names[index] || (create.RequestSHA256 == "") != (create.RetryToken == "") ||
			create.HoldReason != "" && (!slices.Contains([]string{"create-refused", "retry-expired"}, create.HoldReason) || create.FirstDispatchedAt.IsZero() || create.Version != 0) ||
			create.RequestSHA256 != "" && (!validFoundationDigest(create.RequestSHA256) || !validFoundationDigest(create.RetryToken)) ||
			!create.FirstDispatchedAt.IsZero() && (create.RequestSHA256 == "" || create.FirstDispatchedAt.Before(j.BornAt) || create.FirstDispatchedAt.After(r.UpdatedAt)) ||
			create.SecretID != "" && (create.FirstDispatchedAt.IsZero() || !workerSecretPattern.MatchString(create.SecretID) || !strings.HasPrefix(create.SecretID, "ocid1.vaultsecret.oc1."+foundationHomeRegion+".") || len(create.SecretID) > 512) ||
			create.Version != 0 && (create.Version != 1 || create.SecretID == "" || !validFoundationDigest(create.ContentSHA256)) || create.Version == 0 && create.ContentSHA256 != "" {
			return errors.New("invalid original NetBird material creation checkpoint")
		}
		complete = complete && create.Version == 1
		if index > 0 && create.RequestSHA256 != "" && j.Creates[0].Version != 1 {
			return errors.New("NetBird derivation precedes independently pinned root")
		}
	}
	if j.Creates[0].RequestSHA256 == "" || j.Complete && !complete {
		return errors.New("NetBird material completion lacks all original refs")
	}
	return nil
}

func (next FoundationRecord) retainNetBirdMaterial(previous FoundationRecord) error {
	old, current := previous.NetBirdMaterial, next.NetBirdMaterial
	if old == nil {
		if current != nil {
			return errors.New("existing foundation journal cannot gain a material birth")
		}
		return nil
	}
	if current == nil || current.Authority != old.Authority || current.OriginalGrantSHA256 != old.OriginalGrantSHA256 ||
		current.OriginalBundleSHA256 != old.OriginalBundleSHA256 || !current.BornAt.Equal(old.BornAt) || old.Complete && !current.Complete ||
		next.AuxiliaryIDs["head_bucket"] != previous.AuxiliaryIDs["head_bucket"] || next.AuxiliaryIDs["ledger_bucket"] != previous.AuxiliaryIDs["ledger_bucket"] {
		return errors.New("original NetBird material birth cannot be reset")
	}
	for index, before := range old.Creates {
		after := current.Creates[index]
		if before.Name != after.Name || !retainedString(before.RequestSHA256, after.RequestSHA256) || !retainedString(before.RetryToken, after.RetryToken) ||
			!retainedString(before.SecretID, after.SecretID) || !retainedString(before.ContentSHA256, after.ContentSHA256) || !retainedString(before.HoldReason, after.HoldReason) || before.Version != 0 && before.Version != after.Version ||
			!before.FirstDispatchedAt.IsZero() && !before.FirstDispatchedAt.Equal(after.FirstDispatchedAt) {
			return errors.New("original NetBird material creation cannot be replaced")
		}
	}
	return nil
}

func (authority *HomeIAMAuthority) originalMaterialGrant() (FoundationGrant, error) {
	if authority == nil || authority.operator == nil {
		return FoundationGrant{}, errors.New("NetBird material requires authenticated original operator")
	}
	return decodeOriginalMaterialGrant(authority.operator.bundle)
}

func decodeOriginalMaterialGrant(bundle RetainedFoundation) (FoundationGrant, error) {
	envelope, err := trust.DecodeEnvelope(bundle.GrantWire)
	if err != nil {
		return FoundationGrant{}, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return FoundationGrant{}, err
	}
	return grant, nil
}

func netBirdMaterialRequest(a NetBirdMaterialAuthority, index int, value []byte) vault.CreateSecretRequest {
	details := vault.CreateSecretDetails{CompartmentId: new(a.Context.Target.CompartmentOCID), VaultId: new(a.Context.Target.VaultOCID), KeyId: new(a.Context.Target.KMSKeyOCID), SecretName: new(a.Names[index])}
	if index == 0 {
		// OCI requires this fixed vendor field to generate the root inside Vault.
		details.EnableAutoGeneration = new(true)
		details.SecretGenerationContext = vault.BytesGenerationContext{GenerationTemplate: vault.BytesGenerationContextGenerationTemplate512}
	} else {
		details.SecretContent = vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(value)), Stage: vault.SecretContentDetailsStageCurrent}
	}
	policy := common.NoRetryPolicy()
	return vault.CreateSecretRequest{CreateSecretDetails: details, RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
}

func netBirdMaterialRequestSHA(request vault.CreateSecretRequest) (string, error) {
	requestBody, err := request.HTTPRequest("POST", "/20180608/secrets", nil, nil)
	if err != nil || requestBody.Body == nil {
		return "", errors.New("NetBird material request cannot be serialized")
	}
	defer requestBody.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(requestBody.Body, 8193))
	defer clear(wire)
	if err != nil || len(wire) > 8192 {
		return "", errors.New("NetBird material request exceeds fixed bound")
	}
	return netBirdMaterialSHA(wire), nil
}

func (authority *HomeIAMAuthority) netBirdMaterialScope(grant FoundationGrant) (NetBirdMaterialAuthority, FoundationIntent, error) {
	if err := validateFoundationNetBirdMaterial(grant); err != nil {
		return NetBirdMaterialAuthority{}, FoundationIntent{}, err
	}
	for _, intent := range grant.Regions {
		if intent.Plan["cell"] == "GRU" && intent.NetBirdManager != nil && intent.NetBirdManager.Material != nil {
			a := *intent.NetBirdManager.Material
			if a.Context.ProducerUserID != authority.operator.id {
				return NetBirdMaterialAuthority{}, FoundationIntent{}, errors.New("authenticated original user differs from signed material producer")
			}
			return a, intent, nil
		}
	}
	return NetBirdMaterialAuthority{}, FoundationIntent{}, errors.New("original NetBird material purpose is absent")
}

func (authority *HomeIAMAuthority) checkNetBirdMaterialBirth(record FoundationRecord, grant FoundationGrant, a NetBirdMaterialAuthority, intent FoundationIntent) error {
	wire, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest, err := FoundationIntentDigest(intent)
	if err != nil {
		return err
	}
	j := record.NetBirdMaterial
	if j == nil || j.Authority != a || j.OriginalGrantSHA256 != netBirdMaterialSHA(authority.operator.bundle.GrantWire) ||
		j.OriginalBundleSHA256 != netBirdMaterialSHA(wire) || record.GrantSHA256 != j.OriginalGrantSHA256 || record.IntentDigest != digest ||
		record.Generation != intent.Generation || record.TenancyID != grant.TenancyID || record.ParentCompartmentID != grant.ParentCompartmentID || record.SharedCompartmentID != grant.SharedCompartmentID ||
		record.OperationID != entityid.Derive("regional-foundation", grant.TenancyID, "GRU", fmt.Sprint(intent.Generation)) ||
		record.AuxiliaryIDs["head_bucket"] != authority.operator.buckets["head_bucket"] || record.AuxiliaryIDs["ledger_bucket"] != authority.operator.buckets["ledger_bucket"] ||
		!j.Complete && (record.Stage != "material" || !record.netBirdMaterialOnly()) {
		return errors.New("NetBird material requires its exact retained original birth; HOLD")
	}
	return nil
}

func (authority *HomeIAMAuthority) reserveNetBirdMaterialBirth(ctx context.Context) error {
	grant, err := authority.originalMaterialGrant()
	if err != nil || grant.SchemaVersion != 3 {
		return err
	}
	a, intent, err := authority.netBirdMaterialScope(grant)
	if err != nil {
		return err
	}
	ctx, releaseLease, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer releaseLease()
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err == nil {
		return authority.checkNetBirdMaterialBirth(record, grant, a, intent)
	}
	if !errors.Is(err, ErrFoundationMissing) {
		return err
	}
	// Retained origins prove prior birth even when its mutable journal was lost.
	for _, origin := range grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			return err
		}
		_, err = readDiscoveryObject(ctx, authority.operator.objects, authority.operator.domain.Namespace, name, 1<<20)
		if service, missing := common.IsServiceError(err); missing && service.GetHTTPStatusCode() == 404 {
			continue
		}
		return errors.New("retained original origins without material birth refuse regeneration; HOLD")
	}
	if len(grant.WorkloadGenesis) != 9 {
		return errors.New("material birth requires all nine original origin keys")
	}
	wire, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest, err := FoundationIntentDigest(intent)
	if err != nil {
		return err
	}
	requestDigest, err := netBirdMaterialRequestSHA(netBirdMaterialRequest(a, 0, nil))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	j := &NetBirdMaterialJournal{Authority: a, OriginalGrantSHA256: netBirdMaterialSHA(authority.operator.bundle.GrantWire), OriginalBundleSHA256: netBirdMaterialSHA(wire), BornAt: now}
	for index, name := range a.Names {
		j.Creates[index].Name = name
	}
	j.Creates[0].RequestSHA256 = requestDigest
	j.Creates[0].RetryToken = BootstrapRetryToken(a.Context.ManagerOperationID+":"+a.Names[0], requestDigest)
	record = FoundationRecord{NetBirdMaterial: j, SchemaVersion: 1, Cell: "GRU", OCIRegion: foundationHomeRegion, TenancyID: grant.TenancyID,
		ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: intent.Generation, IntentDigest: digest, GrantSHA256: j.OriginalGrantSHA256,
		OperationID: entityid.Derive("regional-foundation", grant.TenancyID, "GRU", fmt.Sprint(intent.Generation)), Epoch: 1, Stage: "material", StartedAt: now, UpdatedAt: now,
		ResourceIDs: map[string]string{}, AuxiliaryIDs: maps.Clone(authority.operator.buckets)}
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	_, err = authority.resolver.Store.CompareAndSwap(ctx, record, "")
	return err
}

func (authority *HomeIAMAuthority) checkpointNetBirdMaterial(ctx context.Context, record *FoundationRecord, etag *string) error {
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	record.UpdatedAt = time.Now().UTC()
	next, err := authority.resolver.Store.CompareAndSwap(ctx, *record, *etag)
	if err == nil {
		*etag = next
	}
	return err
}

func (authority *HomeIAMAuthority) produceNetBirdMaterial(ctx context.Context) error {
	grant, err := authority.originalMaterialGrant()
	if err != nil || grant.SchemaVersion != 3 {
		return err
	}
	a, intent, err := authority.netBirdMaterialScope(grant)
	if err != nil {
		return err
	}
	ctx, releaseLease, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer releaseLease()
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	if err := authority.checkNetBirdMaterialOrigins(ctx, grant); err != nil {
		return err
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if err := authority.checkNetBirdMaterialBirth(record, grant, a, intent); err != nil {
		return err
	}
	management, err := vault.NewVaultsClientWithConfigurationProvider(authority.factory.Provider())
	if err != nil {
		return errors.New("original material Vault client unavailable")
	}
	management.SetRegion(foundationHomeRegion)
	authority.factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	bundles, err := authority.factory.SecretsContext(ctx)
	if err != nil {
		return errors.New("original material bundle client unavailable")
	}
	root, err := authority.retainNetBirdMaterialSecret(ctx, &management, &bundles, &record, &etag, 0, nil)
	if err != nil {
		return err
	}
	defer clear(root)
	for index := 1; index < len(a.Names); index++ {
		derived, err := hkdf.Key(sha256.New, root, []byte(a.LineageSHA256), netBirdMaterialDerivation+":"+netBirdMaterialPurposes[index], 32)
		if err != nil {
			return errors.New("original material derivation failed")
		}
		value := []byte(base64.StdEncoding.EncodeToString(derived))
		clear(derived)
		observed, err := authority.retainNetBirdMaterialSecret(ctx, &management, &bundles, &record, &etag, index, value)
		clear(value)
		clear(observed)
		if err != nil {
			return err
		}
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	if err := authority.checkNetBirdMaterialOrigins(ctx, grant); err != nil {
		return err
	}
	if !record.NetBirdMaterial.Complete {
		record.NetBirdMaterial.Complete = true
		return authority.checkpointNetBirdMaterial(ctx, &record, &etag)
	}
	return nil
}

func (authority *HomeIAMAuthority) checkNetBirdMaterialOrigins(ctx context.Context, grant FoundationGrant) error {
	expected, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil || len(grant.WorkloadGenesis) != 9 {
		return errors.New("original material requires nine retained origins")
	}
	for _, origin := range grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			return err
		}
		wire, err := readDiscoveryObject(ctx, authority.operator.objects, authority.operator.domain.Namespace, name, int64(len(expected)))
		if err != nil || !bytes.Equal(wire, expected) {
			return errors.New("original material lacks exact independent origin readbacks")
		}
	}
	return nil
}

func (authority *HomeIAMAuthority) retainNetBirdMaterialSecret(ctx context.Context, management *vault.VaultsClient, bundles *secrets.SecretsClient, record *FoundationRecord, etag *string, index int, value []byte) ([]byte, error) {
	a := record.NetBirdMaterial.Authority
	create := &record.NetBirdMaterial.Creates[index]
	if create.HoldReason != "" {
		return nil, errors.New("original material create is permanently unresolved; HOLD")
	}
	request := netBirdMaterialRequest(a, index, value)
	digest, err := netBirdMaterialRequestSHA(request)
	if err != nil {
		return nil, err
	}
	if create.RequestSHA256 == "" {
		if record.NetBirdMaterial.Complete || record.Stage != "material" || record.NetBirdManager != nil {
			return nil, errors.New("original launch or completed material refuses generation")
		}
		create.RequestSHA256, create.RetryToken = digest, BootstrapRetryToken(a.Context.ManagerOperationID+":"+a.Names[index], digest)
		if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
			return nil, err
		}
	}
	if create.RequestSHA256 != digest || create.RetryToken != BootstrapRetryToken(a.Context.ManagerOperationID+":"+a.Names[index], digest) {
		return nil, errors.New("original material request changed; HOLD")
	}
	if create.SecretID == "" {
		if record.NetBirdMaterial.Complete || record.Stage != "material" || record.NetBirdManager != nil {
			return nil, errors.New("original launch or completed material refuses regeneration")
		}
		if create.FirstDispatchedAt.IsZero() {
			create.FirstDispatchedAt = time.Now().UTC()
			if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
				return nil, err
			}
		}
		if time.Since(create.FirstDispatchedAt) >= 23*time.Hour || time.Now().Before(create.FirstDispatchedAt) {
			create.HoldReason = "retry-expired"
			if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
				return nil, err
			}
			return nil, errors.New("unknown original material create is outside retry lifetime; HOLD")
		}
		request.OpcRetryToken = new(create.RetryToken)
		if err := authority.Guard(ctx, 0); err != nil {
			return nil, err
		}
		response, err := management.CreateSecret(ociclient.RequestContext(ctx), request)
		if err != nil || response.Id == nil || !workerSecretPattern.MatchString(*response.Id) || !strings.HasPrefix(*response.Id, "ocid1.vaultsecret.oc1."+foundationHomeRegion+".") || len(*response.Id) > 512 {
			if service, refused := common.IsServiceError(err); refused && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 {
				create.HoldReason = "create-refused"
				if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
					return nil, err
				}
			}
			return nil, errors.New("original material create unresolved; retain original body and token; HOLD")
		}
		create.SecretID = *response.Id
		if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
			return nil, err
		}
	}
	if create.Version == 0 && time.Since(create.FirstDispatchedAt) >= 23*time.Hour {
		create.HoldReason = "retry-expired"
		if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
			return nil, err
		}
		return nil, errors.New("unpinned original material exceeds safe lifetime; HOLD")
	}
	observed, err := readNetBirdMaterialSecret(ctx, management, bundles, a, index, *create)
	if err != nil {
		return nil, err
	}
	if index > 0 && !bytes.Equal(observed, value) {
		clear(observed)
		return nil, errors.New("original derived material content changed; HOLD")
	}
	contentDigest := netBirdMaterialSHA(observed)
	if create.Version != 0 && (create.Version != 1 || create.ContentSHA256 != contentDigest) {
		clear(observed)
		return nil, errors.New("pinned original material content changed; HOLD")
	}
	if create.Version == 0 {
		create.Version, create.ContentSHA256 = 1, contentDigest
		if err := authority.checkpointNetBirdMaterial(ctx, record, etag); err != nil {
			clear(observed)
			return nil, err
		}
	}
	return observed, nil
}

func readNetBirdMaterialSecret(ctx context.Context, management *vault.VaultsClient, bundles *secrets.SecretsClient, a NetBirdMaterialAuthority, index int, create NetBirdMaterialCreate) ([]byte, error) {
	metadata, err := management.GetSecret(ociclient.RequestContext(ctx), vault.GetSecretRequest{SecretId: new(create.SecretID)})
	if err != nil || deref(metadata.Id) != create.SecretID || deref(metadata.SecretName) != a.Names[index] || deref(metadata.CompartmentId) != a.Context.Target.CompartmentOCID ||
		deref(metadata.VaultId) != a.Context.Target.VaultOCID || deref(metadata.KeyId) != a.Context.Target.KMSKeyOCID || metadata.LifecycleState != vault.SecretLifecycleStateActive ||
		metadata.CurrentVersionNumber == nil || *metadata.CurrentVersionNumber != 1 || metadata.RotationConfig != nil || metadata.ReplicationConfig != nil || metadata.TimeOfDeletion != nil || metadata.LastRotationTime != nil || metadata.NextRotationTime != nil ||
		metadata.TimeOfCurrentVersionExpiry != nil || len(metadata.SecretRules) != 0 || metadata.IsReplica != nil && *metadata.IsReplica {
		return nil, errors.New("original material metadata differs from exact immutable target; HOLD")
	}
	if index == 0 {
		generation, ok := metadata.SecretGenerationContext.(vault.BytesGenerationContext)
		if !ok || generation.GenerationTemplate != vault.BytesGenerationContextGenerationTemplate512 || generation.SecretTemplate != nil || metadata.IsAutoGenerationEnabled == nil || !*metadata.IsAutoGenerationEnabled {
			return nil, errors.New("original root generation context changed; HOLD")
		}
	} else if metadata.SecretGenerationContext != nil || metadata.IsAutoGenerationEnabled != nil && *metadata.IsAutoGenerationEnabled {
		return nil, errors.New("original child material unexpectedly generates or rotates")
	}
	bundle, err := bundles.GetSecretBundle(ociclient.RequestContext(ctx), secrets.GetSecretBundleRequest{SecretId: new(create.SecretID), VersionNumber: new(int64(1)), Stage: secrets.GetSecretBundleStageCurrent})
	if err != nil || deref(bundle.SecretId) != create.SecretID || bundle.VersionNumber == nil || *bundle.VersionNumber != 1 ||
		!slices.Contains(bundle.Stages, secrets.SecretBundleStagesCurrent) || bundle.TimeOfDeletion != nil || bundle.TimeOfExpiry != nil {
		return nil, errors.New("original material version1 CURRENT readback failed; HOLD")
	}
	content, ok := bundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(1024) {
		return nil, errors.New("original material bundle exceeds transport bound")
	}
	opaque, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || base64.StdEncoding.EncodeToString(opaque) != *content.Content || index == 0 && (len(opaque) < 64 || len(opaque) > 1024) || index > 0 && len(opaque) != 44 {
		clear(opaque)
		return nil, errors.New("original material has invalid bounded transport content")
	}
	return opaque, nil
}
