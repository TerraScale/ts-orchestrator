package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const netBirdMaterialDerivation = "netbird-manager-config-hkdf-sha256-v1"

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
		if err != nil {
			return fmt.Errorf("original material lacks exact independent origin readbacks for %s: %w", name, err)
		}
		if !bytes.Equal(wire, expected) {
			return fmt.Errorf("original material lacks exact independent origin readbacks for %s: bytes differ (expected %d, observed %d)", name, len(expected), len(wire))
		}
	}
	return nil
}
