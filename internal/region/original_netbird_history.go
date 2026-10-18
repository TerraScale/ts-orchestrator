package region

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// OriginalFoundationNetBirdManager is a finite original-user prerequisite.
// Physical completion alone grants no local custody, credentials or runtime.
type OriginalFoundationNetBirdManager struct {
	Intent               NetBirdManagerIntent               `json:"intent"`
	Plan                 map[string]any                     `json:"plan"`
	Allocation           BootstrapSlotIntent                `json:"allocation"`
	GrantSHA256          string                             `json:"grantSha256"`
	BundleSHA256         string                             `json:"bundleSha256"`
	IntentSHA256         string                             `json:"intentSha256"`
	NetworkProofSHA256   string                             `json:"networkProofSha256"`
	VaultProofSHA256     string                             `json:"vaultProofSha256"`
	MaterialSHA256       string                             `json:"materialSha256"`
	ControlCompartmentID string                             `json:"controlCompartmentId"`
	NetworkCompartmentID string                             `json:"networkCompartmentId"`
	Creates              [6]OriginalFoundationNetworkCreate `json:"creates"`
	Launch               *NetBirdManagerLaunch              `json:"launch,omitempty"`
	PrimaryVNICID        string                             `json:"primaryVnicId,omitempty"`
	ReadbackSHA256       string                             `json:"readbackSha256,omitempty"`
	VerifiedAt           time.Time                          `json:"verifiedAt,omitzero"`
	HoldReason           string                             `json:"holdReason,omitempty"`
	OCIRIssuances        map[string]OCIRIssuanceEntry       `json:"ocirIssuances,omitempty"`
	Backup               *OriginalNetBirdBackupJournal      `json:"backup,omitempty"`
}

var originalNetBirdNetworkKeys = [6]string{"netbird_manager_vcn", "netbird_manager_internet_gateway", "netbird_manager_route", "netbird_manager_security_list", "netbird_manager_nsg", "netbird_manager_subnet"}

func originalNetBirdManagerScope(record FoundationRecord, intent NetBirdManagerIntent, slot BootstrapSlotIntent) (OriginalFoundationNetBirdManager, error) {
	var scope OriginalFoundationNetBirdManager
	if err := originalActorPrerequisiteRecord(record); err != nil {
		return scope, err
	}
	root := record.OriginalFoundationCompartments
	region := root.Regions[0]
	material := record.NetBirdMaterial
	if intent.validate() != nil || intent.Material == nil || !sameOriginalSourceValue(*intent.Material, material.Authority) || intent.StoreOrigin != "new" || record.validateNetBirdMaterial() != nil || !material.Complete ||
		intent.Material.Context.InstallationID != (*record.OriginalSourceProducers)[0].Intent.InstallationID || intent.Material.Context.TenancyID != record.TenancyID || intent.Material.Context.ProducerUserID != root.UserID {
		return scope, ErrOriginalSourceProducerHold
	}
	for _, entry := range material.Creates {
		if entry.Version != 1 || entry.SecretID == "" || entry.ContentSHA256 == "" || entry.HoldReason != "" {
			return scope, ErrOriginalSourceProducerHold
		}
	}
	profile, err := NetBirdManagerProfileDigest(intent.Profile)
	if err != nil {
		return scope, err
	}
	envelope, err := trust.DecodeEnvelope(intent.ImageReceiptWire)
	if err != nil {
		return scope, err
	}
	var receipt release.ImageReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt, json.RejectUnknownMembers(true)); err != nil || receipt.Validate() != nil || receipt.OCIImageOCID != intent.ImageOCID || receipt.Architecture != intent.Architecture || receipt.OCIRegion != "GRU" {
		return scope, ErrOriginalSourceProducerHold
	}
	recipe, err := NetBirdManagerRecipeDigest(intent, receipt.ImageSHA256)
	if err != nil {
		return scope, err
	}
	control := originalCompartmentID(region.Compartments[0])
	p := intent.Profile
	if slot.SlotID != material.Authority.Context.ManagerSlotID || slot.Cell != "GRU" || slot.Role != NetBirdManagerRole || slot.Slot != NetBirdManagerRole || slot.ProfileSHA256 != profile || slot.RecipeSHA256 != recipe ||
		!originalActorRole("GRU", "control_compartment", slot.CompartmentID, control) || slot.Shape != p.Shape || slot.OCPUs != float64(p.OCPUs) || slot.MemoryGB != float64(p.MemoryGB) || slot.BootGB != float64(p.BootVolumeGB) || slot.MonthlyLimitMinor <= 0 || slot.MonthlyLimitMinor > root.MonthlyLimitMinor {
		return scope, ErrOriginalSourceProducerHold
	}
	networkWire, err := json.Marshal(region.Network, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	vaultWire, err := json.Marshal(region.Vault, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	materialWire, err := json.Marshal(material, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope = OriginalFoundationNetBirdManager{Intent: intent, Plan: region.Network.Plan, Allocation: slot, GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256, IntentSHA256: region.IntentSHA256,
		NetworkProofSHA256: digestSource(networkWire), VaultProofSHA256: digestSource(vaultWire), MaterialSHA256: digestSource(materialWire), ControlCompartmentID: control, NetworkCompartmentID: originalCompartmentID(region.Compartments[1])}
	for index, key := range originalNetBirdNetworkKeys {
		scope.Creates[index].Key = key
	}
	return scope, nil
}

func (m OriginalFoundationNetBirdManager) scopeOnly() OriginalFoundationNetBirdManager {
	for index, key := range originalNetBirdNetworkKeys {
		m.Creates[index] = OriginalFoundationNetworkCreate{Key: key}
	}
	m.Launch, m.OCIRIssuances, m.Backup = nil, nil, nil
	m.PrimaryVNICID, m.ReadbackSHA256, m.HoldReason, m.VerifiedAt = "", "", "", time.Time{}
	return m
}

func originalNetBirdManagerIDs(manager *OriginalFoundationNetBirdManager) map[string]string {
	ids := map[string]string{}
	if manager != nil {
		for _, entry := range manager.Creates {
			if entry.Provenance != nil {
				ids[entry.Key] = entry.Provenance.ResourceID
			}
		}
	}
	return ids
}

func validOriginalNetBirdNetworkID(key, id string) bool {
	index := slices.Index(originalNetBirdNetworkKeys[:], key)
	if index < 0 || len(id) > 512 || strings.ContainsAny(id, "\x00\r\n /\\") {
		return false
	}
	kind := [6]string{"vcn", "internetgateway", "routetable", "securitylist", "networksecuritygroup", "subnet"}[index]
	prefix := "ocid1." + kind + ".oc1." + foundationHomeRegion + "."
	suffix, ok := strings.CutPrefix(id, prefix)
	if !ok || suffix == "" {
		return false
	}
	for component := range strings.SplitSeq(suffix, ".") {
		if component == "" {
			return false
		}
		for _, ch := range component {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}

func originalNetBirdManagerReadback(manager *OriginalFoundationNetBirdManager, boot, vnic string) (string, error) {
	if manager == nil || manager.Launch == nil || manager.Launch.OriginalQuote == nil {
		return "", ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal(struct{ InstanceID, BootVolumeID, PrimaryVNICID, RequestSHA256, QuoteSHA256 string }{manager.Launch.InstanceID, boot, vnic, manager.Launch.RequestDigest, manager.Launch.OriginalQuote.SHA256()}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func originalNetBirdManagerState(record FoundationRecord) (*OriginalFoundationNetBirdManager, error) {
	if record.validateOriginalFoundationCompartments() != nil || record.validateOriginalNetBirdManager() != nil || record.OriginalFoundationCompartments == nil {
		return nil, ErrOriginalSourceProducerHold
	}
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if manager == nil {
		return nil, ErrOriginalSourceProducerHold
	}
	return manager, nil
}

func (record FoundationRecord) validateOriginalNetBirdManager() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	if root.Regions[1].NetBirdManager != nil || root.Regions[2].NetBirdManager != nil {
		return ErrOriginalSourceProducerHold
	}
	m := root.Regions[0].NetBirdManager
	if m == nil {
		return nil
	}
	expected, err := originalNetBirdManagerScope(record, m.Intent, m.Allocation)
	if err != nil || !sameOriginalSourceValue(m.scopeOnly(), expected) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if err := validateOriginalNetBirdOCIRJournal(m); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, region := range root.Regions {
		if region.Network != nil {
			for _, entry := range region.Network.Creates {
				if entry.Provenance != nil {
					seen[entry.Provenance.ResourceID] = true
				}
			}
		}
		if id := originalActorID(region.Actor); id != "" {
			seen[id] = true
		}
	}
	for index, entry := range m.Creates {
		if entry.Key != originalNetBirdNetworkKeys[index] {
			return ErrOriginalSourceProducerHold
		}
		if entry.Pending == nil {
			if entry.Provenance != nil || entry.ReadbackSHA256 != "" || !entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		for previous := 0; previous < index; previous++ {
			p := m.Creates[previous]
			if p.Provenance == nil || p.VerifiedAt.IsZero() || p.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
		}
		pending := *entry.Pending
		operation := record.NetBirdMaterial.Authority.Context.ManagerOperationID
		if pending.OperationID != operation || pending.IntentDigest != record.IntentDigest || pending.Request.Key != entry.Key || pending.Request.Region != foundationHomeRegion || !validFoundationDigest(pending.Request.RequestDigest) ||
			pending.Request.RetryToken != originalNetBirdNetworkToken(operation, entry.Key, pending.Request.RequestDigest) || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(root.BornAt) || pending.FirstAttemptAt.After(record.UpdatedAt) {
			return ErrOriginalSourceProducerHold
		}
		if entry.Provenance != nil {
			proof := entry.Provenance
			if !sameOriginalSourceValue(proof.Create, pending) || proof.GrantSHA256 != root.GrantSHA256 || proof.Generation != record.Generation || !validOriginalNetBirdNetworkID(entry.Key, proof.ResourceID) || seen[proof.ResourceID] || entry.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			seen[proof.ResourceID] = true
		}
		if entry.HoldReason != "" && (entry.Provenance != nil || !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved"}, entry.HoldReason)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() && (entry.Provenance == nil || entry.VerifiedAt.Before(pending.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.ReadbackSHA256 != "" {
			wire, err := json.Marshal([]string{entry.Provenance.ResourceID, pending.Request.RequestDigest, "AVAILABLE"}, json.Deterministic(true))
			if err != nil || entry.ReadbackSHA256 != digestSource(wire) {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	if m.Launch == nil {
		if m.PrimaryVNICID != "" || m.ReadbackSHA256 != "" || !m.VerifiedAt.IsZero() || m.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	for _, entry := range m.Creates {
		if entry.Provenance == nil || entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	l := m.Launch
	if err := l.Account.validate(m.Intent.Account); err != nil {
		return err
	}
	if l.Account != nil && !l.Account.BornAt.Equal(l.StartedAt) {
		return ErrOriginalSourceProducerHold
	}
	slot := m.Allocation
	physical, err := originalActorPhysicalScope(record, 0, time.Time{})
	logical, logicalErr := originalActorSignedScope(record)
	if err != nil || logicalErr != nil || l.validate() != nil || l.OriginalQuote == nil || l.SlotID != slot.SlotID || l.OperationID != record.NetBirdMaterial.Authority.Context.ManagerOperationID || l.ProfileSHA256 != slot.ProfileSHA256 || l.RecipeSHA256 != slot.RecipeSHA256 ||
		l.OriginGrantSHA256 != root.GrantSHA256 || l.OriginalScopeSHA256 != logical.SHA256 || l.PhysicalScopeSHA256 != physical.SHA256 || l.StartedAt.Before(root.BornAt) || l.StartedAt.After(record.UpdatedAt) || l.RetryToken != BootstrapRetryToken(l.OperationID, l.RequestDigest) {
		return errors.Join(ErrOriginalSourceProducerHold, err, logicalErr)
	}
	scopeWire, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil || l.OriginBindingSHA256 != digestSource(scopeWire) {
		return ErrOriginalSourceProducerHold
	}
	ids := originalNetBirdManagerIDs(m)
	details := netBirdLaunchDetails(m.Intent, m.ControlCompartmentID, ids["netbird_manager_subnet"], ids["netbird_manager_nsg"])
	digest, err := netBirdRequestDigest(details)
	if err != nil || digest != l.RequestDigest || l.validateOriginalQuote(details) != nil || l.OriginalQuote.Currency != root.Currency || l.OriginalQuote.MonthlyCents == 0 || l.OriginalQuote.MonthlyCents > uint64(slot.MonthlyLimitMinor) {
		return ErrOriginalSourceProducerHold
	}
	if m.HoldReason != "" && (l.InstanceID != "" || !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved"}, m.HoldReason)) {
		return ErrOriginalSourceProducerHold
	}
	if l.InstanceID != "" {
		if !validOriginalActorID("instance", foundationHomeRegion, l.InstanceID) || seen[l.InstanceID] {
			return ErrOriginalSourceProducerHold
		}
		seen[l.InstanceID] = true
	}
	if m.VerifiedAt.IsZero() {
		if m.PrimaryVNICID != "" || m.ReadbackSHA256 != "" || l.BootVolumeID != "" || l.StoreState != "empty" {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	if m.HoldReason != "" || l.InstanceID == "" || !validOriginalActorID("bootvolume", foundationHomeRegion, l.BootVolumeID) || !validOriginalActorID("vnic", foundationHomeRegion, m.PrimaryVNICID) || seen[l.BootVolumeID] || seen[m.PrimaryVNICID] || m.VerifiedAt.Before(l.StartedAt) || m.VerifiedAt.After(record.UpdatedAt) {
		return ErrOriginalSourceProducerHold
	}
	readback, err := originalNetBirdManagerReadback(m, l.BootVolumeID, m.PrimaryVNICID)
	if err != nil || m.ReadbackSHA256 != readback {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func validateOriginalNetBirdAllocation(grant FoundationGrant, record FoundationRecord, intent verifiedNetBirdIntent, now time.Time) error {
	m, err := originalNetBirdManagerState(record)
	if err != nil {
		return err
	}
	if grant.SchemaVersion != 3 || grant.Generation != 1 || grant.InstallationID != intent.installationID || grant.TenancyID != record.TenancyID || intent.grantDigest != record.GrantSHA256 || !now.Before(intent.expires) || !sameOriginalSourceValue(m.Intent, intent.intent) {
		return ErrOriginalSourceProducerHold
	}
	slot, err := originalNetBirdSignedSlot(grant)
	if err != nil || !sameOriginalSourceValue(slot, m.Allocation) || ValidatePreparedFoundation(grant) != nil {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func (next FoundationRecord) retainOriginalNetBirdManager(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		return nil
	}
	old := before.Regions[0].NetBirdManager
	if after == nil {
		if old != nil {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	current := after.Regions[0].NetBirdManager
	if old == nil {
		if current != nil {
			expected, err := originalNetBirdManagerScope(next, current.Intent, current.Allocation)
			if err != nil || !sameOriginalSourceValue(current, expected) {
				return ErrOriginalSourceProducerHold
			}
		}
		return nil
	}
	if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) || !retainedString(old.PrimaryVNICID, current.PrimaryVNICID) || !retainedString(old.ReadbackSHA256, current.ReadbackSHA256) || !retainedString(old.HoldReason, current.HoldReason) || !old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) {
		return ErrOriginalSourceProducerHold
	}
	for index, entry := range old.Creates {
		n := current.Creates[index]
		if entry.Key != n.Key || entry.Pending != nil && !sameOriginalSourceValue(entry.Pending, n.Pending) || entry.Provenance != nil && !sameOriginalSourceValue(entry.Provenance, n.Provenance) || !retainedString(entry.ReadbackSHA256, n.ReadbackSHA256) || !retainedString(entry.HoldReason, n.HoldReason) || !entry.VerifiedAt.IsZero() && !entry.VerifiedAt.Equal(n.VerifiedAt) {
			return ErrOriginalSourceProducerHold
		}
	}
	if old.Launch != nil {
		if current.Launch == nil {
			return ErrOriginalSourceProducerHold
		}
		if err := (FoundationRecord{NetBirdManager: current.Launch}).retainNetBirdManager(FoundationRecord{NetBirdManager: old.Launch}); err != nil {
			return err
		}
	} else if current.Launch != nil {
		if current.Launch.StoreState != "empty" || current.Launch.InstanceID != "" || current.Launch.BootVolumeID != "" || current.Launch.ComponentFloors != nil {
			return ErrOriginalSourceProducerHold
		}
		var account *NetBirdAccountJournal
		if current.Intent.Account != nil {
			account = newNetBirdAccountJournal(*current.Intent.Account, current.Launch.StartedAt)
		}
		if !sameOriginalSourceValue(current.Launch.Account, account) {
			return ErrOriginalSourceProducerHold
		}
	}
	return retainOriginalNetBirdOCIRJournal(old, current)
}
