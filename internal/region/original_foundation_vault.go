package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

var ErrOriginalFoundationVaultPending = fmt.Errorf("%w: original regional Vault and key retained; original actor and material archive remain unavailable", ErrOriginalSourceProducerHold)

// OriginalFoundationVault retains prerequisites, never runtime or material authority.
type OriginalFoundationVault struct {
	ControlCompartmentID string                          `json:"controlCompartmentId"`
	NetworkProofSHA256   string                          `json:"networkProofSha256"`
	Vault                OriginalFoundationVaultResource `json:"vault"`
	Key                  OriginalFoundationVaultKey      `json:"key"`
}

type OriginalFoundationKMSCreate struct {
	SelectedID     string                        `json:"selectedId,omitempty"`
	Pending        *PendingFoundationCreate      `json:"pending,omitempty"`
	Provenance     *FoundationResourceProvenance `json:"provenance,omitempty"`
	ReadbackSHA256 string                        `json:"readbackSha256,omitempty"`
	VerifiedAt     time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason     string                        `json:"holdReason,omitempty"`
}

type OriginalFoundationVaultResource struct {
	OriginalFoundationKMSCreate
	Request            keymanagement.CreateVaultDetails `json:"request"`
	ManagementEndpoint string                           `json:"managementEndpoint,omitempty"`
}

type OriginalFoundationVaultKey struct {
	OriginalFoundationKMSCreate
	Request            keymanagement.CreateKeyDetails `json:"request"`
	VaultID            string                         `json:"vaultId,omitempty"`
	ManagementEndpoint string                         `json:"managementEndpoint,omitempty"`
	CurrentKeyVersion  string                         `json:"currentKeyVersion,omitempty"`
}

var originalKMSID = regexp.MustCompile(`^ocid1\.(vault|key|keyversion)\.oc1\.[a-z0-9-]+\.[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*$`)

func validOriginalKMSID(kind, region, id string) bool {
	return len(id) <= 512 && originalKMSID.MatchString(id) && strings.HasPrefix(id, "ocid1."+kind+".oc1."+region+".")
}

func provisionOriginalFoundationVault(ctx context.Context, authority *HomeIAMAuthority) error {
	if err := retainOriginalFoundationVault(ctx, authority); err != nil {
		return err
	}
	return provisionOriginalFoundationActors(ctx, authority)
}

func retainOriginalFoundationVault(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, err := originalVaultPrerequisites(ctx, authority, true)
	if err != nil {
		return err
	}
	if err := record.validateOriginalFoundationVault(); err != nil {
		return err
	}
	changed := false
	for index := range record.OriginalFoundationCompartments.Regions {
		expected, err := originalVaultScope(record, index)
		if err != nil {
			return err
		}
		region := &record.OriginalFoundationCompartments.Regions[index]
		if region.Vault == nil {
			region.Vault = &expected
			changed = true
		}
	}
	if changed {
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	for index := range record.OriginalFoundationCompartments.Regions {
		region := record.OriginalFoundationCompartments.Regions[index]
		v := region.Vault
		if !v.Vault.VerifiedAt.IsZero() && !v.Key.VerifiedAt.IsZero() {
			if v.Vault.ReadbackSHA256 == "" || v.Key.ReadbackSHA256 == "" || v.Vault.HoldReason != "" || v.Key.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			regional, err := authority.factory.ForRegion(region.OCIRegion)
			if err != nil {
				return err
			}
			reader := sdkcli.NewClient(regional, "")
			endpoint, err := readOriginalVault(ctx, reader, v)
			if err != nil {
				return err
			}
			if endpoint != v.Vault.ManagementEndpoint {
				return ErrOriginalSourceProducerHold
			}
			version, err := readOriginalVaultKey(ctx, reader, region.OCIRegion, v)
			if err != nil {
				return err
			}
			if version != v.Key.CurrentKeyVersion {
				return ErrOriginalSourceProducerHold
			}
			for slot := range 2 {
				entry := originalVaultEntry(v, slot)
				readback, err := originalVaultReadback(v, slot, originalVaultID(*entry))
				if err != nil || readback != entry.ReadbackSHA256 {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		for slot := range 2 {
			if err := provisionOriginalVaultResource(ctx, authority, index, slot); err != nil {
				return err
			}
		}
	}
	return nil
}

// originalVaultPrerequisites requires the complete original network journal.
// With fresh it also re-reads every network resource; the Vault stage does
// that once per run, since KMS effects do not use network resources.
func originalVaultPrerequisites(ctx context.Context, authority *HomeIAMAuthority, fresh bool) (FoundationRecord, string, error) {
	if _, err := originalCompartmentScope(ctx, authority); err != nil {
		return FoundationRecord{}, "", err
	}
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return record, "", err
	}
	if record.OriginalFoundationCompartments == nil {
		return record, "", ErrOriginalSourceProducerHold
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		if region.Network == nil || !region.Network.Complete {
			return record, "", ErrOriginalSourceProducerHold
		}
	}
	if !fresh {
		if err := record.validateOriginalFoundationNetwork(); err != nil {
			return record, "", err
		}
		return authority.resolver.Store.Load(ctx, "GRU")
	}
	// The complete journal permits only fresh exact network reads in this helper.
	if err := retainOriginalFoundationNetwork(ctx, authority); err != nil {
		return record, "", err
	}
	return authority.resolver.Store.Load(ctx, "GRU")
}

func originalVaultScope(record FoundationRecord, index int) (OriginalFoundationVault, error) {
	var scope OriginalFoundationVault
	if record.OriginalFoundationCompartments == nil || record.OriginalSourceProducers == nil || index < 0 || index >= 3 {
		return scope, ErrOriginalSourceProducerHold
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		if region.Network == nil || !region.Network.Complete {
			return scope, ErrOriginalSourceProducerHold
		}
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	control := region.Compartments[0]
	if control.VerifiedAt.IsZero() || control.HoldReason != "" {
		return scope, ErrOriginalSourceProducerHold
	}
	ids, ok := region.Network.Plan["resource_ids"].(map[string]any)
	if !ok {
		return scope, ErrOriginalSourceProducerHold
	}
	selected := [2]string{}
	for slot, kind := range [2]string{"vault", "key"} {
		if value := ids[kind]; value != nil {
			var valid bool
			selected[slot], valid = value.(string)
			if !valid || !validOriginalKMSID(kind, region.OCIRegion, selected[slot]) {
				return scope, ErrOriginalSourceProducerHold
			}
		}
	}
	if index == 0 {
		escrow := (*record.OriginalSourceProducers)[0].Intent.Escrow
		if selected[0] != escrow.VaultOCID || selected[1] != escrow.KMSKeyOCID || originalCompartmentID(control) != escrow.CompartmentOCID {
			return scope, ErrOriginalSourceProducerHold
		}
	}
	wire, err := json.Marshal(region.Network, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	name := strings.ToLower(region.Cell) + "-1"
	scope.ControlCompartmentID, scope.NetworkProofSHA256 = originalCompartmentID(control), digestSource(wire)
	scope.Vault.SelectedID, scope.Key.SelectedID = selected[0], selected[1]
	scope.Vault.Request = keymanagement.CreateVaultDetails{CompartmentId: new(scope.ControlCompartmentID), DisplayName: new(name + "-vault"), VaultType: keymanagement.CreateVaultDetailsVaultTypeDefault}
	scope.Key.Request = keymanagement.CreateKeyDetails{CompartmentId: new(scope.ControlCompartmentID), DisplayName: new(name + "-key"), KeyShape: &keymanagement.KeyShape{Algorithm: keymanagement.KeyShapeAlgorithmAes, Length: new(32)}, ProtectionMode: keymanagement.CreateKeyDetailsProtectionModeHsm}
	return scope, nil
}

func originalVaultEntry(v *OriginalFoundationVault, slot int) *OriginalFoundationKMSCreate {
	if slot == 0 {
		return &v.Vault.OriginalFoundationKMSCreate
	}
	return &v.Key.OriginalFoundationKMSCreate
}

func originalVaultID(entry OriginalFoundationKMSCreate) string {
	if entry.Provenance != nil {
		return entry.Provenance.ResourceID
	}
	return entry.SelectedID
}

func originalVaultRequestSHA(v *OriginalFoundationVault, slot int) (string, error) {
	var request http.Request
	var err error
	if slot == 0 {
		request, err = (keymanagement.CreateVaultRequest{CreateVaultDetails: v.Vault.Request}).HTTPRequest(http.MethodPost, "/20180608/vaults", nil, nil)
	} else {
		request, err = (keymanagement.CreateKeyRequest{CreateKeyDetails: v.Key.Request}).HTTPRequest(http.MethodPost, "/20180608/keys", nil, nil)
	}
	if err != nil || request.Body == nil {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	defer request.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(request.Body, 8193))
	if err != nil || len(wire) > 8192 {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(object, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(canonical), nil
}

func originalVaultCreateIdentity(region OriginalFoundationCompartmentRegion, slot int, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: [2]string{"vault", "key"}[slot], Region: region.OCIRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(region.OperationID, digest)}
}

func originalVaultReadback(v *OriginalFoundationVault, slot int, id string) (string, error) {
	digest, err := originalVaultRequestSHA(v, slot)
	if err != nil {
		return "", err
	}
	pins := []string{id, digest, v.Vault.ManagementEndpoint, "ACTIVE"}
	if slot == 1 {
		pins = []string{id, digest, v.Key.VaultID, v.Key.ManagementEndpoint, v.Key.CurrentKeyVersion, "ENABLED"}
	}
	wire, err := json.Marshal(pins, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func readOriginalVault(ctx context.Context, reader *sdkcli.Client, v *OriginalFoundationVault) (string, error) {
	client, err := reader.KMSVaults()
	if err != nil {
		return "", err
	}
	id := originalVaultID(v.Vault.OriginalFoundationKMSCreate)
	response, err := client.GetVault(ociclient.RequestContext(ctx), keymanagement.GetVaultRequest{VaultId: new(id)})
	if err != nil {
		return "", err
	}
	actual := response.Vault
	endpoint := deref(actual.ManagementEndpoint)
	if deref(actual.Id) != id || deref(actual.CompartmentId) != v.ControlCompartmentID || deref(actual.DisplayName) != deref(v.Vault.Request.DisplayName) || actual.VaultType != keymanagement.VaultVaultTypeDefault || actual.LifecycleState != keymanagement.VaultLifecycleStateActive || actual.TimeOfDeletion != nil || deref(actual.RestoredFromVaultId) != "" || actual.ReplicaDetails != nil || actual.IsPrimary != nil && !*actual.IsPrimary || actual.IsVaultReplicable != nil && *actual.IsVaultReplicable || actual.ExternalKeyManagerMetadataSummary != nil || endpoint == "" || v.Vault.ManagementEndpoint != "" && v.Vault.ManagementEndpoint != endpoint {
		return "", ErrOriginalSourceProducerHold
	}
	if _, err := reader.KMSManagement(endpoint); err != nil {
		return "", err
	}
	return endpoint, nil
}

func readOriginalVaultKey(ctx context.Context, reader *sdkcli.Client, region string, v *OriginalFoundationVault) (string, error) {
	endpoint, err := readOriginalVault(ctx, reader, v)
	if err != nil || v.Key.VaultID != originalVaultID(v.Vault.OriginalFoundationKMSCreate) || v.Key.ManagementEndpoint != endpoint {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	client, err := reader.KMSManagement(endpoint)
	if err != nil {
		return "", err
	}
	id := originalVaultID(v.Key.OriginalFoundationKMSCreate)
	response, err := client.GetKey(ociclient.RequestContext(ctx), keymanagement.GetKeyRequest{KeyId: new(id)})
	if err != nil {
		return "", err
	}
	actual := response.Key
	version := deref(actual.CurrentKeyVersion)
	if deref(actual.Id) != id || deref(actual.CompartmentId) != v.ControlCompartmentID || deref(actual.DisplayName) != deref(v.Key.Request.DisplayName) || deref(actual.VaultId) != v.Key.VaultID || actual.LifecycleState != keymanagement.KeyLifecycleStateEnabled || actual.ProtectionMode != keymanagement.KeyProtectionModeHsm || !sameOriginalSourceValue(actual.KeyShape, v.Key.Request.KeyShape) || actual.TimeOfDeletion != nil || deref(actual.RestoredFromKeyId) != "" || actual.ReplicaDetails != nil || actual.IsPrimary != nil && !*actual.IsPrimary || actual.IsAutoRotationEnabled != nil && *actual.IsAutoRotationEnabled || actual.AutoKeyRotationDetails != nil || actual.ExternalKeyReferenceDetails != nil || !validOriginalKMSID("keyversion", region, version) || v.Key.CurrentKeyVersion != "" && v.Key.CurrentKeyVersion != version {
		return "", ErrOriginalSourceProducerHold
	}
	return version, nil
}

func provisionOriginalVaultResource(ctx context.Context, authority *HomeIAMAuthority, index, slot int) error {
	record, etag, err := originalVaultPrerequisites(ctx, authority, false)
	if err != nil {
		return err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	v := region.Vault
	if v == nil || originalVaultEntry(v, slot).HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	regional, err := authority.factory.ForRegion(region.OCIRegion)
	if err != nil {
		return err
	}
	reader := sdkcli.NewClient(regional, "")
	if slot == 1 {
		if v.Vault.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
		endpoint, err := readOriginalVault(ctx, reader, v)
		if err != nil {
			return err
		}
		if v.Key.VaultID == "" {
			v.Key.VaultID, v.Key.ManagementEndpoint = originalVaultID(v.Vault.OriginalFoundationKMSCreate), endpoint
			if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
				return err
			}
		} else if v.Key.VaultID != originalVaultID(v.Vault.OriginalFoundationKMSCreate) || v.Key.ManagementEndpoint != endpoint {
			return ErrOriginalSourceProducerHold
		}
	}
	entry := originalVaultEntry(v, slot)
	digest, err := originalVaultRequestSHA(v, slot)
	if err != nil {
		return err
	}
	if entry.SelectedID == "" && entry.Provenance == nil {
		if entry.Pending == nil {
			entry.Pending = &PendingFoundationCreate{OperationID: region.OperationID, IntentDigest: region.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalVaultCreateIdentity(region, slot, digest)}
			if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
				return err
			}
		}
		pending := *entry.Pending
		if !time.Now().Before(pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			entry.HoldReason = "retry-expired"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		guard := func(dispatchCtx context.Context) error {
			checkCtx := ociclient.CheckpointContext(dispatchCtx)
			saved, _, err := originalVaultPrerequisites(checkCtx, authority, false)
			if err != nil {
				return err
			}
			current := saved.OriginalFoundationCompartments.Regions[index].Vault
			if current == nil || !sameOriginalSourceValue(current, v) || originalVaultEntry(current, slot).Provenance != nil || !sameOriginalSourceValue(originalVaultEntry(current, slot).Pending, pending) {
				return ErrOriginalSourceProducerHold
			}
			if slot == 1 {
				endpoint, err := readOriginalVault(checkCtx, reader, current)
				if err != nil || current.Key.ManagementEndpoint != endpoint || current.Key.VaultID != originalVaultID(current.Vault.OriginalFoundationKMSCreate) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			for _, deadline := range []time.Time{authority.operator.deadline, pending.FirstAttemptAt.Add(bootstrapRetryLifetime)} {
				if err := ociclient.LimitAdmission(dispatchCtx, deadline); err != nil {
					return err
				}
			}
			return nil
		}
		if err := guard(ctx); err != nil {
			return err
		}
		noRetry := common.NoRetryPolicy()
		metadata := common.RequestMetadata{RetryPolicy: &noRetry}
		createCtx := ociclient.RequestContext(ociclient.WithAuthority(ctx, guard))
		var id string
		if slot == 0 {
			client, clientErr := reader.KMSVaults()
			if clientErr != nil {
				return clientErr
			}
			response, createErr := client.CreateVault(createCtx, keymanagement.CreateVaultRequest{CreateVaultDetails: v.Vault.Request, OpcRetryToken: new(pending.Request.RetryToken), RequestMetadata: metadata})
			id, err = deref(response.Id), createErr
		} else {
			client, clientErr := reader.KMSManagement(v.Key.ManagementEndpoint)
			if clientErr != nil {
				return clientErr
			}
			response, createErr := client.CreateKey(createCtx, keymanagement.CreateKeyRequest{CreateKeyDetails: v.Key.Request, OpcRetryToken: new(pending.Request.RetryToken), RequestMetadata: metadata})
			id, err = deref(response.Id), createErr
		}
		if err != nil {
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
				return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
			}
			return err
		}
		if !validOriginalKMSID([2]string{"vault", "key"}[slot], region.OCIRegion, id) {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: pending, ResourceID: id, Generation: region.Generation, GrantSHA256: record.OriginalFoundationCompartments.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if slot == 0 {
		endpoint, err := readOriginalVault(ctx, reader, v)
		if err != nil {
			return err
		}
		v.Vault.ManagementEndpoint = endpoint
	} else {
		version, err := readOriginalVaultKey(ctx, reader, region.OCIRegion, v)
		if err != nil {
			return err
		}
		v.Key.CurrentKeyVersion = version
	}
	readback, err := originalVaultReadback(v, slot, originalVaultID(*entry))
	if err != nil || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != readback {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = readback, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func (r FoundationRecord) validateOriginalFoundationVault() error {
	if r.OriginalFoundationCompartments == nil {
		return nil
	}
	attached := 0
	seen := map[string]bool{}
	for index, region := range r.OriginalFoundationCompartments.Regions {
		v := region.Vault
		if v == nil {
			continue
		}
		attached++
		expected, err := originalVaultScope(r, index)
		if err != nil || v.ControlCompartmentID != expected.ControlCompartmentID || v.NetworkProofSHA256 != expected.NetworkProofSHA256 || v.Vault.SelectedID != expected.Vault.SelectedID || v.Key.SelectedID != expected.Key.SelectedID || !sameOriginalSourceValue(v.Vault.Request, expected.Vault.Request) || !sameOriginalSourceValue(v.Key.Request, expected.Key.Request) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if v.Vault.VerifiedAt.IsZero() != (v.Vault.ManagementEndpoint == "") || v.Key.VerifiedAt.IsZero() != (v.Key.CurrentKeyVersion == "") {
			return ErrOriginalSourceProducerHold
		}
		if v.Key.VaultID == "" {
			if v.Key.ManagementEndpoint != "" || v.Key.Pending != nil || v.Key.Provenance != nil || !v.Key.VerifiedAt.IsZero() {
				return ErrOriginalSourceProducerHold
			}
		} else if v.Vault.VerifiedAt.IsZero() || v.Key.VaultID != originalVaultID(v.Vault.OriginalFoundationKMSCreate) || v.Key.ManagementEndpoint != v.Vault.ManagementEndpoint {
			return ErrOriginalSourceProducerHold
		}
		for slot := range 2 {
			entry := originalVaultEntry(v, slot)
			notBefore := r.OriginalFoundationCompartments.BornAt
			for _, prerequisite := range r.OriginalFoundationCompartments.Regions {
				if prerequisite.Network.Rules.VerifiedAt.After(notBefore) {
					notBefore = prerequisite.Network.Rules.VerifiedAt
				}
			}
			if slot == 1 && v.Vault.VerifiedAt.After(notBefore) {
				notBefore = v.Vault.VerifiedAt
			}
			digest, err := originalVaultRequestSHA(v, slot)
			if err != nil {
				return err
			}
			if entry.SelectedID != "" && (entry.Pending != nil || entry.Provenance != nil || entry.HoldReason != "") || entry.Pending == nil && (entry.Provenance != nil || entry.HoldReason != "") {
				return ErrOriginalSourceProducerHold
			}
			if entry.Pending != nil {
				p := *entry.Pending
				if p.OperationID != region.OperationID || p.IntentDigest != region.IntentSHA256 || p.Request != originalVaultCreateIdentity(region, slot, digest) || p.FirstAttemptAt.IsZero() || p.FirstAttemptAt.Before(notBefore) || p.FirstAttemptAt.After(r.UpdatedAt) || slot == 1 && v.Key.VaultID == "" {
					return ErrOriginalSourceProducerHold
				}
			}
			id := originalVaultID(*entry)
			if id != "" {
				if !validOriginalKMSID([2]string{"vault", "key"}[slot], region.OCIRegion, id) || seen[id] {
					return ErrOriginalSourceProducerHold
				}
				seen[id] = true
			}
			if entry.Provenance != nil {
				p := entry.Provenance
				if !sameOriginalSourceValue(p.Create, entry.Pending) || p.GrantSHA256 != r.OriginalFoundationCompartments.GrantSHA256 || p.Generation != region.Generation || !validOriginalKMSID([2]string{"vault", "key"}[slot], region.OCIRegion, p.ResourceID) || entry.HoldReason != "" {
					return ErrOriginalSourceProducerHold
				}
			}
			if entry.HoldReason != "" && !slices.Contains([]string{"create-refused", "retry-expired", "create-unresolved"}, entry.HoldReason) {
				return ErrOriginalSourceProducerHold
			}
			if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() && (id == "" || entry.VerifiedAt.Before(notBefore) || entry.VerifiedAt.After(r.UpdatedAt) || entry.Pending != nil && entry.VerifiedAt.Before(entry.Pending.FirstAttemptAt)) {
				return ErrOriginalSourceProducerHold
			}
			if entry.ReadbackSHA256 != "" {
				readback, err := originalVaultReadback(v, slot, id)
				if err != nil || entry.ReadbackSHA256 != readback || slot == 1 && !validOriginalKMSID("keyversion", region.OCIRegion, v.Key.CurrentKeyVersion) {
					return ErrOriginalSourceProducerHold
				}
			}
		}
	}
	if attached != 0 && attached != 3 {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationVault(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, region := range after.Regions {
				if region.Vault != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, region := range before.Regions {
		old := region.Vault
		if old == nil {
			if after != nil && after.Regions[index].Vault != nil {
				expected, err := originalVaultScope(next, index)
				if err != nil || !sameOriginalSourceValue(after.Regions[index].Vault, expected) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		if after == nil {
			return ErrOriginalSourceProducerHold
		}
		current := after.Regions[index].Vault
		if current == nil || old.ControlCompartmentID != current.ControlCompartmentID || old.NetworkProofSHA256 != current.NetworkProofSHA256 || !sameOriginalSourceValue(old.Vault.Request, current.Vault.Request) || !sameOriginalSourceValue(old.Key.Request, current.Key.Request) || old.Vault.ManagementEndpoint != "" && old.Vault.ManagementEndpoint != current.Vault.ManagementEndpoint || old.Key.VaultID != "" && (old.Key.VaultID != current.Key.VaultID || old.Key.ManagementEndpoint != current.Key.ManagementEndpoint) || old.Key.CurrentKeyVersion != "" && old.Key.CurrentKeyVersion != current.Key.CurrentKeyVersion {
			return ErrOriginalSourceProducerHold
		}
		for slot := range 2 {
			entry, retained := originalVaultEntry(old, slot), originalVaultEntry(current, slot)
			if entry.SelectedID != retained.SelectedID || entry.Pending != nil && !sameOriginalSourceValue(entry.Pending, retained.Pending) || entry.Provenance != nil && !sameOriginalSourceValue(entry.Provenance, retained.Provenance) || entry.HoldReason != "" && entry.HoldReason != retained.HoldReason || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != retained.ReadbackSHA256 || !entry.VerifiedAt.IsZero() && !entry.VerifiedAt.Equal(retained.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return nil
}
