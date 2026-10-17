package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var (
	ErrNetBirdBrokerPolicyAbsent  = errors.New("NetBird broker policy has neither original reservation nor same-name cloud policy")
	ErrNetBirdBrokerPolicyPending = errors.New("NetBird broker policy lacks a completed original positive receipt")
)

// VerifyNetBirdBrokerReader observes a completed original policy across admitted
// controllers. It never acquires write authority or changes retained history.
func VerifyNetBirdBrokerReader(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, source bootstrap.VerifiedRegionalSource, recipient VerifiedNetBirdManagerRecipient) error {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || resolver.Store == nil || factory == nil || !source.IsVerified() || !recipient.IsVerified() {
		return errors.New("NetBird broker policy verification requires current sealed source, recipient and foundation")
	}
	entry, ok := catalog.CellForOCIRegion(factory.Region())
	if !ok || !slices.Contains([]string{"GRU", "SFO", "FRA"}, entry.Cell) || source.Manifest().OCIRegion != entry.OCIRegion || string(source.Manifest().Cell) != entry.Cell ||
		source.StorageDomain() != reader.storage || source.Template().InstallationID() != reader.home.InstallationID || source.Template().GrantDigest() != reader.home.GrantSHA256 ||
		recipient.InstallationID() != reader.home.InstallationID || recipient.GrantDigest() != reader.home.GrantSHA256 {
		return errors.New("NetBird broker policy verification differs from the original signed regional source")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != reader.tenancy {
		return errors.Join(ErrFoundationFenced, err)
	}
	expires := source.ExpiresAt()
	for _, until := range []time.Time{recipient.ExpiresAt(), reader.expires} {
		if until.Before(expires) {
			expires = until
		}
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if err := recipient.Check(ctx); err != nil {
		return err
	}
	footprint, signedExpiry, err := reader.authorizedRegions(ctx)
	if err != nil || footprint.GrantSHA256 != source.Template().GrantDigest() {
		return errors.Join(ErrFoundationFenced, err)
	}
	if signedExpiry.Before(expires) {
		expires = signedExpiry
	}
	ctx, cancelSigned := context.WithDeadline(ctx, expires)
	defer cancelSigned()
	original, err := resolver.Resolve(ctx, entry.Cell)
	if err != nil {
		return err
	}
	target, err := original.VaultTarget()
	if err != nil {
		return err
	}
	bound := source.Template().VaultTarget()
	if target != (vaultsecret.Target{CompartmentID: bound.CompartmentOCID, VaultID: bound.VaultOCID, KeyID: bound.KMSKeyOCID}) {
		return errors.New("NetBird broker policy verification changed the signed regional Vault target")
	}
	check := func() error {
		if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return err
		}
		if err := recipient.Check(ctx); err != nil {
			return err
		}
		latest, err := resolver.Resolve(ctx, entry.Cell)
		if err != nil {
			return err
		}
		before, err := json.Marshal(original.NetBirdBrokerPolicies, json.Deterministic(true))
		after, currentErr := json.Marshal(latest.NetBirdBrokerPolicies, json.Deterministic(true))
		if err != nil || currentErr != nil || string(before) != string(after) || latest.OperationID != original.OperationID || latest.Epoch != original.Epoch || latest.IntentDigest != original.IntentDigest ||
			latest.Generation != original.Generation || latest.GrantSHA256 != original.GrantSHA256 || !maps.Equal(latest.ResourceIDs, original.ResourceIDs) || !sameFoundationWriterOriginal(original.FoundationWriter, latest.FoundationWriter) {
			return ErrFoundationFenced
		}
		if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return err
		}
		if err := recipient.Check(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return ociclient.LimitAdmission(ctx, expires)
	}
	if err := check(); err != nil {
		return err
	}
	bindings, err := resolver.ResourceBindingsFor(ctx, entry.Cell, "control_compartment", "vault", "key")
	if err != nil {
		return err
	}
	for key, expected := range map[string]string{"control_compartment": target.CompartmentID, "vault": target.VaultID, "key": target.KeyID} {
		reference, err := FoundationResourceReference(entry.Cell, key)
		if err != nil {
			return err
		}
		actual, err := bindings.Resolve(reference)
		if err != nil || actual != expected {
			return errors.Join(ErrFoundationFenced, err)
		}
	}
	if bindings.ExpiresAt().Before(expires) {
		expires = bindings.ExpiresAt()
	}
	ctx, cancelBindings := context.WithDeadline(ctx, expires)
	defer cancelBindings()
	if err := check(); err != nil {
		return err
	}
	name := strings.ToLower(entry.Cell) + "-1-netbird-broker"
	secretID, err := netBirdBrokerSecret(ctx, factory, target, name)
	if err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	key := netBirdBrokerPolicyKey(recipient.InstanceID(), secretID)
	pending, exists := original.NetBirdBrokerPolicies[key]
	if exists && (pending.PolicyID == "" || pending.Uncertain) {
		return ErrNetBirdBrokerPolicyPending
	}
	if exists {
		if err := netBirdBrokerReaderOriginal(original, pending, source.StorageDomain()); err != nil {
			return err
		}
		if pending.InstallationID != source.Template().InstallationID() || pending.GrantSHA256 != source.Template().GrantDigest() || pending.SourceSHA256 != digestSource(source.Inventory()) || pending.InstanceID != recipient.InstanceID() || pending.PrivateIP != recipient.PrivateIP() ||
			pending.StoreGeneration != recipient.StoreGeneration() || pending.ManagerVaultTarget != recipient.VaultTarget() || pending.VaultTarget != target || pending.SecretName != name || pending.SecretID != secretID {
			return errors.New("NetBird broker completed policy differs from the current sealed source or recipient")
		}
		if pending.FirstAttemptAt.After(time.Now()) || pending.ExpiresAt.After(source.ExpiresAt()) || pending.ExpiresAt.After(recipient.AuthorityExpiresAt()) {
			return errors.New("NetBird broker completed receipt exceeds its original signed authority")
		}
	} else {
		for _, history := range original.NetBirdBrokerPolicies {
			if history.SecretName == name && history.VaultTarget == target {
				return ErrNetBirdBrokerPolicyPending
			}
		}
	}
	homeRegion, err := factory.HomeRegion(ctx, tenancy)
	if err != nil || homeRegion != foundationHomeRegion {
		return errors.Join(ErrFoundationFenced, err)
	}
	if err := check(); err != nil {
		return err
	}
	home, err := factory.ForRegion(homeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	request := netBirdBrokerPolicyRequest(NetBirdBrokerPolicyRecord{InstanceID: recipient.InstanceID(), SecretID: secretID, VaultTarget: target})
	observed, err := findNetBirdBrokerPolicy(ctx, &iam, request)
	if err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if !exists && observed != "" {
		return ErrNetBirdBrokerPolicyPending
	}
	if exists {
		if observed != "" && observed != pending.PolicyID {
			return errors.New("NetBird broker completed policy name resolves to another identity")
		}
		if err := verifyNetBirdBrokerPolicy(ctx, &iam, pending); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
	}
	currentSecret, err := netBirdBrokerSecret(ctx, factory, target, name)
	if err != nil || currentSecret != secretID {
		return errors.Join(ErrFoundationFenced, err)
	}
	if err := bindings.Revalidate(ctx); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if !exists {
		return ErrNetBirdBrokerPolicyAbsent
	}
	return nil
}

// Historic dispatch expiry does not invalidate an installed exact positive
// policy. Current source/recipient/context deadlines still bound every read.
func netBirdBrokerReaderOriginal(record FoundationRecord, pending NetBirdBrokerPolicyRecord, storage bootstrap.StorageDomain) error {
	writer := record.FoundationWriter
	key := netBirdBrokerPolicyKey(pending.InstanceID, pending.SecretID)
	if pending.validate(key, record.Cell) != nil || pending.PolicyID == "" || pending.Uncertain || writer == nil || writer.validate() != nil || writer.Policy == nil || writer.Policy.PolicyID == "" || writer.Policy.VerifiedAt.IsZero() ||
		writer.InstanceID != pending.ActorInstanceID || writer.InstallationID != pending.InstallationID || writer.Namespace != storage.Namespace || writer.Bucket != storage.HeadBucket || writer.KMSKeyID != storage.HeadKMSKeyOCID ||
		pending.FirstAttemptAt.Before(writer.Policy.VerifiedAt) || pending.OperationID != record.OperationID || pending.Epoch != record.Epoch || pending.IntentDigest != record.IntentDigest {
		return errors.New("NetBird broker completed receipt lacks its canonical original writer provenance")
	}
	return nil
}
