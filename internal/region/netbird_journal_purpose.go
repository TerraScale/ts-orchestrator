package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// preparedNetBirdJournalPurpose derives signed intent before the spending digest.
// It never fills a future grant digest or adopts a post-launch native identity.
func preparedNetBirdJournalPurpose(grant FoundationGrant, expires time.Time) (bootstrap.NetBirdJournalPurpose, error) {
	fail := func() (bootstrap.NetBirdJournalPurpose, error) {
		return bootstrap.NetBirdJournalPurpose{}, errors.New("NetBird journal purpose requires the exact prepared original GRU allocations and source")
	}
	if expires.IsZero() || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil {
		return fail()
	}
	retain := func(deadline time.Time) {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	retainWires := func(wires ...[]byte) error {
		for _, wire := range wires {
			if len(wire) == 0 {
				continue
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				return err
			}
			retain(envelope.ExpiresAt)
		}
		return nil
	}
	for _, authority := range grant.ReleaseAuthorities {
		if err := retainWires(authority.DelegationWire); err != nil {
			return bootstrap.NetBirdJournalPurpose{}, err
		}
	}
	var selected *FoundationIntent
	for _, regional := range grant.Regions {
		if regional.BootstrapMaterial == nil || regional.BootstrapMaterial.Startup == nil || regional.BootstrapMaterial.Startup.FounderResources == nil {
			return fail()
		}
		startup := regional.BootstrapMaterial.Startup
		retain(startup.FounderResources.LaunchDeadline)
		if err := retainWires(startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire); err != nil {
			return bootstrap.NetBirdJournalPurpose{}, err
		}
		if regional.Plan["cell"] == "GRU" {
			if selected != nil || regional.NetBirdManager == nil {
				return fail()
			}
			selected = new(regional)
		} else if regional.NetBirdManager != nil {
			return fail()
		}
	}
	if selected == nil {
		return fail()
	}
	material, manager := selected.BootstrapMaterial, selected.NetBirdManager
	if material.SourceRegistration == nil || material.SourceRegistration.Validate() != nil || material.Startup.SeedSlot != "controller-a" ||
		material.InstallationID != grant.InstallationID || material.SourceRegistration.Generation != grant.Generation || selected.Generation != grant.Generation {
		return fail()
	}
	configWire, err := json.Marshal(material.Config, json.Deterministic(true))
	registration := material.SourceRegistration
	if err != nil || preparationDigest(configWire) != material.PlanSHA256 || registration.InstallationID != grant.InstallationID ||
		registration.PlanSHA256 != material.PlanSHA256 || registration.DeploymentID != material.Config.DeploymentID || registration.ClusterID != material.Config.ClusterID ||
		registration.Environment != material.Config.Environment || registration.Cell != "GRU" || registration.SeedSlot != material.Startup.SeedSlot {
		return fail()
	}
	if err := retainWires(manager.ImageReceiptWire, manager.ImageDelegationWire, manager.QualificationWire, manager.QualificationDelegationWire); err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	recipe, err := NetBirdJournalUnderlayRecipe(selected.Plan, manager.Profile, *material)
	if err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	allocation := func(role, slot string) (bootstrap.NetBirdJournalAllocation, error) {
		id := BootstrapSlotID(grant.InstallationID, "GRU", role, slot)
		var result bootstrap.NetBirdJournalAllocation
		matches := 0
		for _, candidate := range grant.InfrastructureSpend.Bootstrap.Slots {
			if candidate.SlotID != id {
				continue
			}
			if candidate.Cell != "GRU" || candidate.Role != role || candidate.Slot != slot {
				return result, errors.New("journal allocation source differs from its logical original birth")
			}
			result = bootstrap.NetBirdJournalAllocation{SlotID: id, OperationID: BootstrapOperationID(grant.InstallationID, id),
				ProfileSHA256: candidate.ProfileSHA256, RecipeSHA256: candidate.RecipeSHA256}
			matches++
		}
		if matches != 1 {
			return result, errors.New("journal allocation source is absent or duplicated")
		}
		return result, nil
	}
	managerAllocation, err := allocation(NetBirdManagerRole, NetBirdManagerRole)
	if err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	writerAllocation, err := allocation("controller", material.Startup.SeedSlot)
	if err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	var seed bootstrap.LaunchProfile
	seedMatches := 0
	for _, profile := range material.Startup.Profiles {
		if profile.Slot == material.Startup.SeedSlot {
			seed, seedMatches = profile, seedMatches+1
		}
	}
	writerProfile, err := bootstrap.ControllerBootstrapProfileDigest(seed)
	if err != nil || seedMatches != 1 || writerProfile != writerAllocation.ProfileSHA256 {
		return fail()
	}
	writerRecipe, err := bootstrap.ControllerBootstrapRecipeDigest(*material.Startup)
	if err != nil || writerRecipe != writerAllocation.RecipeSHA256 {
		return fail()
	}
	managerProfile, err := NetBirdManagerProfileDigest(manager.Profile)
	if err != nil || managerProfile != managerAllocation.ProfileSHA256 {
		return fail()
	}
	envelope, err := trust.DecodeEnvelope(manager.ImageReceiptWire)
	if err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	var receipt release.ImageReceipt
	if json.Unmarshal(envelope.Payload, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.Validate() != nil || receipt.OCIImageOCID != manager.ImageOCID {
		return fail()
	}
	managerRecipe, err := NetBirdManagerRecipeDigest(*manager, receipt.ImageSHA256)
	if err != nil || managerRecipe != managerAllocation.RecipeSHA256 {
		return fail()
	}
	purpose := bootstrap.NetBirdJournalPurpose{Purpose: bootstrap.NetBirdAccountJournalPurpose, InstallationID: grant.InstallationID,
		DeploymentID: material.Config.DeploymentID, ClusterID: material.Config.ClusterID, Environment: material.Config.Environment, Cell: "GRU",
		SourcePlanSHA256: material.PlanSHA256, SourceGeneration: grant.Generation, Manager: managerAllocation, Writer: writerAllocation,
		Storage: material.SourceRegistration.StorageDomain, Object: foundationObjectPrefix + "GRU.json", Actions: []string{"reserve", "complete"}, Underlay: recipe, ExpiresAt: expires}
	if err := purpose.Validate(); err != nil {
		return bootstrap.NetBirdJournalPurpose{}, err
	}
	return purpose, nil
}

// validateNetBirdJournalPurpose is shared by preparation, signing and every
// accepted current grant. A shorter final envelope cannot rewrite approved intent.
func validateNetBirdJournalPurpose(grant FoundationGrant, envelopeExpiry time.Time) error {
	return validateNetBirdJournalPurposeAt(grant, envelopeExpiry, time.Now())
}

func validateNetBirdJournalPurposeAt(grant FoundationGrant, envelopeExpiry, at time.Time) error {
	var purpose *bootstrap.NetBirdJournalPurpose
	for _, regional := range grant.Regions {
		if regional.NetBirdManager == nil {
			continue
		}
		if regional.Plan["cell"] != "GRU" || purpose != nil {
			return errors.New("journal purpose is outside its unique original GRU manager")
		}
		purpose = new(regional.NetBirdManager.JournalPurpose.Clone())
	}
	if purpose == nil {
		return nil
	}
	if at.IsZero() || purpose.Validate() != nil || !at.Before(purpose.ExpiresAt) || !envelopeExpiry.IsZero() && purpose.ExpiresAt.After(envelopeExpiry) {
		return errors.New("signed journal purpose is absent, invalid or outlives its grant")
	}
	expected, err := preparedNetBirdJournalPurpose(grant, purpose.ExpiresAt)
	if err != nil {
		return err
	}
	want, err := expected.Digest()
	if err != nil {
		return err
	}
	actual, err := purpose.Digest()
	if err != nil || actual != want {
		return errors.New("signed journal purpose differs from its exact original source, allocations or private recipe")
	}
	return nil
}

// VerifiedNetBirdJournalPurpose adds exact current grant/material provenance to
// the shared signed-purpose proof. It confers no native or mutation authority.
type VerifiedNetBirdJournalPurpose struct {
	original context.Context
	reader   *SignedFootprint
	material VerifiedBootstrapMaterial
	proof    bootstrap.VerifiedNetBirdJournalPurpose
	expires  time.Time
}

func (proof VerifiedNetBirdJournalPurpose) Purpose() bootstrap.NetBirdJournalPurpose {
	return proof.proof.Purpose()
}
func (proof VerifiedNetBirdJournalPurpose) Digest() string       { return proof.proof.Digest() }
func (proof VerifiedNetBirdJournalPurpose) GrantDigest() string  { return proof.proof.GrantDigest() }
func (proof VerifiedNetBirdJournalPurpose) ExpiresAt() time.Time { return proof.expires }

// CheckOriginal checks retained lifetimes only; it performs no current reads.
func (proof VerifiedNetBirdJournalPurpose) CheckOriginal() error {
	if proof.original == nil || proof.reader == nil || !proof.material.IsVerified() {
		return errors.New("original signed journal purpose is absent or canceled")
	}
	if err := proof.proof.CheckOriginal(); err != nil {
		return err
	}
	if err := proof.original.Err(); err != nil {
		return err
	}
	now := time.Now()
	if !now.Before(proof.expires) || !now.Before(proof.material.ExpiresAt()) {
		return errors.New("original signed journal purpose or material expired")
	}
	return proof.material.original.Err()
}

func (resolver FoundationResolver) NetBirdJournalPurposeForOperation(ctx, original context.Context) (VerifiedNetBirdJournalPurpose, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || ctx == nil || original == nil || original.Err() != nil {
		return VerifiedNetBirdJournalPurpose{}, errors.New("journal purpose requires the actual current signed foundation source")
	}
	ctx, cancel := context.WithDeadline(ctx, reader.expires)
	defer cancel()
	stop := context.AfterFunc(original, cancel)
	defer stop()
	if deadline, ok := original.Deadline(); ok {
		var cancelOriginal context.CancelFunc
		ctx, cancelOriginal = context.WithDeadline(ctx, deadline)
		defer cancelOriginal()
	}
	material, err := reader.AuthorizedBootstrapMaterialForOperation(ctx, original, "GRU")
	if err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	if material.startupAuthority == nil {
		return VerifiedNetBirdJournalPurpose{}, errors.New("journal purpose has no genuine current signed startup authority")
	}
	ctx, cancelMaterial := context.WithDeadline(ctx, material.ExpiresAt())
	defer cancelMaterial()
	lower, err := material.startupAuthority.NetBirdJournalPurposeForOperation(ctx, original)
	if err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	expires := lower.ExpiresAt()
	if material.ExpiresAt().Before(expires) {
		expires = material.ExpiresAt()
	}
	proof := VerifiedNetBirdJournalPurpose{original: original, reader: reader, material: material, proof: lower, expires: expires}
	deadline, err := proof.CurrentDeadline(ctx)
	if err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	if deadline.Before(proof.expires) {
		proof.expires = deadline
	}
	return proof, nil
}

func (proof VerifiedNetBirdJournalPurpose) Revalidate(ctx context.Context) error {
	_, err := proof.CurrentDeadline(ctx)
	return err
}

func (proof VerifiedNetBirdJournalPurpose) CurrentDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil || proof.original == nil || proof.reader == nil || !proof.proof.IsVerified() || proof.original.Err() != nil || !time.Now().Before(proof.expires) {
		return time.Time{}, errors.New("original signed journal purpose is absent or expired")
	}
	ctx, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	stop := context.AfterFunc(proof.original, cancel)
	defer stop()
	current, err := proof.reader.AuthorizedBootstrapMaterialForOperation(ctx, proof.original, "GRU")
	if err != nil {
		return time.Time{}, err
	}
	if current.PlanDigest() != proof.material.PlanDigest() || digestSource(current.FoundationGrantWire()) != proof.GrantDigest() {
		return time.Time{}, errors.New("journal purpose current original material changed")
	}
	deadline := proof.expires
	if current.ExpiresAt().Before(deadline) {
		deadline = current.ExpiresAt()
	}
	ctx, cancelMaterial := context.WithDeadline(ctx, deadline)
	defer cancelMaterial()
	if err := proof.proof.Revalidate(ctx); err != nil {
		return time.Time{}, err
	}
	if err := proof.original.Err(); err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return deadline, ociclient.LimitAdmission(ctx, deadline)
}

func (proof VerifiedNetBirdJournalPurpose) BootstrapPurpose(ctx context.Context) (bootstrap.VerifiedNetBirdJournalPurpose, error) {
	deadline, err := proof.CurrentDeadline(ctx)
	if err != nil {
		return bootstrap.VerifiedNetBirdJournalPurpose{}, err
	}
	return proof.proof.Limit(ctx, deadline)
}
