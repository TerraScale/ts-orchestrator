package region

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// VerifiedNetBirdManagerRecipient identifies a remote recipient; it grants no
// local manager admission, store transition, controller or signing authority.
type VerifiedNetBirdManagerRecipient struct {
	installationID, grantDigest, instanceID, privateIP, storeGeneration string
	target                                                              vaultsecret.Target
	expires                                                             time.Time
	check                                                               func(context.Context) error
}

func (v VerifiedNetBirdManagerRecipient) IsVerified() bool {
	return v.check != nil && v.instanceID != ""
}
func (v VerifiedNetBirdManagerRecipient) InstallationID() string          { return v.installationID }
func (v VerifiedNetBirdManagerRecipient) GrantDigest() string             { return v.grantDigest }
func (v VerifiedNetBirdManagerRecipient) InstanceID() string              { return v.instanceID }
func (v VerifiedNetBirdManagerRecipient) PrivateIP() string               { return v.privateIP }
func (v VerifiedNetBirdManagerRecipient) StoreGeneration() string         { return v.storeGeneration }
func (v VerifiedNetBirdManagerRecipient) VaultTarget() vaultsecret.Target { return v.target }
func (v VerifiedNetBirdManagerRecipient) ExpiresAt() time.Time            { return v.expires }
func (v VerifiedNetBirdManagerRecipient) Check(ctx context.Context) error {
	if !v.IsVerified() || !time.Now().Before(v.expires) {
		return errors.New("remote NetBird manager recipient is absent or expired")
	}
	return v.check(ctx)
}

type netBirdRecipientObservation struct {
	installationID, grantDigest, privateIP, storeGeneration string
	foundationOperation, foundationIntent                   string
	foundationEpoch, generation                             uint64
	bindingDigest, scopeDigest, physicalScopeDigest         string
	launch                                                  NetBirdManagerLaunch
	target                                                  vaultsecret.Target
	expires                                                 time.Time
}

// VerifyNetBirdManagerRecipient uses the current regional source and fresh
// HOME SDK observations. It never runs manager-local IMDS or binary admission.
func VerifyNetBirdManagerRecipient(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, source bootstrap.VerifiedRegionalSource) (VerifiedNetBirdManagerRecipient, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || factory == nil || !source.IsVerified() || factory.Region() != source.Manifest().OCIRegion {
		return VerifiedNetBirdManagerRecipient{}, errors.New("remote NetBird manager recipient requires the actual regional source and OCI provider")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != reader.tenancy || source.StorageDomain() != reader.storage {
		return VerifiedNetBirdManagerRecipient{}, errors.Join(errors.New("remote NetBird manager source differs from authenticated foundation"), err)
	}
	current := func(ctx context.Context) (netBirdRecipientObservation, error) {
		if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return netBirdRecipientObservation{}, err
		}
		observed, err := observeNetBirdRecipient(ctx, factory, resolver, reader)
		if err != nil {
			return netBirdRecipientObservation{}, err
		}
		if source.Template().InstallationID() != observed.installationID || source.Template().GrantDigest() != observed.grantDigest {
			return netBirdRecipientObservation{}, errors.New("remote NetBird manager is outside the same original regional source grant")
		}
		if source.ExpiresAt().Before(observed.expires) {
			observed.expires = source.ExpiresAt()
		}
		if !time.Now().Before(observed.expires) {
			return netBirdRecipientObservation{}, errors.New("remote NetBird manager authority expired during observation")
		}
		if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return netBirdRecipientObservation{}, err
		}
		return observed, ctx.Err()
	}
	original, err := current(ctx)
	if err != nil {
		return VerifiedNetBirdManagerRecipient{}, err
	}
	return retainNetBirdRecipient(ctx, original, current)
}

func retainNetBirdRecipient(originalContext context.Context, original netBirdRecipientObservation, current func(context.Context) (netBirdRecipientObservation, error)) (VerifiedNetBirdManagerRecipient, error) {
	expires := original.expires
	if deadline, ok := originalContext.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if originalContext.Err() != nil || !time.Now().Before(expires) {
		return VerifiedNetBirdManagerRecipient{}, errors.Join(errors.New("remote NetBird manager original call expired"), originalContext.Err())
	}
	proof := VerifiedNetBirdManagerRecipient{installationID: original.installationID, grantDigest: original.grantDigest,
		instanceID: original.launch.InstanceID, privateIP: original.privateIP, storeGeneration: original.storeGeneration,
		target: original.target, expires: expires}
	proof.check = func(ctx context.Context) error {
		if err := originalContext.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithDeadline(ctx, expires)
		defer cancel()
		stop := context.AfterFunc(originalContext, cancel)
		defer stop()
		next, err := current(ctx)
		if err != nil {
			return err
		}
		if next != original || !time.Now().Before(expires) {
			return errors.New("remote NetBird manager recipient or original authority changed")
		}
		return errors.Join(ctx.Err(), originalContext.Err())
	}
	return proof, nil
}

func observeNetBirdRecipient(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, reader *SignedFootprint) (netBirdRecipientObservation, error) {
	intent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	record, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	slotID := BootstrapSlotID(intent.installationID, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	allocation, err := resolver.BootstrapAllocation(ctx, slotID)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	if err := validateNetBirdAllocation(allocation, intent, record.ResourceIDs["control_compartment"]); err != nil {
		return netBirdRecipientObservation{}, err
	}
	if err := allocation.Revalidate(ctx); err != nil {
		return netBirdRecipientObservation{}, err
	}
	launch := record.NetBirdManager
	if record.LeaseID != "" || launch == nil || launch.InstanceID == "" || launch.BootVolumeID == "" || launch.SlotID != slotID ||
		launch.OperationID != allocation.OperationID() || launch.RecipeSHA256 != intent.recipeDigest || launch.ProfileSHA256 != intent.profileDigest {
		return netBirdRecipientObservation{}, errors.New("remote NetBird manager lacks its exact reconciled launch checkpoint")
	}
	profile, err := managerLaunchProfile(intent.intent.Profile, record)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	bodyDigest, err := netBirdRequestDigest(netBirdLaunchDetails(intent.intent, profile.CompartmentOCID, profile.SubnetOCID, record.AuxiliaryIDs["netbird_manager_nsg"]))
	if err != nil || bodyDigest != launch.RequestDigest {
		return netBirdRecipientObservation{}, errors.Join(errors.New("remote NetBird manager original SDK request changed"), err)
	}
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.RegionGRU, home.Provider())
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	observed, err := (netBirdObservedInstance{factory: home, resolver: resolver, reader: reader, observer: observer}).ObserveInstance(ctx, launch.InstanceID)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	if observed.InstanceOCID != launch.InstanceID || observed.ImageOCID != intent.intent.ImageOCID || observed.CompartmentOCID != profile.CompartmentOCID ||
		observed.AvailabilityDomain != profile.AvailabilityDomain || observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape ||
		observed.SubnetOCID != profile.SubnetOCID || !slices.Equal(slices.Sorted(slices.Values(observed.NSGOCIDs)), slices.Sorted(slices.Values(profile.NetworkSecurityGroupOCIDs))) ||
		!observed.PrimaryVNIC || observed.PrimaryPrivateIP != intent.intent.Profile.PrivateIP || observed.LifecycleState != "RUNNING" {
		return netBirdRecipientObservation{}, errors.New("remote NetBird manager fresh OCI observation differs from its signed recipient")
	}
	target, err := record.VaultTarget()
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	expires := intent.expires
	if allocation.ExpiresAt().Before(expires) {
		expires = allocation.ExpiresAt()
	}
	checkpoint := *launch
	// Store initialization advances without changing its singleton identity.
	checkpoint.StoreState = ""
	return netBirdRecipientObservation{installationID: intent.installationID, grantDigest: intent.grantDigest,
		privateIP: intent.intent.Profile.PrivateIP, storeGeneration: entityid.Derive("netbird-foundation-store", intent.installationID) + ":1",
		foundationOperation: record.OperationID, foundationIntent: record.IntentDigest, foundationEpoch: record.Epoch, generation: intent.generation,
		bindingDigest: allocation.BindingDigest(), scopeDigest: allocation.ScopeDigest(), physicalScopeDigest: allocation.PhysicalScopeDigest(),
		launch: checkpoint, target: target, expires: expires}, ctx.Err()
}
