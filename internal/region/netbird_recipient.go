package region

import (
	"context"
	"encoding/hex"
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
	expires, authorityExpires                                           time.Time
	check                                                               func(context.Context) error
	journal                                                             NetBirdManagerJournalExpectation
	original                                                            context.Context
}

// NetBirdManagerJournalExpectation describes independently authenticated launch
// inputs. BinarySHA256 is an image receipt pin, never a remote kernel measurement.
type NetBirdManagerJournalExpectation struct {
	AdmissionSHA256, LaunchRecipeSHA256, BinarySHA256 string
}

func (v VerifiedNetBirdManagerRecipient) JournalExpectation(ctx context.Context) (NetBirdManagerJournalExpectation, error) {
	if ctx == nil || !bootstrapSHA256.MatchString(v.journal.AdmissionSHA256) || !bootstrapSHA256.MatchString(v.journal.LaunchRecipeSHA256) ||
		!bootstrapSHA256.MatchString(v.journal.BinarySHA256) {
		return NetBirdManagerJournalExpectation{}, errors.New("remote NetBird journal expectation is absent")
	}
	if err := v.Check(ctx); err != nil {
		return NetBirdManagerJournalExpectation{}, err
	}
	return v.journal, nil
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

// AuthorityExpiresAt binds the shared signed snapshot; local effects must
// still honor ExpiresAt and Check, including the original caller cancellation.
func (v VerifiedNetBirdManagerRecipient) AuthorityExpiresAt() time.Time { return v.authorityExpires }

// CheckOriginal seals the retained caller and first cap without another read.
// Source currentness still requires the independent full Check.
func (v VerifiedNetBirdManagerRecipient) CheckOriginal() error {
	if !v.IsVerified() || v.original == nil || v.expires.IsZero() {
		return errors.New("remote NetBird manager original recipient is absent")
	}
	return checkNetBirdManagerDeadline(v.original, v.expires)
}

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
	launch                                                  netBirdManagerOrigin
	target                                                  vaultsecret.Target
	expires                                                 time.Time
	journal                                                 NetBirdManagerJournalExpectation
}

// VerifyNetBirdManagerRecipient uses the current regional source and fresh
// HOME SDK observations. It never runs manager-local IMDS or binary admission.
func VerifyNetBirdManagerRecipient(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, source bootstrap.VerifiedRegionalSource) (VerifiedNetBirdManagerRecipient, error) {
	return VerifyNetBirdManagerRecipientForOperation(ctx, ctx, factory, resolver, source)
}

// VerifyNetBirdManagerRecipientForOperation bounds initial reads separately from
// the original lifecycle retained by the resulting proof.
func VerifyNetBirdManagerRecipientForOperation(ctx, originalCtx context.Context, factory *ociclient.Factory, resolver FoundationResolver, source bootstrap.VerifiedRegionalSource) (VerifiedNetBirdManagerRecipient, error) {
	if ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil {
		return VerifiedNetBirdManagerRecipient{}, errors.New("remote NetBird manager requires live operation and original contexts")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(originalCtx, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := originalCtx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
		defer cancelDeadline()
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || factory == nil || !source.IsVerified() || factory.Region() != source.Manifest().OCIRegion {
		return VerifiedNetBirdManagerRecipient{}, errors.New("remote NetBird manager recipient requires the actual regional source and OCI provider")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != reader.tenancy || source.StorageDomain() != reader.storage {
		return VerifiedNetBirdManagerRecipient{}, errors.Join(errors.New("remote NetBird manager source differs from authenticated foundation"), err)
	}
	current := func(ctx context.Context) (netBirdRecipientObservation, error) {
		ctx, cancel := context.WithDeadline(ctx, source.ExpiresAt())
		defer cancel()
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
	return retainNetBirdRecipient(originalCtx, original, current)
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
		target: original.target, expires: expires, authorityExpires: original.expires, journal: original.journal, original: originalContext}
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
	ctx, cancelReader := context.WithDeadline(ctx, reader.expires)
	defer cancelReader()
	intent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	ctx, cancelIntent := context.WithDeadline(ctx, intent.expires)
	defer cancelIntent()
	record, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	slotID := BootstrapSlotID(intent.installationID, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	allocation, err := resolver.BootstrapAllocation(ctx, slotID)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	ctx, cancelAllocation := context.WithDeadline(ctx, allocation.ExpiresAt())
	defer cancelAllocation()
	if err := validateNetBirdAllocation(allocation, intent, record.ResourceIDs["control_compartment"]); err != nil {
		return netBirdRecipientObservation{}, err
	}
	if err := allocation.Revalidate(ctx); err != nil {
		return netBirdRecipientObservation{}, err
	}
	original, err := netBirdRecipientCheckpoint(intent, record, allocation)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	launch := original.launch
	profile, err := managerLaunchProfile(intent.intent.Profile, record)
	if err != nil {
		return netBirdRecipientObservation{}, err
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
	lastAllocation, err := resolver.BootstrapAllocation(ctx, original.launch.SlotID)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	if err := lastAllocation.Revalidate(ctx); err != nil {
		return netBirdRecipientObservation{}, err
	}
	lastIntent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	lastRecord, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	if err := validateNetBirdAllocation(lastAllocation, lastIntent, lastRecord.ResourceIDs["control_compartment"]); err != nil {
		return netBirdRecipientObservation{}, err
	}
	latest, err := netBirdRecipientCheckpoint(lastIntent, lastRecord, lastAllocation)
	if err != nil || latest != original || !time.Now().Before(original.expires) {
		return netBirdRecipientObservation{}, errors.Join(errors.New("remote NetBird manager original checkpoint changed during SDK observation"), err)
	}
	return original, ctx.Err()
}

func netBirdRecipientCheckpoint(intent verifiedNetBirdIntent, record FoundationRecord, allocation VerifiedBootstrapAllocation) (netBirdRecipientObservation, error) {
	slotID := BootstrapSlotID(intent.installationID, "GRU", NetBirdManagerRole, NetBirdManagerRole)
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
	target, err := record.VaultTarget()
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	expires := intent.expires
	if allocation.ExpiresAt().Before(expires) {
		expires = allocation.ExpiresAt()
	}
	checkpoint := launch.original()
	admission, err := netBirdManagerAdmissionPin(intent, record, allocation)
	if err != nil {
		return netBirdRecipientObservation{}, err
	}
	journal := NetBirdManagerJournalExpectation{AdmissionSHA256: hex.EncodeToString(admission[:]), LaunchRecipeSHA256: intent.recipeDigest, BinarySHA256: intent.image.Receipt().BinarySHA256}
	return netBirdRecipientObservation{installationID: intent.installationID, grantDigest: intent.grantDigest,
		privateIP: intent.intent.Profile.PrivateIP, storeGeneration: entityid.Derive("netbird-foundation-store", intent.installationID) + ":1",
		foundationOperation: record.OperationID, foundationIntent: record.IntentDigest, foundationEpoch: record.Epoch, generation: intent.generation,
		bindingDigest: allocation.BindingDigest(), scopeDigest: allocation.ScopeDigest(), physicalScopeDigest: allocation.PhysicalScopeDigest(),
		launch: checkpoint, target: target, expires: expires, journal: journal}, nil
}
