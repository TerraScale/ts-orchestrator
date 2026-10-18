package region

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func admitOriginalNetBirdManager(ctx context.Context, resolver FoundationResolver, reader *SignedFootprint, observer bootstrapstart.InstanceObserver,
	instanceID string, verifyBinary func(release.VerifiedImage) (bootstrapstart.RunningBinary, error),
) (VerifiedNetBirdManager, error) {
	if ctx == nil || reader == nil || observer == nil || verifyBinary == nil {
		return VerifiedNetBirdManager{}, ErrOriginalSourceProducerHold
	}
	current := func(ctx context.Context) (originalNetBirdState, error) {
		state, err := reader.originalNetBirdState(ctx, resolver)
		if err != nil {
			return state, err
		}
		launch := state.manager.Launch
		if launch == nil || launch.InstanceID != instanceID || launch.BootVolumeID == "" || state.manager.PrimaryVNICID == "" ||
			state.manager.VerifiedAt.IsZero() || state.manager.HoldReason != "" {
			return state, ErrOriginalSourceProducerHold
		}
		guard := func(context.Context) error {
			next, err := reader.originalNetBirdState(ctx, resolver)
			if err != nil {
				return err
			}
			if next.intent.grantDigest != state.intent.grantDigest || next.target() != state.target() || next.regionalTarget() != state.regionalTarget() ||
				next.manager.Launch == nil || netBirdOriginalBinding(*next.manager.Launch) != netBirdOriginalBinding(*launch) || next.manager.PrimaryVNICID != state.manager.PrimaryVNICID {
				return ErrOriginalSourceProducerHold
			}
			return nil
		}
		guarded := ociclient.WithRequestGuard(ctx, guard)
		if err := checkOriginalNetBirdManagerNetwork(guarded, reader.factory, state.manager); err != nil {
			return state, err
		}
		observed, err := observer.ObserveInstance(guarded, instanceID)
		if err != nil {
			return state, err
		}
		intent, profile := state.intent.intent, state.intent.intent.Profile
		ids := originalNetBirdManagerIDs(state.manager)
		if observed.InstanceOCID != instanceID || observed.ImageOCID != intent.ImageOCID || observed.CompartmentOCID != state.manager.ControlCompartmentID ||
			observed.AvailabilityDomain != profile.AvailabilityDomain || observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape ||
			observed.SubnetOCID != ids["netbird_manager_subnet"] ||
			!slices.Equal(slices.Sorted(slices.Values(observed.NSGOCIDs)), []string{ids["netbird_manager_nsg"]}) ||
			!observed.PrimaryVNIC || observed.PrimaryPrivateIP != profile.PrivateIP || observed.LifecycleState != "RUNNING" {
			return state, errors.New("original NetBird manager differs from its signed image and retained physical profile")
		}
		boot, vnic, err := observeNetBirdManagerGeometry(guarded, reader.factory, intent, *launch, state.manager.ControlCompartmentID)
		if err != nil || boot != launch.BootVolumeID || vnic != state.manager.PrimaryVNICID {
			return state, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if _, err := verifyBinary(state.intent.image); err != nil {
			return state, err
		}
		if err := guard(ctx); err != nil {
			return state, err
		}
		return state, nil
	}
	state, err := current(ctx)
	if err != nil {
		return VerifiedNetBirdManager{}, err
	}
	target, credentialTarget := state.regionalTarget(), state.target()
	store := state.intent.intent.Material.Context.StoreGeneration
	binding := netBirdOriginalBinding(*state.manager.Launch)
	check := func(ctx context.Context) error {
		next, err := current(ctx)
		if err != nil {
			return err
		}
		if next.intent.grantDigest != state.intent.grantDigest || next.target() != credentialTarget || next.regionalTarget() != target ||
			next.intent.intent.Material.Context.StoreGeneration != store || netBirdOriginalBinding(*next.manager.Launch) != binding {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	transition := func(ctx context.Context, ready bool) error {
		if err := check(ctx); err != nil {
			return err
		}
		latest, err := reader.originalNetBirdState(ctx, resolver)
		if err != nil {
			return err
		}
		if latest.manager.Launch == nil || latest.intent.grantDigest != state.intent.grantDigest || netBirdOriginalBinding(*latest.manager.Launch) != binding {
			return ErrFoundationFenced
		}
		launch := *latest.manager.Launch
		if ready {
			if launch.StoreState != "initializing" && !(latest.intent.intent.StoreOrigin == "restore" && launch.StoreState == "empty") && launch.StoreState != "ready" {
				return errors.New("original NetBird store has no consumed genesis or restore authority")
			}
			launch.StoreState = "ready"
		} else {
			if latest.intent.intent.StoreOrigin != "new" || launch.StoreState != "empty" {
				return errors.New("original NetBird genesis was absent or already consumed; restore is required")
			}
			launch.StoreState = "initializing"
		}
		manager := *latest.manager
		manager.Launch = &launch
		latest.record.OriginalFoundationCompartments.Regions[0].NetBirdManager = &manager
		latest.record.UpdatedAt = time.Now().UTC()
		guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return check(ctx) })
		if _, err := resolver.Store.CompareAndSwap(guarded, latest.record, latest.etag); err != nil {
			return err
		}
		return check(ctx)
	}
	return VerifiedNetBirdManager{target: target, credentialTarget: credentialTarget, storeGeneration: store, check: check, transition: transition,
		binding: binding, originalGrantSHA256: state.intent.grantDigest,
		recovery: state.intent.intent.StoreOrigin == "restore" || state.manager.Launch.StoreState != "empty"}, nil
}

func netBirdOriginalBinding(launch NetBirdManagerLaunch) NetBirdManagerBinding {
	return NetBirdManagerBinding{InstanceID: launch.InstanceID, BootVolumeID: launch.BootVolumeID, RecipeSHA256: launch.RecipeSHA256, PhysicalScopeSHA256: launch.PhysicalScopeSHA256}
}
