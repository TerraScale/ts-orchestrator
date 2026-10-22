package region

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/distribution/reference"
)

var errNetBirdComponentFloor = errors.New("NetBird component release floors are incomplete, conflicting or would move backward")

// NetBirdComponentFloor retains original signed evidence in the manager's
// existing physical-store journal; it grants no process or runtime authority.
type NetBirdComponentFloor struct {
	Role                    string `json:"role"`
	ReleaseSequence         uint64 `json:"releaseSequence"`
	ReleaseIdentity         string `json:"releaseIdentity"`
	Image                   string `json:"image"`
	SequenceMigrationSHA256 string `json:"sequenceMigrationSha256"`
	SequenceNamespace       string `json:"sequenceNamespace"`
	SequenceBucket          string `json:"sequenceBucket"`
	SequenceRegion          string `json:"sequenceRegion"`
	BundleSHA256            string `json:"bundleSha256"`
}

func validateNetBirdComponentFloors(floors *[3]NetBirdComponentFloor) error {
	if floors == nil {
		return nil
	}
	for i, role := range netBirdComponentRoles() {
		floor := floors[i]
		if floor.Role != role || floor.ReleaseSequence == 0 || !bootstrapSHA256.MatchString(floor.ReleaseIdentity) ||
			!bootstrapSHA256.MatchString(floor.SequenceMigrationSHA256) || !bootstrapSHA256.MatchString(floor.BundleSHA256) ||
			floor.SequenceNamespace == "" || len(floor.SequenceNamespace) > 128 || strings.ContainsAny(floor.SequenceNamespace, "/\\\r\n") ||
			floor.SequenceBucket != "gru-1-head" || floor.SequenceRegion != "GRU" {
			return errNetBirdComponentFloor
		}
		ref, err := reference.ParseNormalizedNamed(floor.Image)
		if err != nil {
			return errNetBirdComponentFloor
		}
		digest, ok := ref.(reference.Canonical)
		_, tagged := ref.(reference.Tagged)
		if !ok || tagged || ref.String() != floor.Image || digest.Digest().Algorithm().String() != "sha256" || digest.Digest().Validate() != nil {
			return errNetBirdComponentFloor
		}
	}
	return nil
}

func retainNetBirdComponentFloors(old, next *[3]NetBirdComponentFloor) error {
	if err := validateNetBirdComponentFloors(next); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	if next == nil {
		return errNetBirdComponentFloor
	}
	for i, previous := range old {
		current := next[i]
		if current.ReleaseSequence < previous.ReleaseSequence || current.SequenceMigrationSHA256 != previous.SequenceMigrationSHA256 ||
			current.SequenceNamespace != previous.SequenceNamespace || current.SequenceBucket != previous.SequenceBucket || current.SequenceRegion != previous.SequenceRegion ||
			current.ReleaseSequence == previous.ReleaseSequence && current != previous {
			return errNetBirdComponentFloor
		}
	}
	return nil
}

// RetainReleaseFloors atomically retains the complete CURRENT component set.
// The caller must separately establish OS custody before any runtime effect.
func (v NetBirdComponents) RetainReleaseFloors(ctx context.Context) error {
	if err := v.Check(ctx); err != nil {
		return err
	}
	s := v.state
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	if s.original {
		return v.retainOriginalReleaseFloors(ctx)
	}
	guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return v.Check(ctx) })
	record, etag, err := s.resolver.Store.Load(guarded, "GRU")
	if err != nil {
		return err
	}
	if record.Stage != "reconciled" || record.LeaseID != "" || record.Generation != s.intent.generation || record.NetBirdManager == nil ||
		record.NetBirdManager.RecipeSHA256 != s.intent.recipeDigest || record.NetBirdManager.ProfileSHA256 != s.intent.profileDigest {
		return ErrFoundationFenced
	}
	launch := *record.NetBirdManager
	if launch.ComponentFloors == nil && (s.intent.intent.StoreOrigin != "new" || launch.StoreState != "empty") {
		return errNetBirdComponentFloor
	}
	floors := s.currentReleaseFloors(launch.ComponentFloors)
	if err := retainNetBirdComponentFloors(launch.ComponentFloors, &floors); err != nil {
		return err
	}
	if launch.ComponentFloors != nil && *launch.ComponentFloors == floors {
		return v.Check(ctx)
	}
	launch.ComponentFloors = &floors
	record.NetBirdManager, record.UpdatedAt = &launch, time.Now().UTC()
	if _, err := s.resolver.Store.CompareAndSwap(guarded, record, etag); err != nil {
		// A lost committed response or competing CAS is resolved only by reread.
		observed, _, observeErr := s.resolver.Store.Load(guarded, "GRU")
		if observeErr != nil || observed.NetBirdManager == nil || observed.NetBirdManager.ComponentFloors == nil || *observed.NetBirdManager.ComponentFloors != floors {
			return errors.Join(err, observeErr)
		}
	}
	return v.Check(ctx)
}

func (s *netBirdComponents) currentReleaseFloors(previous *[3]NetBirdComponentFloor) [3]NetBirdComponentFloor {
	var floors [3]NetBirdComponentFloor
	for i, component := range s.components {
		claim, migration := component.release.Claim(), component.release.Migration()
		floors[i] = NetBirdComponentFloor{Role: component.role, ReleaseSequence: claim.ReleaseSequence, ReleaseIdentity: component.release.ReleaseIdentity(),
			Image: claim.Image, SequenceMigrationSHA256: claim.SequenceMigrationSHA256, SequenceNamespace: migration.Namespace,
			SequenceBucket: migration.Bucket, SequenceRegion: migration.Region, BundleSHA256: component.release.BundleSHA256()}
		if previous != nil && floors[i].ReleaseSequence == previous[i].ReleaseSequence {
			// Renewed signatures cannot replace the original bundle evidence.
			floors[i].BundleSHA256 = previous[i].BundleSHA256
		}
	}
	return floors
}

func (v NetBirdComponents) retainOriginalReleaseFloors(ctx context.Context) error {
	s := v.state
	// Already retained floors need no write: verify them read-only within one check.
	if peek := withOriginalNetBirdStateMemo(ctx); v.originalReleaseFloorsRetained(peek) {
		return v.Check(peek)
	}
	// This writes the state it reads; never share or reuse a memoized state here.
	ctx = withoutOriginalNetBirdStateMemo(ctx)
	guarded := ociclient.WithRequestGuard(ctx, func(context.Context) error { return v.Check(ctx) })
	state, err := s.reader.originalNetBirdState(guarded, s.resolver)
	if err != nil {
		return err
	}
	if state.intent.grantDigest != s.intent.grantDigest || state.manager.Launch == nil || state.manager.Launch.RecipeSHA256 != s.intent.recipeDigest ||
		state.manager.Launch.ProfileSHA256 != s.intent.profileDigest {
		return ErrFoundationFenced
	}
	launch := *state.manager.Launch
	if launch.ComponentFloors == nil && (s.intent.intent.StoreOrigin != "new" || launch.StoreState != "empty") {
		return errNetBirdComponentFloor
	}
	floors := s.currentReleaseFloors(launch.ComponentFloors)
	if err := retainNetBirdComponentFloors(launch.ComponentFloors, &floors); err != nil {
		return err
	}
	if launch.ComponentFloors != nil && *launch.ComponentFloors == floors {
		return v.Check(ctx)
	}
	launch.ComponentFloors = &floors
	manager := *state.manager
	manager.Launch = &launch
	state.record.OriginalFoundationCompartments.Regions[0].NetBirdManager = &manager
	state.record.UpdatedAt = time.Now().UTC()
	if _, err := s.resolver.Store.CompareAndSwap(guarded, state.record, state.etag); err != nil {
		observed, observeErr := s.reader.originalNetBirdState(guarded, s.resolver)
		if observeErr != nil || observed.manager.Launch == nil || observed.manager.Launch.ComponentFloors == nil || *observed.manager.Launch.ComponentFloors != floors {
			return errors.Join(err, observeErr)
		}
	}
	return v.Check(ctx)
}

func (v NetBirdComponents) originalReleaseFloorsRetained(ctx context.Context) bool {
	s := v.state
	state, err := s.reader.originalNetBirdState(ctx, s.resolver)
	if err != nil || state.intent.grantDigest != s.intent.grantDigest || state.manager.Launch == nil || state.manager.Launch.RecipeSHA256 != s.intent.recipeDigest ||
		state.manager.Launch.ProfileSHA256 != s.intent.profileDigest || state.manager.Launch.ComponentFloors == nil {
		return false
	}
	retained := *state.manager.Launch.ComponentFloors
	floors := s.currentReleaseFloors(&retained)
	return retainNetBirdComponentFloors(&retained, &floors) == nil && retained == floors
}
