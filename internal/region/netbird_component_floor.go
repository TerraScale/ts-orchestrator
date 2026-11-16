package region

import (
	"errors"
	"strings"

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
