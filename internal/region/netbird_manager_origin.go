package region

import "time"

// netBirdManagerOrigin excludes independently progressing store and account state.
type netBirdManagerOrigin struct {
	SlotID              string    `json:"slotId"`
	OperationID         string    `json:"operationId"`
	ProfileSHA256       string    `json:"profileSha256"`
	RecipeSHA256        string    `json:"recipeSha256"`
	RequestDigest       string    `json:"requestDigest"`
	RetryToken          string    `json:"retryToken"`
	StartedAt           time.Time `json:"startedAt"`
	InstanceID          string    `json:"instanceId,omitempty"`
	BootVolumeID        string    `json:"bootVolumeId,omitempty"`
	OriginGrantSHA256   string    `json:"originGrantSha256"`
	OriginBindingSHA256 string    `json:"originBindingSha256,omitempty"`
	OriginalScopeSHA256 string    `json:"originalScopeSha256"`
	PhysicalScopeSHA256 string    `json:"physicalScopeSha256"`
}

func (launch NetBirdManagerLaunch) original() netBirdManagerOrigin {
	return netBirdManagerOrigin{
		SlotID: launch.SlotID, OperationID: launch.OperationID,
		ProfileSHA256: launch.ProfileSHA256, RecipeSHA256: launch.RecipeSHA256,
		RequestDigest: launch.RequestDigest, RetryToken: launch.RetryToken, StartedAt: launch.StartedAt,
		InstanceID: launch.InstanceID, BootVolumeID: launch.BootVolumeID,
		OriginGrantSHA256: launch.OriginGrantSHA256, OriginBindingSHA256: launch.OriginBindingSHA256,
		OriginalScopeSHA256: launch.OriginalScopeSHA256, PhysicalScopeSHA256: launch.PhysicalScopeSHA256,
	}
}
