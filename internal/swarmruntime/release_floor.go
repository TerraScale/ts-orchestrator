package swarmruntime

// ServiceReleaseFloor describes retained admission evidence, not permission to retry.
type ServiceReleaseFloor struct {
	OperationID                   string
	Generation, ReleaseSequence   uint64
	ReleaseIdentity, IntentSHA256 string
}
