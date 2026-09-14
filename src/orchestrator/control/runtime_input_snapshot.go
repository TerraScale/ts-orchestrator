package control

// RuntimeTechnicalLimits ports the public technical denial-of-service safety
// limits; these are not lifecycle, health, or rollout policy.
const RuntimeTechnicalLimitsMaximumCapturedItems = 4096

// RuntimeInputSnapshot is retained as a name anchor for the internal helper
// runtimeInputSnapshotCopy defined with the runtime models.
var RuntimeInputSnapshot runtimeInputSnapshotStatic

type runtimeInputSnapshotStatic struct{}
