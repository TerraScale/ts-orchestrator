package protocol

const (
	ReleaseWildcard = "ts.release.>"
	ReleaseVersion  = "ts.release.version"
	ReleaseHealth   = "ts.release.health"
	ReleaseOrch     = "ts.release.ts-orch"
	ReleaseApp      = "ts.release.app"
	ReleaseNudge    = "ts.release.nudge"
	// The multi-region workflow may publish only under ReleaseMeshWildcard;
	// the host forwards these to the cross-region mesh (internal/natscell/mesh).
	ReleaseMeshWildcard = "ts.release.mesh.>"
	ReleaseMeshPing     = "ts.release.mesh.ping"
	ReleaseMeshApply    = "ts.release.mesh.apply"
	ReleaseMeshRemove   = "ts.release.mesh.rm"
	// ReleaseMeshState reads every mesh service's desired image.
	ReleaseMeshState = "ts.release.mesh.state"
)
