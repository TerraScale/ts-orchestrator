package protocol

// Release push subjects on a region's single-host NATS (internal/releasepush).
// CI may publish only under ReleaseWildcard.
const (
	ReleaseWildcard = "ts.release.>"
	ReleaseVersion  = "ts.release.version"
	ReleaseOrch     = "ts.release.ts-orch"
	ReleaseApp      = "ts.release.app"
	// The multi-region workflow may publish only under ReleaseMeshWildcard;
	// the host forwards these to the cross-region mesh (internal/natscell/mesh).
	ReleaseMeshWildcard = "ts.release.mesh.>"
	ReleaseMeshPing     = "ts.release.mesh.ping"
	ReleaseMeshApply    = "ts.release.mesh.apply"
	ReleaseMeshRemove   = "ts.release.mesh.rm"
	// ReleaseMeshState reads every mesh service's desired image.
	ReleaseMeshState = "ts.release.mesh.state"
)
