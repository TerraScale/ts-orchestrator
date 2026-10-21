package protocol

// Release push subjects on a region's single-host NATS (internal/releasepush).
// CI may publish only under ReleaseWildcard.
const (
	ReleaseWildcard = "ts.release.>"
	ReleaseVersion  = "ts.release.version"
	ReleaseOrch     = "ts.release.ts-orch"
	ReleaseApp      = "ts.release.app"
)
