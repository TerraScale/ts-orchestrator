package protocol

const (
	// MeshApplySubject merges one service desired-state entry and reconciles it.
	MeshApplySubject = "ts.svc.apply"
	// MeshStateSubject returns a region's whole desired-state map for anti-entropy.
	MeshStateSubject = "ts.svc.state"
	// MeshPingSubject answers with the region and server name.
	MeshPingSubject         = "ts.mesh.ping"
	MeshWorkerReleasePrefix = "ts.mesh.release."
	MeshWorkerPrefix        = "ts.mesh.worker."
	// MeshDrainPrefix + region asks its ingress to drain a TerraBase task.
	MeshDrainPrefix = "ts.mesh.drain."
	// MeshHealthSubject answers with the region's host and SwarmKit health
	// (internal/regionhealth).
	MeshHealthSubject      = "ts.mesh.health"
	MeshReconcileSubject   = "ts.mesh.reconcile"
	MeshPullPrefix         = "ts.mesh.pull."
	MeshPullProgressPrefix = "ts.mesh.pull-progress."
	MeshPullDiscoverPrefix = "ts.mesh.pull-discover."
	MeshMemberPrefix       = "ts.mesh.member."
)
