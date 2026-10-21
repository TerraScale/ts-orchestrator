package protocol

// Mesh subjects cross every region's gateway on the single-host mesh
// (internal/natscell/mesh). Each is a request that collects one reply per region.
const (
	// MeshApplySubject merges one service desired-state entry and reconciles it.
	MeshApplySubject = "ts.svc.apply"
	// MeshStateSubject returns a region's whole desired-state map for anti-entropy.
	MeshStateSubject = "ts.svc.state"
	// MeshPingSubject answers with the region and server name.
	MeshPingSubject = "ts.mesh.ping"
)
