package app

import (
	"context"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Node operations (TS-632) are the one way a cell's servers change: ts-orch
// node drain|undrain|reboot|resize|add|retire. The authority leader runs
// them one at a time, each the same way: take the node's backends out of every fenced
// load balancer set (drain, the grace for in-flight requests, offline, each
// only while the set's quorum guard holds without it), act, check that the
// node serves again, and return its backends once their health checks
// pass. The check is the cell's own: the node's controller is back in the
// JetStream cluster and every role desired on the node reports running at
// its desired generation, which needs the member's /readyz (TerraBase
// answers it only once caught up with its peers) since the action.
//
// rename gives a node its new name (TS-609 renames gru-1-ctl-1 to ts-gru-1)
// once the cell spec grants the new name at its address: the instance, boot
// volume and hostname take it, the host re-enrolls under it at the reboot,
// and the roles desired on the old name move to it.
//
// add brings a granted, enrolled node in: its missing backends in the sets
// that name a role it runs are created out of rotation, then checked and
// returned. retire takes a node without replicas or a controller out for
// good: its backends are removed, its boot volume backed up (FULL, tagged
// delete-after a week) and its instance terminated.
//
// An operation is a record in the release channel bucket, written before
// anything changes, so a new leader resumes it. drain keeps the node out
// (holder maintenance) until undrain; the other operations hold it out
// (holder operation) while they run, and after they fail until undrain.
const ()

// nodeInstance is a node's OCI instance as observed.
type nodeInstance struct {
	ID       string
	Name     string
	State    string
	OCPUs    float32
	MemoryGB float32
}

// nodeCompute reads ROOT observations and narrows a retained signed operation.
type nodeCompute interface {
	Prepare(ctx context.Context, request rootoci.NodeMaintenanceRequest) error
	Find(ctx context.Context, node string) (nodeInstance, error)
	Instances(ctx context.Context) ([]nodeInstance, error)
	Reboot(ctx context.Context, id string) error
	Resize(ctx context.Context, id string, ocpus, memoryGB float32) error
	// Backup takes a FULL, available backup of the instance's boot volume;
	// token makes a repeated request return the same one.
	Backup(ctx context.Context, id, name string, tags map[string]string, token string) (string, error)
	Terminate(ctx context.Context, id string) error
	// Rename gives the instance and its boot volume the node's new name.
	Rename(ctx context.Context, id, name string) error
}

// nodeDesired writes host desired state: host.Controller.
type nodeDesired interface {
	ApplyDesired(ctx context.Context, d host.Desired) (host.Receipt, error)
	RetireIdle(ctx context.Context, node string) (bool, error)
}

// nodeOps runs node operations on the authority leader.
type nodeOps struct {
	fence *releaseFence
	cfg   Config
	js    jetstream.JetStream
	// compute opens the instance client on first use.
	compute func(context.Context) (nodeCompute, error)
	// cluster returns nil once node's controller, if it runs one, is back
	// in a whole JetStream cluster; nil checks nothing.
	cluster func(ctx context.Context, node string) error
	// controllers reports a node that runs a controller, which retire
	// refuses: a controller leaves the cell through its membership. Nil
	// reports none.
	controllers func(node string) bool
	// pool reports a node the node scaler owns, which every operation
	// refuses: the scaler names, drains and removes it. Nil reports none.
	pool func(node string) bool
	// desired moves a renamed node's roles to its new name.
	desired nodeDesired
	// forget deletes an instance's host enrollment grant, so a renamed host
	// enrolls afresh under its new name.
	forget func(ctx context.Context, instanceID string) error
	// poll overrides nodeOpPoll in tests.
	poll time.Duration
	wake chan struct{}
	now  func() time.Time

	mu  sync.Mutex
	api nodeCompute
}
