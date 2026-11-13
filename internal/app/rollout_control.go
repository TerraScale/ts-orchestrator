package app

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// Operator rollout requests travel on the host registration subject, like
// cell spec requests, so every issued operator credential can already send them.
const ()

// rolloutControl answers operator rollout requests and runs cell self-updates:
// every controller publishes signed health proofs, collects its peers' and
// relays its own steps to the node's root step agent, and the authority
// leader's executor moves the controllers to the desired release, one per
// wave and the seed last. The leader follows the region's release channel.
type rolloutControl struct {
	cell  string
	store atomic.Pointer[rollout.Store]
	// status is the newest status this controller's executor derived; only
	// the leader's is current, and only the leader answers requests.
	status atomic.Pointer[rolloutexec.Status]
	conn   *nats.Conn
	// verify admits a currently valid release receipt for this cell and
	// returns the release it names; nil refuses every publish.
	verify func(receipt, delegation []byte, now time.Time) (rollout.Release, error)
	// ready reports a controller that finished starting; it publishes
	// health proofs only then.
	ready atomic.Bool
	// interval overrides the executor's and the step relay's tick in tests.
	interval time.Duration

	// roots and environment verify a release channel for this cell.
	roots         *rootRegistry
	environment   string
	architectures []string
	// managedArchitecture observes OCI only when release reconciliation runs,
	// so a provider outage cannot prevent an accepted controller restarting.
	managedArchitecture func(context.Context) (string, error)
	// ticks wakes the consumer after every executor tick.
	ticks chan struct{}
	// channel is the region's head bucket, the CI edge; nil bridges none.
	channel *channelSource
	// channelInterval overrides how often the CI edge reads it, in tests.
	channelInterval time.Duration
	// reported is the status this leader last wrote to the channel.
	reported atomic.Pointer[releasechannel.Status]
	// logged is the status last logged at INFO. Only the channel loop reads
	// or writes it, so a repeat of it is logged at DEBUG.
	logged *releasechannel.Status
	// program derives the executor's rollouts; the channel reads its proofs.
	program rolloutexec.ReleaseProgram
	// controllerNode returns the node of a controller slot's VM, which a
	// host grant can name (TS-609); nil keeps the slot's NATS server name.
	controllerNode func(slot string) string
	// policy returns the fixed rollout policy; tests replace its clock windows.
	policy func() rollout.Policy
	// hosts serves host self-updates once the executor runs.
	hosts atomic.Pointer[rolloutHosts]
	// drainedSeats, when the TerraBase seat controller runs, holds host
	// steps while a seat is out of rotation (rolloutGate).
	drainedSeats func(context.Context) (map[string]bool, error)
	// fence, with the cell spec's release fence, takes each unit's node
	// out of rotation before its step (rolloutFence); nil fences nothing.
	fence *releaseFence
	// spool and layout are the step relay's directory and the node's
	// release root; tests point them elsewhere.
	spool  string
	layout selfupdate.Layout
}

// PublishStatus keeps the executor's status for requests, publishes it and
// wakes the release channel consumer.
func (c *rolloutControl) PublishStatus(status rolloutexec.Status) {
	c.status.Store(&status)
	rolloutexec.NATSStatus{Conn: c.conn, Cell: c.cell}.PublishStatus(status)
	select {
	case c.ticks <- struct{}{}:
	default:
	}
}
