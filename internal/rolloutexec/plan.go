package rolloutexec

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

// ControllerGroup is the quorum group of the regional controllers.
const ControllerGroup = "controllers"

// Program is an ordered list of rollouts. The executor starts each one only
// after the previous one completed, so the controllers finish before any
// host moves, and stops the program at the first rollout that did not
// complete (rolled back, aborted).
type Program []rollout.Spec

// ReleaseProgram derives the executor's program from the cell's desired
// release (rollout.Store.Desired): the controllers that do not run it yet
// move to it from the release they all prove now, one per wave and the seed
// last, and once they completed, the hosts do the same, one seat of a
// TerraBase partition at a time. A started rollout keeps the units and
// predecessor it began with. Nothing starts while the cell is paused, has no
// desired release, already runs it everywhere, or knows it as bad.
//
// ponytail: a unit that falls behind after its generation's rollout
// completed waits for the next generation.
type ReleaseProgram struct {
	Store       *rollout.Store
	Proofs      ProofSource
	Controllers []rollout.Unit
	// Hosts returns the cell's host units (HostUnits) once the controllers
	// completed; nil moves no host.
	Hosts     func(ctx context.Context) ([]rollout.Unit, error)
	Policy    rollout.Policy
	Freshness time.Duration
	Now       func() time.Time
}
