package natscell

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// GlobalControllerPublishes is what a controller in the global home region
// publishes beyond its regional grants: the global-scope authority lease and
// journal (ts.control.global.>) and the fenced global state records
// (ts.global.v1.>). The controller role carries them in every region, so a
// credential never depends on which region is the home: only the global lease
// holder writes, fenced by the lease and the stream's compare-and-set, and
// neither namespace crosses a region link, so outside the home they reach
// nothing.
func GlobalControllerPublishes() []string {
	return []string{protocol.Control(protocol.GlobalScope, ">"), protocol.GlobalState(">")}
}

// GlobalControllerRequests are the home's request subjects, which a home
// controller both sends and answers on its own cluster. Credentials issued
// before this grant lack it: the request gets no answer and the dashboard
// reports the global leader unavailable. The home still starts, so these are
// kept out of GlobalControllerPublishes, whose absence stops it.
func GlobalControllerRequests() []string { return []string{protocol.GlobalBudgetSetSubject()} }

// ErrMissingGlobalGrants means the controller's NATS credentials predate the
// global home grants. Re-issue their signed material before starting the
// global home controller.
var ErrMissingGlobalGrants = errors.New("controller NATS credentials lack the global home publish grants")
