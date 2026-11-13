package hostload

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
)

const (
	// DefaultMinInterval is the shortest spacing of two accepted reports of
	// one node. Every accepted report is one sample per role, so without it
	// a single chatty host could dominate a windowed average.
	DefaultMinInterval = 5 * time.Second
	// DefaultStaleAfter is how long a node's latest report stays listed.
	DefaultStaleAfter = 5 * time.Minute
	maxNodes          = 4096
)

var (
	ErrTooFrequent = errors.New("host load report arrived before the minimum interval")
)

// Request is a role's signed per-replica resource request. Utilization
// signals are usage divided by it, like a Kubernetes HPA's resource target.
type Request struct {
	CPUCores    float64
	MemoryBytes int64
}

// Origin is the authenticated registration a report arrived under. The
// controller fills it from its own registration state, never from the
// report.
type Origin struct {
	Cell        string
	Environment string
	Node        string
}

// NodeLoad is a node's latest accepted report.
type NodeLoad struct {
	Origin Origin    `json:"origin"`
	At     time.Time `json:"at"`
	Report Report    `json:"report"`
}

// StatelessSignal reports whether host telemetry produces the signal for a
// generic (non-TerraBase) role.
func StatelessSignal(name autoscale.SignalName) bool {
	switch name {
	case autoscale.SignalCPUUtilization, autoscale.SignalMemoryUtilization, autoscale.SignalDiskUtilization:
		return true
	default:
		return false
	}
}
