// Package regionview summarizes one region's state: a health score,
// controller quorum, the authority and NATS leaders, versions, capacity,
// TerraBase counts, active rollouts, the latest decisions and the open
// insights. The dashboard's global view (globalview) carries every other
// region; this package only answers for the local region.
//
// The local summary is built from the cell-wide observability snapshot, the
// decision journal and the insight engine. Each region's link probe asks its
// peers for their summary over ts.orch.v1.<region>.obs.region through
// regionlink; a region without a link is listed as not linked instead of
// being guessed at.
package regionview

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

const ()

// Status is a region's overall condition.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusCritical Status = "critical"
	// StatusUnknown is a region that cannot be observed.
	StatusUnknown Status = "unknown"
)

// Health is a 0-100 score with the reasons it was reduced.
type Health struct {
	Score   int      `json:"score"`
	Status  Status   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// Quorum is the controller quorum state.
type Quorum struct {
	Expected  int  `json:"expected"`
	Answering int  `json:"answering"`
	Ready     int  `json:"ready"`
	Required  int  `json:"required"`
	Healthy   bool `json:"healthy"`
	// Missing lists expected controllers that did not answer.
	Missing []string `json:"missing,omitempty"`
	// Unobserved reports that the cell-wide view failed and only this
	// member answered: the controller roster and quorum are unknown.
	Unobserved bool `json:"unobserved,omitempty"`
}

// Leaders names the regional authority owner and the JetStream meta leader.
type Leaders struct {
	Authority  string `json:"authority,omitempty"`
	Epoch      uint64 `json:"epoch,omitzero"`
	MetaLeader string `json:"meta_leader,omitempty"`
}

// Version is one build and the members running it.
type Version struct {
	Version string   `json:"version"`
	Members []string `json:"members"`
}

// Capacity totals coherent resource readings; Partial marks missing coverage.
type Capacity struct {
	Partial         bool    `json:"partial,omitzero"`
	CPUs            int     `json:"cpus"`
	CPUUtilization  float64 `json:"cpu_utilization,omitzero"`
	MemoryBytes     uint64  `json:"memory_bytes"`
	MemoryUsedBytes uint64  `json:"memory_used_bytes"`
	DiskBytes       uint64  `json:"disk_bytes"`
	DiskUsedBytes   uint64  `json:"disk_used_bytes"`
	StoreUsedBytes  uint64  `json:"store_used_bytes"`
	StoreLimitBytes int64   `json:"store_limit_bytes"`
}

// TerraBase counts managed databases and seats.
type TerraBase struct {
	NativeRegion    string    `json:"native_region,omitempty"`
	Databases       int       `json:"databases"`
	DesiredSeats    int       `json:"desired_seats"`
	ServingSeats    int       `json:"serving_seats"`
	Readiness       string    `json:"readiness"`
	ReadinessReason string    `json:"readiness_reason"`
	WAN             []WANPeer `json:"wan,omitempty"`
}

// Member is one answering member, for other regions' topology views.
type Member struct {
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Ready   bool   `json:"ready"`
	Version string `json:"version,omitempty"`
	// MetaLeader marks the JetStream meta leader. The NATS meta leader name
	// is a server name, not a member name, so it is carried per member.
	MetaLeader bool `json:"meta_leader,omitempty"`
}

// Host is a host that carries TerraBase seats.
type Host struct {
	Name            string `json:"name"`
	Seats           int    `json:"seats"`
	Serving         int    `json:"serving"`
	Readiness       string `json:"readiness"`
	ReadinessReason string `json:"readiness_reason"`
}

// Node is one cell server and what runs on it, for the topology view.
type Node struct {
	Name string `json:"name"`
	// Address is the private address the node's host grant names.
	Address string `json:"address,omitempty"`
	// Member is the orchestrator controller member on this node, if any,
	// and Server its NATS server name, which JetStream peers are named by.
	Member   string    `json:"member,omitempty"`
	Server   string    `json:"server,omitempty"`
	Services []Service `json:"services,omitempty"`
	// Fence names who holds the node out of its load balancer backend sets
	// (release, drain, health, ...); empty when nothing does.
	Fence []string `json:"fence,omitempty"`
	// Operation is the node's queued or running node operation with its
	// step ("drain: fence"); empty when none is active.
	Operation string `json:"operation,omitempty"`
	// Backends are the node's load balancer backends: the ones its fence
	// record took out, else one per backend set of a role it runs.
	Backends  []Backend     `json:"backends,omitempty"`
	Resources *ResourceView `json:"resources,omitempty"`
}

// Service is one role a host grant places on a node and its observed state.
type Service struct {
	Role        string `json:"role"`
	Digest      string `json:"digest,omitempty"`
	State       string `json:"state,omitempty"`
	StateReason string `json:"state_reason,omitempty"`
}

// Backend is one of a node's load balancer backends. Offline is from the
// node's fence record, not a live load balancer read.
type Backend struct {
	Set     string `json:"set"`
	Offline bool   `json:"offline,omitzero"`
}

// Summary is one region's card on the global view.
type Summary struct {
	Version int    `json:"version"`
	Region  string `json:"region"`
	Local   bool   `json:"local,omitzero"`
	// Reach is ok, not_linked, unreachable or error (decisionlog states).
	Reach      string                      `json:"reach"`
	ObservedAt time.Time                   `json:"observed_at,omitzero"`
	Health     Health                      `json:"health"`
	Quorum     Quorum                      `json:"quorum"`
	Leaders    Leaders                     `json:"leaders"`
	Versions   []Version                   `json:"versions,omitempty"`
	Capacity   Capacity                    `json:"capacity"`
	TerraBase  TerraBase                   `json:"terrabase"`
	Rollouts   []observability.RolloutView `json:"rollouts,omitempty"`
	Decisions  []decisionlog.Decision      `json:"decisions,omitempty"`
	Insights   []insights.Insight          `json:"insights,omitempty"`
	Counts     insights.Counts             `json:"counts"`
	// Members and Hosts are the region's answering members and seat hosts,
	// bounded, for the topology view. Older regions omit them.
	Members []Member `json:"members,omitempty"`
	Hosts   []Host   `json:"hosts,omitempty"`
	// Nodes are the region's granted nodes and their services, bounded.
	// Older regions omit them.
	Nodes           []Node      `json:"nodes,omitempty"`
	Links           []LinkProbe `json:"links,omitempty"`
	NodesIncomplete bool        `json:"nodes_incomplete,omitzero"`
	// Cost is the region's OCI cost view. Older regions omit it.
	Cost *ocicost.View `json:"cost,omitempty"`
}

// MixedVersions reports whether members run more than one build.
func (summary Summary) MixedVersions() bool { return len(summary.Versions) > 1 }
