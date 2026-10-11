// Package globalview is the dashboard's global view (TS-805). Every region's
// authority leader publishes one compact Rollup of its own state every few
// seconds on ts.orch.v1.<cell>.region.rollup; every controller keeps the
// newest rollup per region in memory and pages render from that memory.
// A last-known copy per region lives in the regional KV bucket
// TS_DASHBOARD_ROLLUPS, so an unreachable region keeps its last values with a
// stale badge. The design is docs/dashboard/global-view.md.
package globalview

import (
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
)

const (
	// Version is the rollup wire version.
	Version = 1
	// PublishEvery is how often a region's leader publishes its rollup.
	PublishEvery = 5 * time.Second
	// StaleAfter is the age past which a rollup is shown as stale: four
	// missed publishes.
	StaleAfter = 20 * time.Second
	// PersistEvery bounds how often the leader writes one region's rollup
	// to the last-known bucket.
	PersistEvery = 30 * time.Second
	// MaxBytes bounds one encoded rollup.
	MaxBytes = 256 << 10
	// NodeDownAfter is the host report age past which a node is down:
	// hosts report every 15 s.
	NodeDownAfter = time.Minute

	maxNodes         = 64
	maxServices      = 16
	maxFilesystems   = 8
	maxVolumes       = 256
	maxLinks         = 32
	maxRoutes        = 64
	maxDatabases     = 10
	maxDatabasePeers = 32
	maxErrors        = 10
	maxErrorNodes    = 8
	maxReasons       = 5
	maxMessage       = 200
)

// Health states of a region and of a node.
const (
	Healthy  = "healthy"
	Degraded = "degraded"
	Critical = "critical"

	NodeOK   = "ok"
	NodeWarn = "warn"
	NodeDown = "down"
)

// Rollup is one region's compact current state, version 1. Lists are capped;
// a capped list sets Truncated. Adding a field is compatible; renaming or
// removing one is not.
type Rollup struct {
	Version     int          `json:"version"`
	Cell        string       `json:"cell"`
	ObservedAt  time.Time    `json:"observed_at"`
	Health      Health       `json:"health"`
	Controllers Controllers  `json:"controllers"`
	Versions    []BuildCount `json:"versions,omitempty"`
	Totals      Totals       `json:"totals"`
	Nodes       []Node       `json:"nodes,omitempty"`
	Volumes     []Volume     `json:"volumes,omitempty"`
	// VolumesUnavailable marks a failed volume read: Volumes is unknown, not empty.
	VolumesUnavailable bool        `json:"volumes_unavailable,omitzero"`
	Links              []Link      `json:"links,omitempty"`
	Routes             []Route     `json:"routes,omitempty"`
	Replication        Replication `json:"replication"`
	Autoscale          Autoscale   `json:"autoscale"`
	Cost               *Cost       `json:"cost,omitempty"`
	// Scale is the region's node scaling status (TS-804): the budget allocator
	// and the region planner read it.
	Scale     *nodescale.Status `json:"scale,omitempty"`
	Databases []Database        `json:"databases,omitempty"`
	Errors    []Error           `json:"errors,omitempty"`
	Truncated bool              `json:"truncated,omitzero"`
}

// Health is a region's status and why it is not healthy.
type Health struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// Controllers is the region's controller quorum and leaders.
type Controllers struct {
	Expected   int    `json:"expected"`
	Ready      int    `json:"ready"`
	Leader     string `json:"leader,omitempty"`
	MetaLeader string `json:"meta_leader,omitempty"`
}

// BuildCount is one orchestrator build and how many controllers run it.
type BuildCount struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
	// Members names the controllers running Version, sorted.
	Members []string `json:"members,omitempty"`
}

// Totals sums the region's nodes that reported.
type Totals struct {
	Nodes           int     `json:"nodes"`
	Ready           int     `json:"ready"`
	CPUCores        int     `json:"cpu_cores"`
	CPUUsedCores    float64 `json:"cpu_used_cores"`
	MemoryBytes     uint64  `json:"memory_bytes"`
	MemoryUsedBytes uint64  `json:"memory_used_bytes"`
	DiskBytes       uint64  `json:"disk_bytes"`
	DiskUsedBytes   uint64  `json:"disk_used_bytes"`
	NetworkRxBps    float64 `json:"net_rx_bps"`
	NetworkTxBps    float64 `json:"net_tx_bps"`
	Load1           float64 `json:"load1"`
}

// Node is one server of the region. A nil reading was not measured; zero
// is a measured zero.
type Node struct {
	Name            string       `json:"name"`
	Health          string       `json:"health"`
	ReportedAt      time.Time    `json:"reported_at,omitzero"`
	CPU             *float64     `json:"cpu,omitempty"`
	CPUCores        int          `json:"cpu_cores,omitzero"`
	MemoryBytes     uint64       `json:"memory_bytes,omitzero"`
	MemoryUsedBytes uint64       `json:"memory_used_bytes,omitzero"`
	DiskBytes       uint64       `json:"disk_bytes,omitzero"`
	DiskUsedBytes   uint64       `json:"disk_used_bytes,omitzero"`
	NetworkRxBps    *float64     `json:"net_rx_bps,omitempty"`
	NetworkTxBps    *float64     `json:"net_tx_bps,omitempty"`
	Load1           *float64     `json:"load1,omitempty"`
	Services        []Service    `json:"services,omitempty"`
	Filesystems     []Filesystem `json:"filesystems,omitempty"`
}

// Service is one role placed on a node and its reported state.
type Service struct {
	Role   string `json:"role"`
	State  string `json:"state,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// Filesystem is one distinct filesystem of a node; Role names the roles
// that share it.
type Filesystem struct {
	Role      string `json:"role"`
	SizeBytes uint64 `json:"size_bytes"`
	UsedBytes uint64 `json:"used_bytes"`
}

// Volume is one managed block volume of the region.
type Volume struct {
	ID     string    `json:"id"`
	Node   string    `json:"node,omitempty"`
	State  string    `json:"state"`
	Detail string    `json:"detail,omitempty"`
	Since  time.Time `json:"since,omitzero"`
}

// Link is this region's view of one peer region: the link probe's round
// trip and reach, and how far TerraBase replication from that peer lags.
type Link struct {
	Region     string    `json:"region"`
	Reach      string    `json:"reach"`
	RTTMillis  *float64  `json:"rtt_ms,omitempty"`
	LagSeconds *float64  `json:"lag_s,omitempty"`
	Error      string    `json:"error,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// Route is one NATS route between two controllers of the region.
type Route struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	RTTMillis *float64 `json:"rtt_ms,omitempty"`
	Lag       uint64   `json:"lag,omitzero"`
	Error     string   `json:"error,omitempty"`
}

// Replication is the worst inbound TerraBase replication lag of the region.
type Replication struct {
	LagSeconds *float64 `json:"lag_s,omitempty"`
	LagGroups  *float64 `json:"lag_groups,omitempty"`
}

// Autoscale is the region's per-service scaling state. The budget cap is
// global (TS-804) and read from the global mirror, not from rollups.
type Autoscale struct {
	Services []Scaling `json:"services,omitempty"`
}

// Scaling is one autoscaled service.
type Scaling struct {
	Service  string `json:"service"`
	Replicas int    `json:"replicas"`
	Goal     int    `json:"goal"`
	Reason   string `json:"reason,omitempty"`
}

// Cost is what this region's own resources cost (TS-807).
type Cost struct {
	Currency          string    `json:"currency"`
	PerHour           float64   `json:"per_hour"`
	MonthToDate       float64   `json:"month_to_date"`
	MonthForecast     float64   `json:"month_forecast"`
	NextMonthForecast float64   `json:"next_month_forecast"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Database is one TerraBase database by replication bandwidth (TS-806).
type Database struct {
	ID                        string         `json:"id"`                      // catalog ULID
	Org                       string         `json:"org"`                     // catalog ULID
	Project                   string         `json:"project"`                 // catalog ULID
	ReplicationBytesPerSecond float64        `json:"replication_bps"`         // sent plus received
	SentBytesPerSecond        float64        `json:"sent_bps"`                // replication bytes sent to peer regions
	ReceivedBytesPerSecond    float64        `json:"received_bps"`            // replication bytes received from peer regions
	Peers                     []DatabasePeer `json:"peers,omitempty"`         // busiest first, capped at maxDatabasePeers
	StorageBytes              int64          `json:"storage_bytes,omitempty"` // this region's replica; 0 is unknown
	ReadsPerSecond            float64        `json:"reads_per_s"`             // reads served
	WritesPerSecond           float64        `json:"writes_per_s"`            // writes committed
	LagSeconds                float64        `json:"lag_s"`
}

// DatabasePeer is one database's replication bandwidth with one peer region.
type DatabasePeer struct {
	Region                 string  `json:"region"`
	SentBytesPerSecond     float64 `json:"sent_bps"`
	ReceivedBytesPerSecond float64 `json:"received_bps"`
}

// Error is one recent error class in the region (TS-808).
type Error struct {
	At        time.Time `json:"at"`    // newest occurrence
	Level     string    `json:"level"` // ERROR or WARN
	Service   string    `json:"service,omitempty"`
	Component string    `json:"component,omitempty"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Nodes     []string  `json:"nodes,omitempty"`
}
