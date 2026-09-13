package dashboard

import "time"

// State is the read-only projection rendered by the operator dashboard.
// Producers may leave sections empty when a subsystem is unavailable.
type State struct {
	Version    uint64    `json:"version"`
	ObservedAt time.Time `json:"observedAt"`
	Runtime    Runtime   `json:"runtime"`
	Regions    []Region  `json:"regions"`
	Nodes      []Node    `json:"nodes"`
	Reconcile  Reconcile `json:"reconcile"`
	Rollouts   []Rollout `json:"rollouts"`
	SLO        SLO       `json:"slo"`
	NATS       NATS      `json:"nats"`
	TerraBase  TerraBase `json:"terrabase"`
	Providers  Providers `json:"providers"`
	Events     []Event   `json:"events"`
}

type Runtime struct {
	Cell      string `json:"cell"`
	Instance  string `json:"instance"`
	Health    string `json:"health"`
	Ready     bool   `json:"ready"`
	Authority uint64 `json:"authority"`
	Term      uint64 `json:"term"`
}
type Region struct {
	Code            string  `json:"code"`
	OCIName         string  `json:"ociName"`
	Health          string  `json:"health"`
	Members         int     `json:"members"`
	Workers         int     `json:"workers"`
	ControlReplicas int     `json:"controlReplicas"`
	LatencyMs       float64 `json:"latencyMs"`
	CapacityPct     float64 `json:"capacityPct"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
}
type Node struct {
	ID            string    `json:"id"`
	Region        string    `json:"region"`
	Role          string    `json:"role"`
	Shape         string    `json:"shape"`
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	Address       string    `json:"address"`
	CPUPercent    float64   `json:"cpuPercent"`
	MemoryPercent float64   `json:"memoryPercent"`
	LastSeen      time.Time `json:"lastSeen"`
}
type Reconcile struct {
	Status    string    `json:"status"`
	Phase     string    `json:"phase"`
	LastError string    `json:"lastError"`
	Cycles    uint64    `json:"cycles"`
	Pending   uint64    `json:"pending"`
	Applied   uint64    `json:"applied"`
	Failed    uint64    `json:"failed"`
	LastRun   time.Time `json:"lastRun"`
	NextRun   time.Time `json:"nextRun"`
}
type Rollout struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	Region    string `json:"region"`
	StartedAt string `json:"startedAt"`
	UpdatedAt string `json:"updatedAt"`
	Progress  int    `json:"progress"`
	Hosts     int    `json:"hosts"`
	Healthy   int    `json:"healthy"`
	Message   string `json:"message"`
}
type SLO struct {
	Availability float64 `json:"availability"`
	P95LatencyMs float64 `json:"p95LatencyMs"`
	ErrorRate    float64 `json:"errorRate"`
	Window       string  `json:"window"`
}
type NATS struct {
	Health    string `json:"health"`
	Connected uint64 `json:"connected"`
	Streams   uint64 `json:"streams"`
	Consumers uint64 `json:"consumers"`
	BytesIn   uint64 `json:"bytesIn"`
	BytesOut  uint64 `json:"bytesOut"`
}
type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Kind    string    `json:"kind"`
	Region  string    `json:"region"`
	Node    string    `json:"node"`
	Message string    `json:"message"`
}

type TerraBase struct {
	Health            string `json:"health"`
	Members           uint64 `json:"members"`
	Leaders           uint64 `json:"leaders"`
	Databases         uint64 `json:"databases"`
	Collections       uint64 `json:"collections"`
	ReplicationFactor uint64 `json:"replicationFactor"`
	StorageBytes      uint64 `json:"storageBytes"`
}

type Providers struct {
	OCI           string `json:"oci"`
	Cloudflare    string `json:"cloudflare"`
	ObjectStorage string `json:"objectStorage"`
	Vault         string `json:"vault"`
}
