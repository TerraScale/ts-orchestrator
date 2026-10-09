// Package cellscale runs TerraBase cells autonomously. It reads the node
// pressure every TerraBase db node exposes, decides one bounded action per
// evaluation (add or remove a node, resize the OCI flex shape of every node,
// or move a noisy tenant), and applies it through small cloud and cell
// boundaries behind quorum, rollout, cooldown, rate and budget rails. Every
// action and every refusal is journaled. See docs/cell-autoscaler.md.
package cellscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

// PressureSchema is the only node pressure version this build accepts.
const PressureSchema = 2

// PressurePath is where a TerraBase db node serves its pressure, on its
// loopback admin listener (terrabase docs/api.md).
const PressurePath = "/admin/node/pressure"

const (
	// MaxTopTenants bounds the tenant list of one pressure report.
	MaxTopTenants    = 10
	maxPressureBytes = 64 << 10
	maxRate          = 1e9
	// MaxPressureAge bounds how long a sampled pressure report is usable.
	MaxPressureAge = 2 * time.Minute
	// MaxPressureClockSkew tolerates a node clock slightly ahead of ours.
	MaxPressureClockSkew = 5 * time.Second
)

var (
	ErrInvalidPressure = errors.New("invalid node pressure")
	releaseRE          = regexp.MustCompile(`^[A-Za-z0-9._:+-]{1,128}$`)
)

// NodeState is where a db node stands in its cell. Only a ready node serves
// tenants and replicas and has caught up. Fresh actions require every node
// ready; membership recovery allows one transitioning node with ready peers.
type NodeState string

const (
	StateJoining  NodeState = "joining"
	StateReady    NodeState = "ready"
	StateDraining NodeState = "draining"
	StateDrained  NodeState = "drained"
)

func (s NodeState) valid() bool {
	return s == StateJoining || s == StateReady || s == StateDraining || s == StateDrained
}

// TenantLoad is one ts-auth project's share of a node's load.
type TenantLoad struct {
	// Project is the ts-auth project ID, a canonical uppercase ULID.
	Project     string  `json:"project"`
	RequestRate float64 `json:"request_rate"`
	// CPUShare is the tenant's fraction of the node's CPU time, in [0,1].
	CPUShare float64 `json:"cpu_share"`
}

// NodePressure is the load contract a TerraBase db node serves at
// PressurePath. Utilizations are fractions in [0,1] of the node's current
// shape; rates are per second over the node's last sampling interval.
type NodePressure struct {
	Schema int    `json:"schema"`
	Node   string `json:"node"`
	// InstanceID binds this report to the OCI instance, not its reusable name.
	InstanceID string    `json:"instance_id"`
	State      NodeState `json:"state"`
	// ProcessID is a canonical ULID unique to every TerraBase process
	// start or reboot.
	ProcessID string `json:"process_id"`
	// SampledAt is when the node measured this report, never the fetch time.
	SampledAt time.Time `json:"sampled_at"`
	// Release identifies the TerraBase build the node runs. Nodes of one
	// cell that report different releases mean a rollout is in flight.
	Release        string  `json:"release"`
	CPUUtil        float64 `json:"cpu_util"`
	MemoryUtil     float64 `json:"mem_util"`
	DiskUsedBytes  int64   `json:"disk_used_bytes"`
	DiskTotalBytes int64   `json:"disk_total_bytes"`
	DiskIOPS       float64 `json:"disk_iops"`
	RequestRate    float64 `json:"request_rate"`
	IOQueueDepth   float64 `json:"io_queue_depth"`
	P95LatencyMS   float64 `json:"p95_latency_ms"`
	// Load is the required TerraBase load block of the member status
	// (connections, storage bytes, replication lag, write rate).
	Load memberstatus.Load `json:"load"`
	// TopTenants lists at most MaxTopTenants distinct projects by descending
	// request rate.
	TopTenants []TenantLoad `json:"top_tenants,omitempty"`
}

// NodeIdentity is the lifetime of one node's evidence and action progress.
// Incarnation is the pressure contract's ProcessID, unique after each start.
type NodeIdentity struct {
	Name        string `json:"node"`
	InstanceID  string `json:"instance_id"`
	Incarnation string `json:"incarnation"`
}

func (id NodeIdentity) valid() bool {
	return dbNode(id.Name) && releaseRE.MatchString(id.InstanceID) && entityid.Valid(id.Incarnation)
}

func (p NodePressure) Identity() NodeIdentity {
	return NodeIdentity{Name: p.Node, InstanceID: p.InstanceID, Incarnation: p.ProcessID}
}

// Fresh rejects unknown, expired and excessively future-dated samples.
func (p NodePressure) Fresh(now time.Time) bool {
	age := now.Sub(p.SampledAt)
	return !p.SampledAt.IsZero() && age >= -MaxPressureClockSkew && age <= MaxPressureAge
}

// DiskUtil is the used fraction of the node's data disk.
func (p NodePressure) DiskUtil() float64 {
	if p.DiskTotalBytes <= 0 {
		return 0
	}
	return float64(p.DiskUsedBytes) / float64(p.DiskTotalBytes)
}

// Validate bounds every field so a broken or hostile node cannot steer the
// autoscaler with NaN, negative or absurd values.
func (p NodePressure) Validate() error {
	if p.Schema != PressureSchema {
		return fmt.Errorf("%w: schema %d", ErrInvalidPressure, p.Schema)
	}
	if p.SampledAt.IsZero() {
		return fmt.Errorf("%w: zero sampled_at", ErrInvalidPressure)
	}
	if !p.Identity().valid() {
		return fmt.Errorf("%w: node identity %+v", ErrInvalidPressure, p.Identity())
	}
	if !dbNode(p.Node) || !p.State.valid() || !releaseRE.MatchString(p.Release) {
		return fmt.Errorf("%w: node %q state %q release %q", ErrInvalidPressure, p.Node, p.State, p.Release)
	}
	for _, fraction := range []float64{p.CPUUtil, p.MemoryUtil} {
		if !(fraction >= 0 && fraction <= 1) {
			return fmt.Errorf("%w: utilization outside [0,1]", ErrInvalidPressure)
		}
	}
	if p.DiskTotalBytes <= 0 || p.DiskUsedBytes < 0 || p.DiskUsedBytes > p.DiskTotalBytes {
		return fmt.Errorf("%w: disk bytes", ErrInvalidPressure)
	}
	for _, rate := range []float64{p.DiskIOPS, p.RequestRate, p.IOQueueDepth, p.P95LatencyMS} {
		if !(rate >= 0 && rate <= maxRate) {
			return fmt.Errorf("%w: rate outside [0,%g]", ErrInvalidPressure, maxRate)
		}
	}
	if err := p.Load.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPressure, err)
	}
	if len(p.TopTenants) > MaxTopTenants {
		return fmt.Errorf("%w: more than %d tenants", ErrInvalidPressure, MaxTopTenants)
	}
	seen := make(map[string]bool, len(p.TopTenants))
	for _, tenant := range p.TopTenants {
		if !entityid.Valid(tenant.Project) || !(tenant.RequestRate >= 0 && tenant.RequestRate <= maxRate) ||
			!(tenant.CPUShare >= 0 && tenant.CPUShare <= 1) {
			return fmt.Errorf("%w: tenant %q", ErrInvalidPressure, tenant.Project)
		}
		if seen[tenant.Project] {
			return fmt.Errorf("%w: duplicate tenant %q", ErrInvalidPressure, tenant.Project)
		}
		seen[tenant.Project] = true
	}
	return nil
}

// Source reads one node's current pressure.
type Source interface {
	Pressure(ctx context.Context, node string) (NodePressure, error)
}

// HTTPSource reads PressurePath from every node. Endpoint maps a node name
// to its base URL, for example "https://gru-1-db-2.netbird.selfhosted:9440".
type HTTPSource struct {
	Client   *http.Client
	Endpoint func(node string) string
	// Now defaults to time.Now and is read after the response body arrives.
	Now func() time.Time
}

// EndpointTemplate returns an Endpoint that substitutes {node} in template.
func EndpointTemplate(template string) func(string) string {
	return func(node string) string { return strings.ReplaceAll(template, "{node}", node) }
}

// Pressure fetches and validates one report, requiring explicit metrics so
// unknown load never reads as zero. A report for another node is rejected,
// so a misrouted endpoint cannot stand in for the node asked.
func (s HTTPSource) Pressure(ctx context.Context, node string) (NodePressure, error) {
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.Endpoint(node), "/")+PressurePath, nil)
	if err != nil {
		return NodePressure{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return NodePressure{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPressureBytes+1))
	if err != nil {
		return NodePressure{}, err
	}
	if response.StatusCode != http.StatusOK {
		return NodePressure{}, fmt.Errorf("node %s pressure: HTTP %d", node, response.StatusCode)
	}
	if len(body) > maxPressureBytes {
		return NodePressure{}, fmt.Errorf("%w: report exceeds %d bytes", ErrInvalidPressure, maxPressureBytes)
	}
	var pressure NodePressure
	if err := json.Unmarshal(body, &pressure); err != nil {
		return NodePressure{}, fmt.Errorf("%w: %v", ErrInvalidPressure, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return NodePressure{}, fmt.Errorf("%w: %v", ErrInvalidPressure, err)
	}
	if err := requirePressureFields(fields,
		"schema", "node", "instance_id", "state", "process_id", "sampled_at", "release", "cpu_util", "mem_util", "disk_used_bytes", "disk_total_bytes",
		"disk_iops", "request_rate", "io_queue_depth", "p95_latency_ms",
	); err != nil {
		return NodePressure{}, err
	}
	if raw := fields["top_tenants"]; len(raw) > 0 {
		var tenants []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tenants); err != nil {
			return NodePressure{}, fmt.Errorf("%w: top_tenants: %v", ErrInvalidPressure, err)
		}
		for i, tenant := range tenants {
			if err := requirePressureFields(tenant, "project", "request_rate", "cpu_share"); err != nil {
				return NodePressure{}, fmt.Errorf("top_tenants[%d]: %w", i, err)
			}
		}
	}
	load := memberstatus.DecodeLoad(fields["load"])
	if load == nil {
		return NodePressure{}, fmt.Errorf("%w: missing or invalid load", ErrInvalidPressure)
	}
	pressure.Load = *load
	if err := pressure.Validate(); err != nil {
		return NodePressure{}, err
	}
	if pressure.Node != node {
		return NodePressure{}, fmt.Errorf("%w: report names %q, asked %q", ErrInvalidPressure, pressure.Node, node)
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}
	if !pressure.Fresh(now()) {
		return NodePressure{}, fmt.Errorf("%w: stale or future sampled_at %s", ErrInvalidPressure, pressure.SampledAt)
	}
	return pressure, nil
}

func requirePressureFields(fields map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if raw := fields[name]; len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
			return fmt.Errorf("%w: missing or null %s", ErrInvalidPressure, name)
		}
	}
	return nil
}
