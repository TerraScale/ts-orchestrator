package cellscale

import (
	"errors"
	"fmt"
	"math"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
)

var ErrInvalidPolicy = errors.New("invalid cell autoscaling policy")

// hoursPerMonth is the OCI billing month.
const hoursPerMonth = 730

// Shape is an OCI flex shape configuration.
type Shape struct {
	OCPUs    float64 `json:"ocpus"`
	MemoryGB float64 `json:"memory_gb"`
}

func (s Shape) String() string { return fmt.Sprintf("%g OCPU/%g GB", s.OCPUs, s.MemoryGB) }

// ShapeBounds limits vertical resizing. Every resize moves OCPUs by
// StepOCPUs and keeps MemoryGBPerOCPU, so a cell has one shape ladder.
type ShapeBounds struct {
	MinOCPUs        float64 `json:"min_ocpus"`
	MaxOCPUs        float64 `json:"max_ocpus"`
	StepOCPUs       float64 `json:"step_ocpus"`
	MemoryGBPerOCPU float64 `json:"memory_gb_per_ocpu"`
}

func (b ShapeBounds) at(ocpus float64) Shape {
	return Shape{OCPUs: ocpus, MemoryGB: ocpus * b.MemoryGBPerOCPU}
}

// Targets is the per-node value of each signal that counts as full: a
// signal's pressure is its value divided by its target.
type Targets struct {
	CPUUtil      float64 `json:"cpu_util"`
	MemoryUtil   float64 `json:"mem_util"`
	DiskUtil     float64 `json:"disk_util"`
	DiskIOPS     float64 `json:"disk_iops"`
	RequestRate  float64 `json:"request_rate"`
	IOQueueDepth float64 `json:"io_queue_depth"`
	P95LatencyMS float64 `json:"p95_latency_ms"`
}

// Prices are the OCI list prices of the cell's shape, in the budget's
// currency. NodeMonthly covers each node's fixed boot and block volumes.
type Prices struct {
	OCPUHour     float64 `json:"ocpu_hour"`
	MemoryGBHour float64 `json:"memory_gb_hour"`
	NodeMonthly  float64 `json:"node_monthly"`
}

// Policy bounds what the autoscaler may do to one cell. Pressure at or above
// 1 sustained for SustainUpSeconds scales up; pressure that would stay at or
// below ScaleDownBelow after removing capacity, sustained for
// SustainDownSeconds, scales down. The band between is the hysteresis.
type Policy struct {
	Nodes autoscale.Bounds `json:"nodes"`
	// ReplicationFactor is the replica count of every tenant. The cell never
	// shrinks below it, and a rolling restart needs a majority of it up.
	ReplicationFactor int `json:"replication_factor"`
	// MaxReplicationLagSeq holds every action while any node's TerraBase
	// load block reports a slower peer further behind, so a drain or restart
	// never removes the only caught-up copy.
	MaxReplicationLagSeq uint64      `json:"max_replication_lag_seq"`
	Shape                ShapeBounds `json:"shape"`
	Targets              Targets     `json:"targets"`
	ScaleDownBelow       float64     `json:"scale_down_below"`
	SustainUpSeconds     int         `json:"sustain_up_seconds"`
	// SustainDownSeconds should exceed a day's quiet trough only if the cell
	// must keep its daytime capacity overnight.
	SustainDownSeconds int `json:"sustain_down_seconds"`
	// CooldownSeconds follows any action before the next scale up;
	// ScaleDownCooldownSeconds follows any action before the next scale down.
	CooldownSeconds          int     `json:"cooldown_seconds"`
	ScaleDownCooldownSeconds int     `json:"scale_down_cooldown_seconds"`
	MaxActionsPerHour        int     `json:"max_actions_per_hour"`
	MonthlyBudget            float64 `json:"monthly_budget"`
	Prices                   Prices  `json:"prices"`
	// MaxFailures consecutive failed actions pause the autoscaler until an
	// operator resumes it.
	MaxFailures int  `json:"max_failures"`
	DryRun      bool `json:"dry_run,omitempty"`
}

func (p Policy) sustainUp() time.Duration   { return seconds(p.SustainUpSeconds) }
func (p Policy) sustainDown() time.Duration { return seconds(p.SustainDownSeconds) }
func (p Policy) cooldown() time.Duration    { return seconds(p.CooldownSeconds) }
func (p Policy) downCooldown() time.Duration {
	return seconds(p.ScaleDownCooldownSeconds)
}

func seconds(value int) time.Duration { return time.Duration(value) * time.Second }

// quorum is the replica majority that must stay up during a restart.
func (p Policy) quorum() int { return p.ReplicationFactor/2 + 1 }

// canRestart requires both cell capacity and every tenant's surviving
// replicas to retain quorum; extra nodes do not add replicas to a tenant.
func (p Policy) canRestart(nodes int) bool {
	return min(nodes, p.ReplicationFactor)-1 >= p.quorum()
}

// MonthlyCost is the run rate of nodes at shape.
func (p Policy) MonthlyCost(nodes int, shape Shape) float64 {
	hourly := shape.OCPUs*p.Prices.OCPUHour + shape.MemoryGB*p.Prices.MemoryGBHour
	return float64(nodes) * (hourly*hoursPerMonth + p.Prices.NodeMonthly)
}

// Validate checks every field is bounded and that the cell's floor fits the
// budget, so the autoscaler can always honour MinNodes.
func (p Policy) Validate() error {
	if err := p.Nodes.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if p.ReplicationFactor < 1 || p.Nodes.Min < p.ReplicationFactor || p.Nodes.Max > maxOrdinal {
		return fmt.Errorf("%w: need 1 <= replication_factor <= nodes.min <= nodes.max <= %d", ErrInvalidPolicy, maxOrdinal)
	}
	if p.MaxReplicationLagSeq < 1 {
		return fmt.Errorf("%w: max_replication_lag_seq must be positive", ErrInvalidPolicy)
	}
	b := p.Shape
	if !positive(b.MinOCPUs) || b.MaxOCPUs < b.MinOCPUs || b.MaxOCPUs > 128 || !positive(b.StepOCPUs) ||
		!positive(b.MemoryGBPerOCPU) || b.MemoryGBPerOCPU > 64 {
		return fmt.Errorf("%w: shape bounds", ErrInvalidPolicy)
	}
	if sameShape(Shape{}, b.at(b.StepOCPUs)) {
		return fmt.Errorf("%w: step_ocpus must change OCPUs or memory by at least 0.001", ErrInvalidPolicy)
	}
	t := p.Targets
	for _, target := range []float64{t.CPUUtil, t.MemoryUtil, t.DiskUtil, t.DiskIOPS, t.RequestRate, t.IOQueueDepth, t.P95LatencyMS} {
		if !positive(target) {
			return fmt.Errorf("%w: every target must be positive and finite", ErrInvalidPolicy)
		}
	}
	if t.CPUUtil > 1 || t.MemoryUtil > 1 || t.DiskUtil > 1 {
		return fmt.Errorf("%w: utilization targets must be at most 1", ErrInvalidPolicy)
	}
	if !(p.ScaleDownBelow > 0 && p.ScaleDownBelow <= 0.9) {
		return fmt.Errorf("%w: scale_down_below must be within (0,0.9]", ErrInvalidPolicy)
	}
	for _, value := range []int{p.SustainUpSeconds, p.SustainDownSeconds, p.CooldownSeconds, p.ScaleDownCooldownSeconds} {
		if value < 0 || value > 7*24*60*60 {
			return fmt.Errorf("%w: sustain and cooldown must be within 0..7d", ErrInvalidPolicy)
		}
	}
	if p.MaxActionsPerHour < 1 || p.MaxActionsPerHour > 60 || p.MaxFailures < 1 || p.MaxFailures > 10 {
		return fmt.Errorf("%w: max_actions_per_hour 1..60 and max_failures 1..10", ErrInvalidPolicy)
	}
	for _, price := range []float64{p.Prices.OCPUHour, p.Prices.MemoryGBHour, p.Prices.NodeMonthly} {
		if !(price >= 0) || math.IsInf(price, 0) {
			return fmt.Errorf("%w: prices must be non-negative and finite", ErrInvalidPolicy)
		}
	}
	if !positive(p.MonthlyBudget) {
		return fmt.Errorf("%w: monthly_budget must be positive", ErrInvalidPolicy)
	}
	if floor := p.MonthlyCost(p.Nodes.Min, b.at(b.MinOCPUs)); floor > p.MonthlyBudget {
		return fmt.Errorf("%w: nodes.min at min shape cost %.2f a month, over the %.2f budget", ErrInvalidPolicy, floor, p.MonthlyBudget)
	}
	return nil
}

func positive(value float64) bool { return value > 0 && !math.IsInf(value, 0) }
