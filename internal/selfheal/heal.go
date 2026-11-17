package selfheal

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const (
	Grace        = 5 * time.Minute
	BootTime     = 10 * time.Minute
	JoinWait     = 30 * time.Minute
	BudgetWindow = 24 * time.Hour

	stepReboot  = "reboot"
	stepReplace = "replace"
	stepJoining = "joining"
)

type Status struct {
	Healthy   int      `json:"healthy"`
	Booting   int      `json:"booting,omitzero"`
	Unhealthy []string `json:"unhealthy,omitempty"`
	Blocked   string   `json:"blocked,omitempty"`
	Repair    *Repair  `json:"repair,omitempty"`
	Last      *Repair  `json:"last,omitempty"`
	Stopped   string   `json:"stopped,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type Healer struct {
	region  string
	state   string
	node    *swarmruntime.Node
	leading func() bool

	mu       sync.Mutex
	since    map[string]time.Time
	status   Status
	repairs  map[[2]string]int
	refusals map[string]int
}

var healers sync.Map

func New(region, state string, node *swarmruntime.Node, leading func() bool) *Healer {
	h := &Healer{region: region, state: state, node: node, leading: leading,
		since: map[string]time.Time{}, repairs: map[[2]string]int{}, refusals: map[string]int{}}
	healers.Store(region, h)
	return h
}

func (h *Healer) Close() { healers.CompareAndDelete(h.region, h) }

func (h *Healer) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

func (h *Healer) Tick(ctx context.Context, guard func(context.Context) error) {
	status, err := h.tick(ctx, guard)
	if err != nil {
		status.Error = err.Error()
		slog.WarnContext(ctx, "self-heal changes nothing this tick", "region", h.region, "error", err)
	}
	h.mu.Lock()
	h.status = status
	h.mu.Unlock()
}

type observed struct {
	node     *api.Node
	host     string
	instance *core.Instance
	reason   string
	booting  bool
}

type pass struct {
	*Healer
	guard      func(context.Context) error
	region     fleet.Region
	client     api.ControlClient
	compute    core.ComputeClient
	store      *store
	record     Record
	revision   uint64
	nodes      []observed
	owned      map[string]core.Instance
	tasks      []*api.Task
	now        time.Time
	reconciled bool
}

func (h *Healer) tick(ctx context.Context, guard func(context.Context) error) (Status, error) {
	document, err := fleet.Load()
	if err != nil {
		return Status{}, err
	}
	p := &pass{Healer: h, guard: guard, now: time.Now()}
	if p.region, err = document.Region(h.region); err != nil {
		return Status{}, err
	}
	p.reconciled = slices.Contains(p.region.Reconcile, "compute")
	if p.client, err = h.node.ControlClient(ctx); err != nil {
		return Status{}, err
	}
	listed, err := p.client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return Status{}, err
	}
	tasks, err := p.client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return Status{}, err
	}
	p.tasks = tasks.Tasks
	conn, err := mesh.Connect(h.state)
	if err != nil {
		return Status{}, err
	}
	defer conn.Close()
	fabric, err := mesh.ConnectFabric(h.state)
	if err != nil {
		return Status{}, err
	}
	defer fabric.Close()
	if p.store, err = openStore(ctx, fabric, h.region); err != nil {
		return Status{}, err
	}
	if p.record, p.revision, err = p.store.load(ctx); err != nil {
		return Status{}, err
	}
	f, err := fleet.LoopFactory(ctx, p.region)
	if err != nil {
		return Status{}, err
	}
	if p.compute, err = f.Compute(); err != nil {
		return Status{}, err
	}
	if p.owned, err = ownedInstances(ctx, p.compute, p.region); err != nil {
		return Status{}, err
	}
	p.observe(ctx, conn, listed.Nodes)
	overdue := p.track(ctx)
	switch {
	case p.record.Repair != nil:
		err = p.advance(ctx)
	case p.record.Stopped != "" && len(p.unhealthy()) == 0 && p.booting() == 0 && len(p.nodes) >= p.record.Nodes:
		stopped := p.record.Stopped
		p.record.Stopped = ""
		if err = p.save(ctx); err == nil {
			slog.InfoContext(ctx, "self-heal resumes: the region is back to its size with every node healthy", "region", h.region, "nodes", len(p.nodes), "was", stopped)
		}
	case len(overdue) > 0:
		err = p.start(ctx, overdue[0])
	}
	return p.summary(), err
}

func ownedInstances(ctx context.Context, client core.ComputeClient, region fleet.Region) (map[string]core.Instance, error) {
	ownership := ociresource.Ownership{Owner: fleet.Owner}
	owned := map[string]core.Instance{}
	var page *string
	for {
		listed, err := client.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &region.CompartmentID, Page: page})
		if err != nil {
			return nil, fmt.Errorf("list instances: %w", err)
		}
		for _, instance := range listed.Items {
			if ownership.Owns(region.Key("instance", "node"), ociresource.Tags{Freeform: instance.FreeformTags}) && instance.Id != nil && instance.DisplayName != nil {
				owned[*instance.Id] = instance
			}
		}
		if page = listed.OpcNextPage; page == nil {
			return owned, nil
		}
	}
}

func (p *pass) observe(ctx context.Context, conn *nats.Conn, nodes []*api.Node) {
	byHost := map[string]core.Instance{}
	for _, instance := range p.owned {
		if current, ok := byHost[*instance.DisplayName]; !ok || instance.TimeCreated.After(current.TimeCreated.Time) {
			byHost[*instance.DisplayName] = instance
		}
	}
	ready := make([]string, len(nodes))
	var pending sync.WaitGroup
	for i, node := range nodes {
		pending.Go(func() {
			reply, err := releasepush.AskStatus(ctx, conn, p.Healer.region, node.ID)
			switch {
			case err != nil:
				ready[i] = "its readiness does not answer"
			case reply.Node != "" && reply.Node != "ok":
				ready[i] = "its node checks fail: " + reply.Node
			}
		})
	}
	pending.Wait()
	for i, node := range nodes {
		o := observed{node: node}
		if node.Description != nil {
			o.host = node.Description.Hostname
		}
		if instance, ok := byHost[o.host]; ok {
			o.instance = &instance
		}
		o.reason = unhealthy(node, o.instance, ready[i])
		o.booting = o.reason != "" && p.now.Sub(p.bootedAt(o)) < BootTime
		p.nodes = append(p.nodes, o)
	}
	slices.SortFunc(p.nodes, func(a, b observed) int { return strings.Compare(a.host, b.host) })
}

func unhealthy(node *api.Node, instance *core.Instance, ready string) string {
	switch {
	case node.Status.State != api.NodeStatus_READY:
		return "SwarmKit reports it " + strings.ToLower(node.Status.State.String())
	case node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_UNREACHABLE:
		return "SwarmKit reports its manager unreachable"
	case instance != nil && instance.LifecycleState != core.InstanceLifecycleStateRunning:
		return "its OCI instance is " + strings.ToLower(string(instance.LifecycleState))
	}
	return ready
}

func (p *pass) bootedAt(o observed) time.Time {
	booted, _ := types.TimestampFromProto(o.node.Meta.CreatedAt)
	if o.instance != nil && o.instance.TimeCreated != nil && o.instance.TimeCreated.After(booted) {
		booted = o.instance.TimeCreated.Time
	}
	if r := p.record.Repair; r != nil && r.Node == o.node.ID && r.Step == stepReboot && r.Sent.After(booted) {
		booted = r.Sent
	}
	return booted
}

func (p *pass) track(ctx context.Context) []observed {
	p.mu.Lock()
	defer p.mu.Unlock()
	present := map[string]bool{}
	var overdue []observed
	for _, o := range p.nodes {
		present[o.node.ID] = true
		if o.reason == "" || o.booting {
			delete(p.since, o.node.ID)
			continue
		}
		since, ok := p.since[o.node.ID]
		if !ok {
			since = p.now
			p.since[o.node.ID] = since
			slog.WarnContext(ctx, "self-heal sees an unhealthy node; it acts only if the node stays unhealthy for the grace time", "region", p.Healer.region, "host", o.host, "reason", o.reason, "grace", Grace)
		}
		if p.now.Sub(since) >= Grace {
			overdue = append(overdue, o)
		}
	}
	for id := range p.since {
		if !present[id] {
			delete(p.since, id)
		}
	}
	return overdue
}

func (p *pass) unhealthy() []observed {
	return slices.DeleteFunc(slices.Clone(p.nodes), func(o observed) bool { return o.reason == "" || o.booting })
}

func (p *pass) booting() int {
	return len(slices.DeleteFunc(slices.Clone(p.nodes), func(o observed) bool { return !o.booting }))
}

func (p *pass) find(id string) (observed, bool) {
	i := slices.IndexFunc(p.nodes, func(o observed) bool { return o.node.ID == id })
	if i < 0 {
		return observed{}, false
	}
	return p.nodes[i], true
}

func (p *pass) blocked() string {
	switch {
	case !p.reconciled:
		return "compute is not in this region's reconcile list"
	case p.record.Stopped != "":
		return "stopped: " + p.record.Stopped
	}
	return ""
}

func (p *pass) standing() (string, string) {
	switch {
	case !p.reconciled:
		return "compute-not-reconciled", p.blocked()
	case p.record.Stopped != "":
		return "stopped", p.record.Stopped
	}
	return "", ""
}

func (p *pass) instance(r *Repair, c observed, present bool) (core.Instance, string, string) {
	instance, ok := p.owned[r.Instance]
	switch {
	case !ok:
		return core.Instance{}, "not-a-pool-node", "instance " + r.Instance + " is not a document-made node of this region"
	case present && c.host != *instance.DisplayName:
		return core.Instance{}, "not-a-pool-node", "instance " + r.Instance + " is not named " + c.host
	}
	return instance, "", ""
}

func (p *pass) refusal(ctx context.Context, c observed) (string, string) {
	if reason, detail := p.standing(); reason != "" {
		return reason, detail
	}
	if n := len(p.unhealthy()); n > 1 {
		return "several-unhealthy", fmt.Sprintf("%d nodes are unhealthy at once; that looks like a region or network problem", n)
	}
	if c.instance == nil {
		return "not-a-pool-node", "no document-made OCI instance is named " + c.host
	}
	if c.node.ManagerStatus != nil && c.node.ManagerStatus.Leader {
		return "leader", "the Raft leader never repairs itself"
	}
	if c.node.Role == api.NodeRoleManager {
		if err := swarmruntime.CanDemoteManager(ctx, p.client, c.node.ID); err != nil {
			return "quorum", err.Error()
		}
	}
	healthy := map[string]bool{}
	for _, o := range p.nodes {
		healthy[o.node.ID] = o.reason == "" && o.node.ID != c.node.ID
	}
	for _, task := range p.tasks {
		if task.NodeID != c.node.ID || !execution.Stateful(task) || task.DesiredState > api.TaskStateRunning && task.Status.State > api.TaskStateRunning {
			continue
		}
		if !slices.ContainsFunc(p.tasks, func(other *api.Task) bool {
			return other.ServiceID == task.ServiceID && healthy[other.NodeID] && other.Status.State == api.TaskStateRunning
		}) {
			return "last-copy", "it holds the last healthy copy of " + task.ServiceAnnotations.Name
		}
	}
	return "", ""
}

func (p *pass) budget() (string, string) {
	if next := p.record.Replaced.Add(BudgetWindow); p.now.Before(next) {
		return "budget", fmt.Sprintf("one replacement per region per %s; the next is allowed at %s", BudgetWindow, next.UTC().Format(time.RFC3339))
	}
	return "", ""
}

func (p *pass) start(ctx context.Context, c observed) error {
	reason, detail := p.refusal(ctx, c)
	step := stepReboot
	if reason == "" && c.instance.LifecycleState != core.InstanceLifecycleStateRunning {
		step = stepReplace
		reason, detail = p.budget()
	}
	if reason != "" {
		p.refuse(ctx, c.host, reason, detail)
		return nil
	}
	p.record.Repair = &Repair{Host: c.host, Node: c.node.ID, Instance: *c.instance.Id, Reason: c.reason, Step: step, Started: p.now, StepAt: p.now}
	p.record.Nodes = len(p.nodes)
	if step == stepReplace {
		p.record.Replaced = p.now
	}
	if err := p.save(ctx); err != nil {
		return err
	}
	p.decided(ctx, step, "started", c.host, c.reason)
	if step == stepReplace {
		return p.replace(ctx, *c.instance)
	}
	return p.reset(ctx)
}

func (p *pass) reset(ctx context.Context) error {
	r := p.record.Repair
	if _, err := p.compute.InstanceAction(ociclient.WithAuthority(ctx, p.guard), core.InstanceActionRequest{InstanceId: &r.Instance, Action: core.InstanceActionActionReset}); err != nil {
		return fmt.Errorf("reboot %s: %w", r.Host, err)
	}
	r.Sent = time.Now()
	if err := p.save(ctx); err != nil {
		return err
	}
	p.decided(ctx, stepReboot, "sent", r.Host, "OCI reset of "+r.Instance)
	return nil
}

func (p *pass) advance(ctx context.Context) error {
	r := p.record.Repair
	c, present := p.find(r.Node)
	if reason, detail := p.standing(); reason != "" {
		p.refuse(ctx, r.Host, reason, detail)
		return nil
	}
	instance, reason, detail := p.instance(r, c, present)
	if reason != "" && r.Step != stepJoining {
		p.refuse(ctx, r.Host, reason, detail)
		return nil
	}
	switch r.Step {
	case stepReboot:
		if r.Sent.IsZero() && instance.LifecycleState == core.InstanceLifecycleStateRunning {
			return p.reset(ctx)
		}
		if !r.Sent.IsZero() && p.now.Sub(r.Sent) < BootTime {
			return nil
		}
		if present && c.reason == "" {
			return p.finish(ctx, stepReboot, "recovered", "healthy after the reboot")
		}
		reason, detail := p.budget()
		if present && reason == "" {
			reason, detail = p.refusal(ctx, c)
		}
		if reason != "" {
			p.refuse(ctx, r.Host, reason, detail)
			return nil
		}
		r.Step, r.StepAt, p.record.Replaced = stepReplace, p.now, p.now
		if err := p.save(ctx); err != nil {
			return err
		}
		p.decided(ctx, stepReplace, "started", r.Host, "still unhealthy "+BootTime.String()+" after the reboot: "+c.reason)
		return p.replace(ctx, instance)
	case stepReplace:
		return p.replace(ctx, instance)
	}
	for _, o := range p.nodes {
		created, _ := types.TimestampFromProto(o.node.Meta.CreatedAt)
		if o.node.ID != r.Node && created.After(r.StepAt) && o.reason == "" {
			return p.finish(ctx, stepJoining, "replaced", "replaced by "+o.host)
		}
	}
	if p.now.Sub(r.StepAt) < JoinWait {
		return nil
	}
	p.record.Stopped = fmt.Sprintf("the replacement for %s did not join and become ready within %s", r.Host, JoinWait)
	slog.ErrorContext(ctx, "self-heal stopped for the region: a replacement did not join; it resumes once the region is back to its size with every node healthy", "region", p.Healer.region, "host", r.Host, "within", JoinWait)
	return p.finish(ctx, stepJoining, "failed", p.record.Stopped)
}

func (p *pass) replace(ctx context.Context, instance core.Instance) error {
	r := p.record.Repair
	if c, present := p.find(r.Node); present {
		if err := swarmruntime.RemoveMember(ctx, p.client, c.host, p.guard); err != nil {
			return fmt.Errorf("drain and remove %s: %w", c.host, err)
		}
		p.decided(ctx, stepReplace, "removed", r.Host, "drained, demoted and removed from the swarm")
	}
	if instance.LifecycleState != core.InstanceLifecycleStateTerminating && instance.LifecycleState != core.InstanceLifecycleStateTerminated {
		if _, err := p.compute.TerminateInstance(ociclient.WithAuthority(ctx, p.guard), core.TerminateInstanceRequest{InstanceId: &r.Instance,
			PreserveBootVolume: common.Bool(false), PreserveDataVolumesCreatedAtLaunch: common.Bool(true)}); err != nil {
			return fmt.Errorf("terminate %s: %w", r.Instance, err)
		}
	}
	r.Step, r.StepAt = stepJoining, time.Now()
	if err := p.save(ctx); err != nil {
		return err
	}
	p.decided(ctx, stepReplace, "terminated", r.Host, r.Instance+" terminated with its data volume kept; the pool and the compute pass bring the replacement")
	return nil
}

func (p *pass) finish(ctx context.Context, step, result, outcome string) error {
	r := p.record.Repair
	r.Outcome, r.Finished = outcome, p.now
	p.record.Last, p.record.Repair = r, nil
	if err := p.save(ctx); err != nil {
		return err
	}
	p.decided(ctx, step, result, r.Host, outcome)
	return nil
}

func (p *pass) save(ctx context.Context) error {
	if err := p.guard(ctx); err != nil {
		return err
	}
	revision, err := p.store.save(ctx, p.record, p.revision)
	if err != nil {
		return err
	}
	p.revision = revision
	return nil
}

func (p *pass) refuse(ctx context.Context, host, reason, detail string) {
	p.mu.Lock()
	p.refusals[reason]++
	p.mu.Unlock()
	slog.WarnContext(ctx, "self-heal refused to repair a node", "region", p.Healer.region, "host", host, "reason", reason, "detail", detail)
}

func (p *pass) decided(ctx context.Context, step, result, host, detail string) {
	p.mu.Lock()
	p.repairs[[2]string{step, result}]++
	p.mu.Unlock()
	slog.InfoContext(ctx, "self-heal repair", "region", p.Healer.region, "host", host, "step", step, "result", result, "detail", detail)
}

func (p *pass) summary() Status {
	status := Status{Blocked: p.blocked(), Repair: p.record.Repair, Last: p.record.Last, Stopped: p.record.Stopped}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, o := range p.nodes {
		switch {
		case o.booting:
			status.Booting++
		case o.reason == "":
			status.Healthy++
		default:
			status.Unhealthy = append(status.Unhealthy, fmt.Sprintf("%s: %s since %s", o.host, o.reason, p.since[o.node.ID].UTC().Format(time.RFC3339)))
		}
	}
	return status
}
