package machines

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// Host is a candidate host. Allocated holds everything the host runs except
// machines, which Schedule charges itself; Pool names the node pool the host
// belongs to, if any.
type Host struct {
	placement.WorkloadHost
	Pool string
	// Lost marks a registered host whose session has been gone past the
	// grace period. Its machines are replaced, but they may still run.
	Lost bool
}

// ScheduleInput is one region's view: every app, every machine record of the
// region and its status, and every registered host.
type ScheduleInput struct {
	Region   string
	Apps     []App
	Machines []Machine
	Statuses []Status
	Hosts    []Host
	// Reserved roles are still placed by a cell-spec service spec or by
	// TerraBase placement. An app of such a role is held until the role moves
	// onto apps.
	Reserved []string
}

// Schedule is the writes that converge the region, each at its record's
// Revision. Create holds new machines, placed or pending. Update holds
// changed machines; Statuses the statuses Schedule decides itself (a lost or
// deregistered host's machines); Delete the destroyed machines whose records
// can go. Pending counts each app's machines that no host fits, and Held says
// why an app was not scheduled.
type Schedule struct {
	Create   []Machine
	Update   []Machine
	Statuses []Status
	Delete   []Machine
	Pending  map[string]int
	Held     map[string]error
}

// Plan computes one region's schedule. It is pure and deterministic apart
// from new machine IDs.
//
// Every app gets Regions[Region] machines. A machine is placed on the
// schedulable host of its role (and node pool) that runs no other machine of
// the app, has its resources and ports free, holds the fewest of the app's
// machines in its failure domain and, among those, would be the fullest
// afterwards: machines spread across failure domains and pack within them. A
// new app version updates every machine in place where its host still fits
// it. Machines of a deleted or recreated app are destroyed, as are machines of
// lost or deregistered hosts, which are replaced elsewhere.
func Plan(in ScheduleInput) Schedule {
	plan := Schedule{Pending: map[string]int{}, Held: map[string]error{}}
	s := newScheduler(in)
	// Statuses by their machine's key.
	statuses := make(map[string]Status, len(in.Statuses))
	for _, status := range in.Statuses {
		statuses[machineKey(status.App, status.ID)] = status
	}
	apps := make(map[string]App, len(in.Apps))
	for _, app := range in.Apps {
		apps[app.Name] = app
	}
	byApp := map[string][]Machine{}
	for _, machine := range sortedMachines(in.Machines) {
		status := statuses[machine.key()]
		// A record goes once it is stored as destroyed and its process is
		// known to be gone: never placed, or observed destroyed.
		if machine.Desired == DesiredDestroyed && (machine.Host == "" || status.State == StateDestroyed) {
			plan.Delete = append(plan.Delete, machine)
			continue
		}
		host, registered := s.hosts[machine.Host]
		next := machine
		if app, exists := apps[machine.App]; !exists || app.ID != machine.AppID {
			next.Desired = DesiredDestroyed
		}
		switch {
		case machine.Host != "" && !registered:
			// The host is gone for good, and its machines with it.
			next.Desired = DesiredDestroyed
			if status.State != StateDestroyed {
				plan.Statuses = append(plan.Statuses, withState(status, machine, StateDestroyed))
			}
		case machine.Host != "" && host.Lost:
			// A partitioned host may come back: its machine is replaced and
			// stopped on return, never assumed stopped.
			next.Desired = DesiredDestroyed
			if status.State != StateLost && status.State != StateDestroyed {
				plan.Statuses = append(plan.Statuses, withState(status, machine, StateLost))
			}
		}
		if next.Desired != machine.Desired {
			plan.Update = append(plan.Update, next)
		}
		// A destroyed machine holds its host until it is observed gone.
		s.charge(next, 1)
		if next.Desired != DesiredDestroyed {
			byApp[next.App] = append(byApp[next.App], next)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(apps)) {
		app := apps[name]
		if slices.Contains(in.Reserved, app.Config.Role) {
			plan.Held[name] = fmt.Errorf("role %s is still placed by the cell spec or TerraBase placement", app.Config.Role)
			continue
		}
		live := byApp[name]
		want := app.Regions[in.Region]
		// Scale in: unplaced machines first, then failed ones, then those
		// in the most crowded failure domain, then by ID. A destroyed record
		// is deleted on a later pass.
		slices.SortStableFunc(live, func(a, b Machine) int {
			return cmp.Or(
				cmp.Compare(boolRank(a.Host != ""), boolRank(b.Host != "")),
				cmp.Compare(boolRank(statuses[a.key()].State != StateFailed), boolRank(statuses[b.key()].State != StateFailed)),
				-cmp.Compare(s.domains[name][a.FailureDomain], s.domains[name][b.FailureDomain]),
				cmp.Compare(a.ID, b.ID))
		})
		for len(live) > want {
			victim := live[0]
			live = live[1:]
			s.charge(victim, -1)
			victim.Desired = DesiredDestroyed
			plan.Update = appendMachine(plan.Update, victim)
		}
		for _, machine := range live {
			next := machine
			if next.Version < app.Version {
				s.charge(next, -1)
				next.Version, next.Config = app.Version, app.Config
				if next.Host != "" && !s.room(app, next.Config, s.hosts[next.Host]) {
					// ponytail: a host that no longer fits the new version
					// keeps the old one; replace such machines with a surge
					// when resizing becomes common.
					next = machine
				}
				s.charge(next, 1)
			}
			if next.Host == "" {
				if host, ok := s.choose(app, next.Config); ok {
					next.Host, next.FailureDomain = host.Node, host.FailureDomain
					s.charge(next, 1)
				} else {
					plan.Pending[name]++
				}
			}
			if !sameJSON(next, machine) {
				plan.Update = appendMachine(plan.Update, next)
			}
		}
		for range want - len(live) {
			machine := Machine{ID: NewMachineID(), App: name, AppID: app.ID, Region: in.Region,
				Version: app.Version, Config: app.Config, Desired: DesiredStarted}
			if host, ok := s.choose(app, machine.Config); ok {
				machine.Host, machine.FailureDomain = host.Node, host.FailureDomain
				s.charge(machine, 1)
			} else {
				plan.Pending[name]++
			}
			plan.Create = append(plan.Create, machine)
		}
	}
	return plan
}

type scheduler struct {
	hosts map[string]Host
	// used, ports and apps describe the machines charged to each host;
	// domains counts each app's machines per failure domain.
	used    map[string]placement.Resources
	ports   map[string]map[int]int
	apps    map[string]map[string]int
	domains map[string]map[string]int
}

func newScheduler(in ScheduleInput) *scheduler {
	s := &scheduler{hosts: map[string]Host{}, used: map[string]placement.Resources{},
		ports: map[string]map[int]int{}, apps: map[string]map[string]int{}, domains: map[string]map[string]int{}}
	for _, host := range in.Hosts {
		s.hosts[host.Node] = host
		s.ports[host.Node], s.apps[host.Node] = map[int]int{}, map[string]int{}
	}
	return s
}

// charge adds (sign 1) or removes (sign -1) a placed machine's resources,
// ports and spread counts.
func (s *scheduler) charge(machine Machine, sign int) {
	if machine.Host == "" {
		return
	}
	if _, ok := s.hosts[machine.Host]; !ok {
		return
	}
	used := s.used[machine.Host]
	used.CPU += sign * machine.Config.Resources.CPU
	used.MemoryBytes += int64(sign) * machine.Config.Resources.MemoryBytes
	used.DiskBytes += int64(sign) * machine.Config.Resources.DiskBytes
	s.used[machine.Host] = used
	for _, service := range machine.Config.Services {
		s.ports[machine.Host][service.Port] += sign
	}
	s.apps[machine.Host][machine.App] += sign
	if s.domains[machine.App] == nil {
		s.domains[machine.App] = map[string]int{}
	}
	s.domains[machine.App][machine.FailureDomain] += sign
}

// fits reports whether host takes a new machine of app with config.
func (s *scheduler) fits(app App, config MachineConfig, host Host) bool {
	return host.CurrentSession && host.Admitted && host.Healthy && !host.Cordoned && !host.Lost &&
		(app.NodePool == "" || host.Pool == app.NodePool) && s.room(app, config, host)
}

// room reports whether host has the role, resources and ports for one more
// machine of app with config and runs no other machine of app. An in-place
// update needs only room: its host already runs the machine.
func (s *scheduler) room(app App, config MachineConfig, host Host) bool {
	if !slices.Contains(host.Roles, config.Role) || s.apps[host.Node][app.Name] > 0 {
		return false
	}
	free := s.free(host)
	if free.CPU < config.Resources.CPU || free.MemoryBytes < config.Resources.MemoryBytes ||
		free.DiskBytes < config.Resources.DiskBytes {
		return false
	}
	for _, service := range config.Services {
		if s.ports[host.Node][service.Port] > 0 {
			return false
		}
	}
	return true
}

func (s *scheduler) free(host Host) placement.Resources {
	used := s.used[host.Node]
	return placement.Resources{
		CPU:         host.Capacity.CPU - host.Allocated.CPU - used.CPU,
		MemoryBytes: host.Capacity.MemoryBytes - host.Allocated.MemoryBytes - used.MemoryBytes,
		DiskBytes:   host.Capacity.DiskBytes - host.Allocated.DiskBytes - used.DiskBytes,
	}
}

// choose returns the host for a new machine of app: fewest of the app's
// machines in its failure domain, then the least room left over afterwards,
// then the node name.
func (s *scheduler) choose(app App, config MachineConfig) (Host, bool) {
	var best Host
	var bestDomain int
	var bestRoom float64
	found := false
	for _, node := range slices.Sorted(maps.Keys(s.hosts)) {
		host := s.hosts[node]
		if !s.fits(app, config, host) {
			continue
		}
		domain := s.domains[app.Name][host.FailureDomain]
		free := s.free(host)
		room := max(
			float64(free.CPU-config.Resources.CPU)/float64(host.Capacity.CPU),
			float64(free.MemoryBytes-config.Resources.MemoryBytes)/float64(host.Capacity.MemoryBytes))
		if !found || domain < bestDomain || domain == bestDomain && room < bestRoom {
			best, bestDomain, bestRoom, found = host, domain, room, true
		}
	}
	return best, found
}

func sortedMachines(machines []Machine) []Machine {
	sorted := slices.Clone(machines)
	slices.SortFunc(sorted, func(a, b Machine) int { return cmp.Or(cmp.Compare(a.App, b.App), cmp.Compare(a.ID, b.ID)) })
	return sorted
}

// appendMachine adds machine, replacing an earlier write of the same record.
func appendMachine(writes []Machine, machine Machine) []Machine {
	if index := slices.IndexFunc(writes, func(m Machine) bool { return m.key() == machine.key() }); index >= 0 {
		writes[index] = machine
		return writes
	}
	return append(writes, machine)
}

func withState(status Status, machine Machine, state State) Status {
	if status.Revision == 0 {
		status = Status{ID: machine.ID, App: machine.App}
	}
	status.State = state
	return status
}

func boolRank(value bool) int {
	if value {
		return 1
	}
	return 0
}
