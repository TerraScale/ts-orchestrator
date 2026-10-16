package machines

import (
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

const gib = int64(1) << 30

func testHost(node, domain string, cpu int, roles ...string) Host {
	if len(roles) == 0 {
		roles = []string{"ts-auth"}
	}
	return Host{WorkloadHost: placement.WorkloadHost{Cell: "gru", Node: node, FailureDomain: domain, Roles: roles,
		Capacity:       placement.Resources{CPU: cpu, MemoryBytes: int64(cpu) * 4 * gib, DiskBytes: 100 * gib},
		CurrentSession: true, Admitted: true, Healthy: true}}
}

func scheduledApp(name string, count int) App {
	app := testApp(name)
	app.Regions = map[string]int{"gru": count}
	app.Config.Resources = placement.Resources{CPU: 1, MemoryBytes: gib, DiskBytes: gib}
	return app
}

// converge applies a schedule as the store would and returns the next input.
func converge(t *testing.T, in ScheduleInput, plan Schedule) ScheduleInput {
	t.Helper()
	next := in
	next.Machines = nil
	updated := map[string]Machine{}
	for _, machine := range plan.Update {
		updated[machine.key()] = machine
	}
	for _, machine := range in.Machines {
		if slices.ContainsFunc(plan.Delete, func(m Machine) bool { return m.key() == machine.key() }) {
			continue
		}
		if change, ok := updated[machine.key()]; ok {
			machine = change
		}
		next.Machines = append(next.Machines, machine)
	}
	next.Machines = append(next.Machines, plan.Create...)
	next.Statuses = slices.Clone(in.Statuses)
	for _, status := range plan.Statuses {
		if index := slices.IndexFunc(next.Statuses, func(s Status) bool { return s.key() == status.key() }); index >= 0 {
			next.Statuses[index] = status
		} else {
			next.Statuses = append(next.Statuses, status)
		}
	}
	for _, machine := range next.Machines {
		if err := machine.Validate(); err != nil {
			t.Fatalf("scheduled an invalid machine: %v", err)
		}
	}
	return next
}

func placedOn(machines []Machine, app string) []string {
	var hosts []string
	for _, machine := range machines {
		if machine.App == app && machine.Desired != DesiredDestroyed {
			hosts = append(hosts, machine.Host)
		}
	}
	slices.Sort(hosts)
	return hosts
}

func noWrites(plan Schedule) bool {
	return len(plan.Create)+len(plan.Update)+len(plan.Statuses)+len(plan.Delete) == 0
}

func TestPlanSpreadsAcrossDomainsAndPacksWithinThem(t *testing.T) {
	busy := testHost("h1", "fd-1", 4)
	busy.Allocated = placement.Resources{CPU: 2, MemoryBytes: 8 * gib, DiskBytes: 10 * gib}
	in := ScheduleInput{Region: "gru", Apps: []App{scheduledApp("ts-auth", 3)},
		Hosts: []Host{busy, testHost("h2", "fd-1", 4), testHost("h3", "fd-2", 4), testHost("h4", "fd-3", 4)}}
	plan := Plan(in)
	if len(plan.Create) != 3 || len(plan.Pending) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	// One machine per failure domain, and the fuller fd-1 host.
	if got := placedOn(plan.Create, "ts-auth"); !slices.Equal(got, []string{"h1", "h3", "h4"}) {
		t.Fatalf("placed on %v", got)
	}
	in = converge(t, in, plan)
	if again := Plan(in); !noWrites(again) {
		t.Fatalf("converged region replanned: %+v", again)
	}

	// A second app packs onto the hosts that already hold machines.
	in.Apps = append(in.Apps, scheduledApp("worker", 1))
	in.Apps[1].Config.Role = "ts-auth"
	in.Apps[1].Config.Services = []Service{{Name: "http", Port: 7000}}
	plan = Plan(in)
	if got := placedOn(plan.Create, "worker"); !slices.Equal(got, []string{"h1"}) {
		t.Fatalf("worker placed on %v", got)
	}
}

func TestPlanKeepsOneMachinePerHostAndReportsWhatDoesNotFit(t *testing.T) {
	in := ScheduleInput{Region: "gru", Apps: []App{scheduledApp("ts-auth", 3)},
		Hosts: []Host{testHost("h1", "fd-1", 8), testHost("h2", "fd-1", 8)}}
	plan := Plan(in)
	if got := placedOn(plan.Create, "ts-auth"); len(plan.Create) != 3 || !slices.Equal(got, []string{"", "h1", "h2"}) ||
		plan.Pending["ts-auth"] != 1 {
		t.Fatalf("placed on %v, pending %v", got, plan.Pending)
	}
	// The pending machine is placed once a host joins.
	in = converge(t, in, plan)
	in.Hosts = append(in.Hosts, testHost("h3", "fd-2", 8))
	plan = Plan(in)
	if len(plan.Update) != 1 || plan.Update[0].Host != "h3" || plan.Update[0].FailureDomain != "fd-2" ||
		len(plan.Create) != 0 || plan.Pending["ts-auth"] != 0 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanHonoursRolesPoolsPortsAndCapacity(t *testing.T) {
	app := scheduledApp("ts-auth", 1)
	pooled := scheduledApp("pooled", 1)
	pooled.NodePool = "general"
	pooled.Config.Services = nil
	big := scheduledApp("big", 1)
	big.Config.Services = nil
	big.Config.Resources.CPU = 64
	clash := scheduledApp("clash", 2) // same service ports as ts-auth
	poolHost := testHost("pool-0", "fd-2", 2)
	poolHost.Pool = "general"
	cordoned := testHost("cordoned", "fd-3", 8)
	cordoned.Cordoned = true
	in := ScheduleInput{Region: "gru", Apps: []App{app, pooled, big, clash},
		Hosts: []Host{testHost("other-role", "fd-1", 8, "terrabase"), testHost("h1", "fd-1", 8), poolHost, cordoned}}
	plan := Plan(in)
	if got := placedOn(plan.Create, "pooled"); !slices.Equal(got, []string{"pool-0"}) {
		t.Fatalf("pooled app on %v", got)
	}
	if plan.Pending["big"] != 1 {
		t.Fatalf("an app too large for every host is not pending: %v", plan.Pending)
	}
	// ts-auth (sorted after clash) and clash share ports: one per host.
	auth, clashes := placedOn(plan.Create, "ts-auth"), placedOn(plan.Create, "clash")
	if slices.Contains(auth, "other-role") || slices.Contains(clashes, "other-role") ||
		slices.Contains(clashes, "cordoned") || len(auth) != 1 {
		t.Fatalf("ts-auth on %v, clash on %v", auth, clashes)
	}
	for _, host := range auth {
		if host != "" && slices.Contains(clashes, host) {
			t.Fatalf("port clash on %s", host)
		}
	}
}

func TestPlanScalesInUnplacedAndFailedMachinesFirst(t *testing.T) {
	app := scheduledApp("ts-auth", 4)
	in := ScheduleInput{Region: "gru", Apps: []App{app},
		Hosts: []Host{testHost("h1", "fd-1", 8), testHost("h2", "fd-2", 8), testHost("h3", "fd-3", 8)}}
	in = converge(t, in, Plan(in))
	destroyed := func(plan Schedule) []Machine {
		return slices.DeleteFunc(slices.Clone(plan.Update), func(m Machine) bool { return m.Desired != DesiredDestroyed })
	}

	// One of four machines found no host: it goes first.
	in.Apps[0].Regions["gru"] = 3
	plan := Plan(in)
	if victims := destroyed(plan); len(victims) != 1 || victims[0].Host != "" || len(plan.Create) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	in = converge(t, in, plan)
	in = converge(t, in, Plan(in)) // Deletes the destroyed record.

	// Then a failed machine, whichever its domain.
	failed := in.Machines[1]
	in.Statuses = []Status{{ID: failed.ID, App: app.Name, State: StateFailed}}
	in.Apps[0].Regions["gru"] = 2
	plan = Plan(in)
	if victims := destroyed(plan); len(victims) != 1 || victims[0].ID != failed.ID || len(plan.Create) != 0 {
		t.Fatalf("plan = %+v", plan)
	}

	// Region pinning: an app moved to another region leaves this one.
	in = converge(t, in, plan)
	in.Apps[0].Regions = map[string]int{"fra": 2}
	plan = Plan(in)
	if victims := destroyed(plan); len(victims) != 2 || len(plan.Create) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanUpdatesMachinesInPlaceWhereTheyFit(t *testing.T) {
	app := scheduledApp("ts-auth", 2)
	small := testHost("small", "fd-1", 1)
	in := ScheduleInput{Region: "gru", Apps: []App{app}, Hosts: []Host{small, testHost("h2", "fd-2", 8)}}
	in = converge(t, in, Plan(in))
	before := placedOn(in.Machines, "ts-auth")

	in.Apps[0].Version = 2
	in.Apps[0].Config.Digest = strings.Repeat("b", 64)
	in.Apps[0].Config.Resources.CPU = 2 // No longer fits the one-core host.
	plan := Plan(in)
	if len(plan.Create) != 0 || len(plan.Update) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	updated := plan.Update[0]
	if updated.Host != "h2" || updated.Version != 2 || updated.Config.Digest != in.Apps[0].Config.Digest {
		t.Fatalf("updated = %+v", updated)
	}
	in = converge(t, in, plan)
	if after := placedOn(in.Machines, "ts-auth"); !slices.Equal(before, after) {
		t.Fatalf("an update moved machines: %v -> %v", before, after)
	}
	if again := Plan(in); !noWrites(again) {
		t.Fatalf("replanned: %+v", again)
	}
}

func TestPlanDestroysOrphansAndDeletesDestroyedRecords(t *testing.T) {
	app := scheduledApp("ts-auth", 1)
	in := ScheduleInput{Region: "gru", Apps: []App{app}, Hosts: []Host{testHost("h1", "fd-1", 8), testHost("h2", "fd-2", 8)}}
	in = converge(t, in, Plan(in))
	running := in.Machines[0]

	// The app is deleted and recreated under the same name.
	recreated := scheduledApp("ts-auth", 1)
	in.Apps = []App{recreated}
	plan := Plan(in)
	if len(plan.Update) != 1 || plan.Update[0].ID != running.ID || plan.Update[0].Desired != DesiredDestroyed {
		t.Fatalf("orphan not destroyed: %+v", plan)
	}
	// The replacement avoids the host the orphan still holds.
	if len(plan.Create) != 1 || plan.Create[0].Host != "h2" || plan.Create[0].AppID != recreated.ID {
		t.Fatalf("replacement = %+v", plan.Create)
	}
	in = converge(t, in, plan)
	if again := Plan(in); len(again.Delete) != 0 {
		t.Fatalf("deleted before the host stopped it: %+v", again.Delete)
	}
	in.Statuses = append(in.Statuses, Status{ID: running.ID, App: running.App, State: StateDestroyed})
	if again := Plan(in); len(again.Delete) != 1 || again.Delete[0].ID != running.ID {
		t.Fatalf("observed destroyed but kept: %+v", again)
	}
}

func TestPlanReplacesMachinesOfLostAndDeregisteredHosts(t *testing.T) {
	app := scheduledApp("ts-auth", 2)
	in := ScheduleInput{Region: "gru", Apps: []App{app},
		Hosts: []Host{testHost("h1", "fd-1", 8), testHost("h2", "fd-2", 8), testHost("h3", "fd-3", 8)}}
	in = converge(t, in, Plan(in))
	if got := placedOn(in.Machines, "ts-auth"); !slices.Equal(got, []string{"h1", "h2"}) {
		t.Fatalf("placed on %v", got)
	}

	// h1 is partitioned past the grace period: its machine is replaced but
	// not deleted, since it may still run.
	in.Hosts[0].Lost = true
	plan := Plan(in)
	if len(plan.Statuses) != 1 || plan.Statuses[0].State != StateLost || len(plan.Delete) != 0 {
		t.Fatalf("lost host plan = %+v", plan)
	}
	if len(plan.Create) != 1 || plan.Create[0].Host != "h3" {
		t.Fatalf("replacement = %+v", plan.Create)
	}
	in = converge(t, in, plan)
	if again := Plan(in); !noWrites(again) {
		t.Fatalf("replanned while partitioned: %+v", again)
	}

	// h2 is deregistered: its machine is gone with it.
	in.Hosts = slices.DeleteFunc(slices.Clone(in.Hosts), func(h Host) bool { return h.Node == "h2" })
	in.Hosts[0].Lost = false
	plan = Plan(in)
	if len(plan.Statuses) != 1 || plan.Statuses[0].State != StateDestroyed || len(plan.Create) != 1 {
		t.Fatalf("deregistered host plan = %+v", plan)
	}
	in = converge(t, in, plan)
	plan = Plan(in)
	if len(plan.Delete) != 1 || len(plan.Create) != 0 {
		t.Fatalf("follow-up plan = %+v", plan)
	}
}

func TestPlanHoldsAppsOfReservedRoles(t *testing.T) {
	in := ScheduleInput{Region: "gru", Apps: []App{scheduledApp("ts-auth", 2)}, Hosts: []Host{testHost("h1", "fd-1", 8)},
		Reserved: []string{"ts-auth"}}
	plan := Plan(in)
	if !noWrites(plan) || plan.Held["ts-auth"] == nil {
		t.Fatalf("plan = %+v", plan)
	}
}
