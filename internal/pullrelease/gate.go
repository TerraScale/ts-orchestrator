package pullrelease

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

type Service struct {
	Name       string
	Running    uint64
	Replicas   uint64
	Generation int64
	Tasks      []string
}

type Baseline struct {
	Lagging []string            `json:"lagging,omitempty"`
	Hosts   map[string][]string `json:"hosts,omitempty"`
}

type watch struct {
	done     time.Time
	tasks    map[string][]string
	versions map[string][2]int64
}

func conditions(health string) []string {
	if health == "ok" {
		return nil
	}
	var found []string
	for line := range strings.Lines(health) {
		prefix, items, listed := strings.Cut(strings.TrimSpace(line), ": ")
		if listed {
			prefix += ": "
		} else {
			prefix, items = "", prefix
		}
		for item := range strings.SplitSeq(items, ", ") {
			found = append(found, prefix+item)
		}
	}
	return found
}

func lagging(services []Service) []string {
	var names []string
	for _, service := range services {
		if service.Running < service.Replicas {
			names = append(names, service.Name)
		}
	}
	slices.Sort(names)
	return names
}

func (b *Baseline) worseHost(id, health string) string {
	var before []string
	if b != nil {
		before = b.Hosts[id]
	}
	for _, condition := range conditions(health) {
		if !slices.Contains(before, condition) {
			return condition
		}
	}
	return ""
}

func (b *Baseline) worseServices(services []Service) string {
	var worse []string
	for _, name := range lagging(services) {
		if b == nil || !slices.Contains(b.Lagging, name) {
			worse = append(worse, name)
		}
	}
	if len(worse) == 0 {
		return ""
	}
	return "below desired replicas, not before the release: " + strings.Join(worse, ", ")
}

func (u *Updater) baseline(ctx context.Context) *Baseline {
	hosts, err := u.Hosts(ctx)
	if err != nil {
		return nil
	}
	services, err := u.Services(ctx)
	if err != nil {
		return nil
	}
	baseline := &Baseline{Lagging: lagging(services), Hosts: map[string][]string{}}
	for _, host := range hosts {
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if found := conditions(reply.Health); err == nil && len(found) != 0 {
			baseline.Hosts[host.ID] = found
		}
	}
	return baseline
}

func (u *Updater) servicesWorse(ctx context.Context) ([]Service, string) {
	services, err := u.Services(ctx)
	if err != nil {
		return nil, "services unreadable: " + err.Error()
	}
	return services, u.status.Baseline.worseServices(services)
}

func (w *watch) restarted(baseline *Baseline, services []Service) string {
	found := ""
	for _, service := range services {
		version := [2]int64{service.Generation, int64(service.Replicas)}
		before, seen := w.tasks[service.Name]
		steady := seen && w.versions[service.Name][0] == version[0] && w.versions[service.Name][1] <= version[1]
		if steady && (baseline == nil || !slices.Contains(baseline.Lagging, service.Name)) {
			for _, task := range before {
				if !slices.Contains(service.Tasks, task) {
					found = service.Name + " task " + task + " stopped during the gate"
				}
			}
		}
		w.tasks[service.Name], w.versions[service.Name] = service.Tasks, version
	}
	return found
}
