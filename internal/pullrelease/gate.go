package pullrelease

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
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
	Releasing  bool
	Tasks      []string
}

type Baseline struct {
	Lagging     map[string]uint64   `json:"lagging,omitempty"`
	Generations map[string]int64    `json:"generations,omitempty"`
	Hosts       map[string][]string `json:"hosts,omitempty"`
}

type watch struct {
	done     time.Time
	tasks    map[string][]string
	versions map[string][2]int64
}

var measured = regexp.MustCompile(`\s*\([^()]*\)$`)

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
			found = append(found, measured.ReplaceAllString(prefix+item, ""))
		}
	}
	return found
}

func lagging(services []Service) map[string]uint64 {
	running := map[string]uint64{}
	for _, service := range services {
		if service.Running < service.Replicas {
			running[service.Name] = service.Running
		}
	}
	return running
}

func generations(services []Service) map[string]int64 {
	found := map[string]int64{}
	for _, service := range services {
		found[service.Name] = service.Generation
	}
	return found
}

func (b *Baseline) ownRelease(service Service) bool {
	if service.Releasing {
		return true
	}
	if b == nil {
		return false
	}
	before, known := b.Generations[service.Name]
	return !known || before != service.Generation
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

func (b *Baseline) worseServices(services []Service) (string, string) {
	var worse, excluded []string
	for _, service := range services {
		if service.Running >= service.Replicas {
			continue
		}
		replicas := fmt.Sprintf("%s %d/%d", service.Name, service.Running, service.Replicas)
		before, lagged := b.lagged(service.Name)
		switch {
		case b.ownRelease(service):
			excluded = append(excluded, replicas)
		case !lagged || service.Running < before:
			worse = append(worse, replicas)
		}
	}
	return listed("fewer replicas running than before the release: ", worse), listed("excluded: own release: ", excluded)
}

func listed(prefix string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	slices.Sort(items)
	return prefix + strings.Join(items, ", ")
}

func (u *Updater) baseline(ctx context.Context) (*Baseline, error) {
	hosts, err := u.Hosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("host inventory: %w", err)
	}
	services, err := u.Services(ctx)
	if err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	baseline := &Baseline{Lagging: lagging(services), Generations: generations(services), Hosts: map[string][]string{}}
	for _, host := range hosts {
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			return nil, fmt.Errorf("%s does not answer: %w", host.Name, err)
		}
		if found := conditions(reply.Health); len(found) != 0 {
			baseline.Hosts[host.ID] = found
		}
	}
	return baseline, nil
}

func (u *Updater) recordBaseline(ctx context.Context) string {
	if u.status.Baseline != nil {
		return ""
	}
	baseline, err := u.baseline(ctx)
	if err != nil {
		return "state before the release unreadable: " + err.Error()
	}
	slog.InfoContext(ctx, "recording the region's state before the release", "region", u.Region, "release", u.status.Target.Tag(), "lagging", baseline.Lagging, "generations", baseline.Generations, "hosts", baseline.Hosts)
	u.status.Baseline = baseline
	if !u.save(ctx) {
		return "pull rollout record changed"
	}
	return ""
}

func (u *Updater) servicesWorse(ctx context.Context) ([]Service, string, string) {
	services, err := u.Services(ctx)
	if err != nil {
		return nil, "services unreadable: " + err.Error(), ""
	}
	worse, excluded := u.status.Baseline.worseServices(services)
	return services, worse, excluded
}

func (w *watch) restarted(baseline *Baseline, services []Service) string {
	found := ""
	for _, service := range services {
		version := [2]int64{service.Generation, int64(service.Replicas)}
		before, seen := w.tasks[service.Name]
		steady := seen && w.versions[service.Name][0] == version[0] && w.versions[service.Name][1] <= version[1]
		_, lagged := baseline.lagged(service.Name)
		if steady && !lagged && !baseline.ownRelease(service) {
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

func (b *Baseline) lagged(name string) (uint64, bool) {
	if b == nil {
		return 0, false
	}
	running, lagged := b.Lagging[name]
	return running, lagged
}
