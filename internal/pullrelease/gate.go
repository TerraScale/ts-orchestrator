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

type ServiceBaseline struct {
	Generation int64  `json:"generation"`
	Running    uint64 `json:"running"`
}

type Baseline struct {
	Lagging  map[string]uint64          `json:"lagging,omitempty"`
	Services map[string]ServiceBaseline `json:"services"`
	Hosts    map[string][]string        `json:"hosts,omitempty"`
}

type judgement struct {
	worse, excluded string
	released        map[string]bool
	settled         bool
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

func serviceBaselines(services []Service) map[string]ServiceBaseline {
	found := map[string]ServiceBaseline{}
	for _, service := range services {
		found[service.Name] = ServiceBaseline{Generation: service.Generation, Running: min(service.Running, service.Replicas)}
	}
	return found
}

func (b *Baseline) ownRelease(service Service) bool {
	if service.Releasing {
		return true
	}
	if b == nil || b.Services == nil {
		return false
	}
	recorded, known := b.Services[service.Name]
	return !known || recorded.Generation != service.Generation
}

func (b *Baseline) floor(service Service) uint64 {
	floor := service.Replicas
	if before, lagged := b.lagged(service.Name); lagged {
		floor = min(floor, before)
	}
	if b != nil {
		if recorded, known := b.Services[service.Name]; known {
			floor = min(floor, recorded.Running)
		}
	}
	return floor
}

func (b *Baseline) settle(service Service) {
	b.Services[service.Name] = ServiceBaseline{Generation: service.Generation, Running: min(service.Running, service.Replicas)}
	if service.Running >= service.Replicas {
		delete(b.Lagging, service.Name)
		return
	}
	if b.Lagging == nil {
		b.Lagging = map[string]uint64{}
	}
	b.Lagging[service.Name] = service.Running
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

func (b *Baseline) judge(services []Service) judgement {
	var worse, excluded []string
	found := judgement{released: map[string]bool{}}
	for _, service := range services {
		replicas := fmt.Sprintf("%s %d/%d", service.Name, service.Running, service.Replicas)
		floor := b.floor(service)
		if b.ownRelease(service) {
			found.released[service.Name] = true
			if service.Releasing || service.Running < floor {
				excluded = append(excluded, replicas)
				continue
			}
			b.settle(service)
			found.settled = true
			continue
		}
		if service.Running < floor {
			worse = append(worse, replicas)
		}
	}
	found.worse, found.excluded = listed("fewer replicas running than before the release: ", worse), listed("excluded: own release: ", excluded)
	return found
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
	baseline := &Baseline{Lagging: lagging(services), Services: serviceBaselines(services), Hosts: map[string][]string{}}
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
	slog.InfoContext(ctx, "recording the region's state before the release", "region", u.Region, "release", u.status.Target.Tag(), "lagging", baseline.Lagging, "services", baseline.Services, "hosts", baseline.Hosts)
	u.status.Baseline = baseline
	if !u.save(ctx) {
		return "pull rollout record changed"
	}
	return ""
}

func (u *Updater) judgeServices(ctx context.Context) ([]Service, judgement) {
	services, err := u.Services(ctx)
	if err != nil {
		return nil, judgement{worse: "services unreadable: " + err.Error()}
	}
	found := u.status.Baseline.judge(services)
	if found.settled {
		slog.InfoContext(ctx, "a service's own release settled healthy during the gate; the gate judges it from its new generation", "region", u.Region, "release", u.status.Target.Tag(), "services", u.status.Baseline.Services)
		u.save(ctx)
	}
	return services, found
}

func (w *watch) restarted(baseline *Baseline, services []Service, released map[string]bool) string {
	found := ""
	for _, service := range services {
		version := [2]int64{service.Generation, int64(service.Replicas)}
		before, seen := w.tasks[service.Name]
		steady := seen && w.versions[service.Name][0] == version[0] && w.versions[service.Name][1] <= version[1]
		_, lagged := baseline.lagged(service.Name)
		if steady && !lagged && !released[service.Name] {
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
