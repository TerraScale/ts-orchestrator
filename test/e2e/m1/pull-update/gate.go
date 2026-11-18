package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

const gateBudget = 75 * time.Second

func readServices(dir string) ([]pullrelease.Service, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	services := []pullrelease.Service{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(data))
		running, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, err
		}
		replicas, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, err
		}
		services = append(services, pullrelease.Service{Name: entry.Name(), Running: running, Replicas: replicas, Generation: 1, Tasks: fields[2:]})
	}
	return services, nil
}

func (l *lane) setService(name string, running, replicas int, tasks ...string) {
	dir := filepath.Join(filepath.Dir(l.hosts["sjc-m"].dir), "services")
	must(os.MkdirAll(dir, 0o700))
	temporary := filepath.Join(dir, "."+name)
	must(os.WriteFile(temporary, []byte(fmt.Sprintf("%d %d %s", running, replicas, strings.Join(tasks, " "))), 0o600))
	must(os.Rename(temporary, filepath.Join(dir, name)))
}

func passed(release published) func(pullrelease.Status) bool {
	return func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == release.tag && s.Phase == pullrelease.PhaseComplete && !s.Passed.IsZero()
	}
}

func settled(release published) func(pullrelease.Status) bool {
	return func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == release.tag && (!s.Passed.IsZero() || s.Phase == pullrelease.PhaseRollingBack || s.Phase == pullrelease.PhaseRolledBack)
	}
}

func gating(release published) func(pullrelease.Status) bool {
	return func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == release.tag && s.Phase == pullrelease.PhaseComplete && !s.Healthy.IsZero() && s.Passed.IsZero()
	}
}

func (l *lane) rolledBack(ctx context.Context, release published) pullrelease.Status {
	return l.waitStatus(ctx, "sjc", "sjc confirms the rollback of "+release.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRolledBack && s.Target != nil && s.Target.Tag() == release.tag && slices.Contains(s.Bad, release.tag)
	})
}

func (l *lane) gate(ctx context.Context) {
	l.setService("ts-auth", 1, 1, "auth-1")
	l.setService("ts-dashboard", 0, 1)
	for _, id := range l.region("sjc") {
		must(os.WriteFile(filepath.Join(l.hosts[id].dir, "backend-down"), nil, 0o600))
	}

	degraded := l.publishGood("115", "c115")
	published := time.Now()
	regions := map[string]pullrelease.Status{}
	for _, region := range []string{"sjc", "fra", "gru"} {
		regions[region] = l.waitStatus(ctx, region, region+" passes the regional gate of "+degraded.tag, passed(degraded))
	}
	elapsed := time.Since(published)
	sjc, fra, gru := regions["sjc"], regions["fra"], regions["gru"]
	require(sjc.Baseline != nil && slices.Equal(sjc.Baseline.Lagging, []string{"ts-dashboard"}) && len(sjc.Baseline.Hosts) == 3,
		"sjc must record ts-dashboard down and its backend-down hosts as the state before the release:\n%+v", sjc.Baseline)
	require(!fra.Done.Before(sjc.Passed) && !gru.Done.Before(fra.Passed), "a region started before its predecessor passed its gate")
	for _, region := range regions {
		require(region.Passed.Sub(region.Done) >= healthyFor && !region.Discovered.IsZero() && !region.Discovered.After(region.Done), "%s gate or discovery timestamps are wrong:\n%s", region.Region, strings.Join(region.Timeline(), "\n"))
		for _, host := range region.Hosts {
			require(!host.Installed.IsZero() && !host.Ready.Before(host.Installed) && !region.Done.Before(host.Ready), "%s has no installed and ready time:\n%s", host.Host, strings.Join(region.Timeline(), "\n"))
		}
	}
	require(elapsed < gateBudget, "a healthy release took %s to pass every region, over the %s budget:\n%s", elapsed, gateBudget, strings.Join(slices.Concat(sjc.Timeline(), fra.Timeline(), gru.Timeline()), "\n"))
	fmt.Printf("ts-dashboard down and every sjc host's edge degraded before %s -> it still installs and passes sjc, fra and gru in order in %s\n%s\n",
		degraded.tag, elapsed.Round(time.Second), strings.Join(slices.Concat(sjc.Timeline(), fra.Timeline(), gru.Timeline()), "\n"))

	second := l.publishGood("116", "c116")
	l.waitStatus(ctx, "sjc", "sjc samples the regional gate of "+second.tag, gating(second))
	l.setService("ts-auth", 1, 2, "auth-1")
	down := time.Now()
	failed := l.waitStatus(ctx, "sjc", "sjc fails the gate of "+second.tag+" with ts-auth down", settled(second))
	require(failed.Passed.IsZero() && strings.Contains(failed.Reason, "regional bake failed in ") && strings.Contains(failed.Reason, "ts-auth") && !failed.Since.Before(down.Add(rollout.BakeFailureDuration)),
		"a release that takes a second service down must fail the gate after 15 seconds of failed samples:\n%s", failed)
	l.setService("ts-auth", 1, 1, "auth-1")
	rolled := l.rolledBack(ctx, second)
	blocked := l.waitStatus(ctx, "fra", "fra holds "+second.tag+" behind sjc", func(s pullrelease.Status) bool {
		return strings.Contains(s.Reason, "sjc: waiting for the same release to pass its regional gate")
	})
	require(blocked.Target != nil && blocked.Target.Tag() == degraded.tag, "fra left %s for the release sjc rolled back:\n%s", degraded.tag, blocked)
	fmt.Printf("ts-auth's second replica never ready during the gate of %s -> rolled back and marked bad in sjc; fra stays on %s\n%s\n", second.tag, degraded.tag, rolled)

	restart := l.publishGood("117", "c117")
	l.waitStatus(ctx, "sjc", "sjc samples the regional gate of "+restart.tag, gating(restart))
	l.setService("ts-auth", 1, 1, "auth-2")
	restarted := l.waitStatus(ctx, "sjc", "sjc fails the gate of "+restart.tag+" on a restarted task", settled(restart))
	require(restarted.Passed.IsZero() && strings.Contains(restarted.Reason, "ts-auth task auth-1 stopped during the gate"),
		"a task that restarts during the gate must fail it at once:\n%s", restarted)
	l.rolledBack(ctx, restart)
	fmt.Printf("ts-auth task replaced during the gate of %s -> rolled back at once\n%s\n", restart.tag, restarted)
}
