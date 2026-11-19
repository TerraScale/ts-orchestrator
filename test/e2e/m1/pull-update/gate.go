package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const gateBudget = 90 * time.Second

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
		generation, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, err
		}
		services = append(services, pullrelease.Service{Name: entry.Name(), Running: running, Replicas: replicas, Generation: generation, Tasks: fields[3:]})
	}
	return services, nil
}

func (l *lane) setService(name string, generation, running, replicas int, tasks ...string) {
	dir := filepath.Join(filepath.Dir(l.hosts["sjc-m"].dir), "services")
	must(os.MkdirAll(dir, 0o700))
	temporary := filepath.Join(dir, "."+name)
	must(os.WriteFile(temporary, []byte(fmt.Sprintf("%d %d %d %s", running, replicas, generation, strings.Join(tasks, " "))), 0o600))
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

func (l *lane) dropBaseline(ctx context.Context, region string) {
	fabric, err := nats.Connect(l.conn.ConnectedUrl(), nats.UserInfo(fabricUser, fabricSecret))
	must(err)
	defer fabric.Close()
	js, err := jetstream.New(fabric)
	must(err)
	kv, err := js.KeyValue(ctx, pullrelease.Bucket)
	must(err)
	for {
		entry, err := kv.Get(ctx, region)
		must(err)
		record := map[string]json.RawMessage{}
		must(json.Unmarshal(entry.Value(), &record))
		delete(record, "baseline")
		data, err := json.Marshal(record)
		must(err)
		if _, err = kv.Update(ctx, region, data, entry.Revision()); !errors.Is(err, jetstream.ErrKeyExists) {
			must(err)
			return
		}
	}
}

func (l *lane) formed(ctx context.Context) {
	starts := l.starts()
	booted := l.github.publish(l.revision, "114", asset, l.self, l.self, l.sigstore.Bundle(sigstore.MainIdentity, l.revision, "114", map[string][]byte{asset: l.self}))
	for _, region := range []string{"sjc", "fra", "gru"} {
		adopted := l.waitStatus(ctx, region, region+" adopts "+booted.tag+", the release its hosts booted", func(s pullrelease.Status) bool {
			require(s.Target == nil || s.Target.Tag() != booted.tag || s.Healthy.IsZero() && s.Failures == 0 && s.Phase != pullrelease.PhaseRollingBack && s.Phase != pullrelease.PhaseStalled,
				"%s gated or rolled back %s, the release every host booted:\n%s", region, booted.tag, s)
			return passed(booted)(s)
		})
		require(adopted.Passed.Equal(adopted.Done) && len(adopted.Hosts) == 3 && !slices.ContainsFunc(adopted.Hosts, func(h pullrelease.HostProgress) bool {
			return h.State != pullrelease.HostDone || !h.Installed.IsZero() || !h.Ready.IsZero()
		}), "%s must record %s complete with every host done and none installed or gated:\n%s\n%s", region, booted.tag, adopted, strings.Join(adopted.Timeline(), "\n"))
		fmt.Printf("%s records %s, the release every host booted, complete with no rollout\n%s\n", region, booted.tag, strings.Join(adopted.Timeline(), "\n"))
	}
	require(maps.Equal(l.starts(), starts), "adopting the booted release restarted a host: %v, before %v", l.starts(), starts)
}

func (l *lane) gate(ctx context.Context) {
	l.formed(ctx)
	l.setService("ts-auth", 1, 1, 1, "auth-1")
	l.setService("ts-dashboard", 1, 0, 1)
	for _, id := range l.region("sjc") {
		must(os.WriteFile(filepath.Join(l.hosts[id].dir, "backend-down"), nil, 0o600))
	}

	for _, id := range []string{"fra-m", "gru-m"} {
		must(os.WriteFile(filepath.Join(l.hosts[id].dir, "mesh-behind"), nil, 0o600))
	}
	degraded := l.publishGood("115", "c115")
	published := time.Now()
	l.waitStatus(ctx, "sjc", "sjc records its state before "+degraded.tag, func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == degraded.tag && s.Baseline != nil
	})
	l.setService("ts-auth", 2, 0, 1)
	regions := map[string]pullrelease.Status{}
	regions["sjc"] = l.waitStatus(ctx, "sjc", "sjc passes the regional gate of "+degraded.tag+" while ts-auth's own release replaces its task", passed(degraded))
	l.setService("ts-auth", 2, 1, 1, "auth-1")
	require(strings.Contains(regions["sjc"].Reason, "excluded: own release: ts-auth 0/1"),
		"an app release that dips its own replicas during the gate must be excluded and named, not fail the gate:\n%s", regions["sjc"])
	fmt.Printf("ts-auth's own release took it to 0/1 during sjc's gate of %s -> sjc passes: %s\n", degraded.tag, regions["sjc"].Reason)
	waiting := l.restartLease(ctx, func(hold map[string]string) bool {
		return (hold["region"] == "fra" || hold["region"] == "gru") && hold["next"] != "" && hold["next"] != hold["region"]
	})
	holder, contender := waiting["region"], waiting["next"]
	behind := l.ask(ctx, holder+"-m", releasepush.PullRequest{Op: releasepush.PullStatus})
	up := l.ask(ctx, contender+"-m", releasepush.PullRequest{Op: releasepush.PullStatus})
	require(behind.SHA256 == degraded.digest && behind.Mesh != "ok" && up.SHA256 != degraded.digest && up.Error == "",
		"while %s-m holds the fleet restart lease and catches up, %s-m must wait up on its previous binary:\nholder %+v\ncontender %+v", holder, contender, behind, up)
	fmt.Printf("%s-m restarted with the fleet restart lease and is catching up (%s); %s-m waits for it, up on its previous binary\n", holder, behind.Mesh, contender)
	for _, id := range []string{"fra-m", "gru-m"} {
		must(os.Remove(filepath.Join(l.hosts[id].dir, "mesh-behind")))
	}
	caughtUp := time.Now()
	for _, region := range []string{"fra", "gru"} {
		regions[region] = l.waitStatus(ctx, region, region+" passes the regional gate of "+degraded.tag, passed(degraded))
	}
	for _, row := range regions[contender].Hosts {
		require(row.ID != contender+"-m" || !row.Installed.Before(caughtUp), "%s-m installed at %s, before %s-m caught up at %s", contender, row.Installed, holder, caughtUp)
	}
	elapsed := time.Since(published)
	sjc, fra, gru := regions["sjc"], regions["fra"], regions["gru"]
	require(sjc.Baseline != nil && maps.Equal(sjc.Baseline.Lagging, map[string]uint64{"ts-dashboard": 0}) && len(sjc.Baseline.Hosts) == 3,
		"sjc must record ts-dashboard down and its backend-down hosts as the state before the release:\n%+v", sjc.Baseline)
	together(sjc, fra, gru)
	for _, region := range regions {
		require(region.Passed.Sub(region.Done) >= healthyFor && !region.Discovered.IsZero() && !region.Discovered.After(region.Done), "%s gate or discovery timestamps are wrong:\n%s", region.Region, strings.Join(region.Timeline(), "\n"))
		for _, host := range region.Hosts {
			require(!host.Installed.IsZero() && !host.Ready.Before(host.Installed) && !region.Done.Before(host.Ready), "%s has no installed and ready time:\n%s", host.Host, strings.Join(region.Timeline(), "\n"))
		}
	}
	require(elapsed < gateBudget, "a healthy release took %s to pass every region, over the %s budget:\n%s", elapsed, gateBudget, strings.Join(slices.Concat(sjc.Timeline(), fra.Timeline(), gru.Timeline()), "\n"))
	fmt.Printf("ts-dashboard down and every sjc host's edge degraded before %s -> it still installs and passes sjc, then fra and gru together, in %s\n%s\n",
		degraded.tag, elapsed.Round(time.Second), strings.Join(slices.Concat(sjc.Timeline(), fra.Timeline(), gru.Timeline()), "\n"))

	resumed := l.publishGood("116", "c116")
	for _, id := range []string{"gru-m", "gru-n"} {
		l.hosts[id].holdRestart()
		l.hosts[id].kill()
	}
	l.waitStatus(ctx, "sjc", "sjc's owner installs "+resumed.tag+" on itself, after the other hosts", ownerInstalling(resumed))
	l.dropBaseline(ctx, "sjc")
	inherited := l.waitStatus(ctx, "sjc", "sjc passes "+resumed.tag+" from a record saved without its state before the release", settled(resumed))
	require(!inherited.Passed.IsZero() && inherited.Baseline != nil && maps.Equal(inherited.Baseline.Lagging, map[string]uint64{"ts-dashboard": 0}),
		"a record an older build saved without a baseline must take the region as it is now and pass with ts-dashboard still down:\n%s\n%+v", inherited, inherited.Baseline)
	fmt.Printf("record of %s saved without its baseline, as an older build saves it -> the owner records the region as it is and passes with ts-dashboard down\n%s\n", resumed.tag, inherited)
	l.waitStatus(ctx, "fra", "fra samples the regional gate of "+resumed.tag, gating(resumed))
	l.hosts["fra-w"].kill()
	fraResumed := l.waitStatus(ctx, "fra", "fra fails the gate of "+resumed.tag+" on fra-w's restart", settled(resumed))
	require(fraResumed.Passed.IsZero() && strings.Contains(fraResumed.Reason, "fra-w orchestrator restarted"), "a later region whose host restarts during its gate must fail it:\n%s", fraResumed)
	fraResumed = l.waitStatus(ctx, "fra", "fra confirms the rollback of "+resumed.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRolledBack && s.Target != nil && s.Target.Tag() == resumed.tag && slices.Contains(s.Bad, resumed.tag)
	})
	for _, id := range []string{"gru-m", "gru-n"} {
		l.hosts[id].releaseRestart()
	}
	gruResumed := l.waitStatus(ctx, "gru", "gru, whose admission was pending while fra failed, holds "+resumed.tag, func(s pullrelease.Status) bool {
		require(s.Target == nil || s.Target.Tag() != resumed.tag, "gru took %s after fra failed its gate:\n%s", resumed.tag, s)
		return strings.Contains(s.Reason, "fra: failed the gate of "+resumed.tag)
	})
	sjcResumed := l.waitStatus(ctx, "sjc", "the canary keeps "+resumed.tag+" after fra rolled it back", func(s pullrelease.Status) bool { return s.Updated.After(fraResumed.Updated) })
	require(passed(resumed)(sjcResumed) && sjcResumed.Passed.Equal(inherited.Passed) && !slices.Contains(sjcResumed.Bad, resumed.tag),
		"a failed gate in fra must roll back fra only and leave the canary's record as it passed:\nsjc %s", sjcResumed)
	fmt.Printf("fra-w restarted during the gate of %s -> fra rolled back alone; the canary keeps it; gru, whose managers were down until then, holds it: %s\n%s\n", resumed.tag, gruResumed.Reason, strings.Join(slices.Concat(sjcResumed.Timeline(), fraResumed.Timeline()), "\n"))

	second := l.publishGood("117", "c117")
	l.waitStatus(ctx, "sjc", "sjc samples the regional gate of "+second.tag, gating(second))
	for _, id := range l.region("sjc") {
		must(os.WriteFile(filepath.Join(l.hosts[id].dir, "refuse-stop"), nil, 0o600))
	}
	l.setService("ts-auth", 2, 1, 2, "auth-1")
	down := time.Now()
	failed := l.waitStatus(ctx, "sjc", "sjc fails the gate of "+second.tag+" with ts-auth down", settled(second))
	require(failed.Passed.IsZero() && strings.Contains(failed.Reason, "regional bake failed in ") && strings.Contains(failed.Reason, "ts-auth") && !failed.Since.Before(down.Add(rollout.BakeFailureDuration)),
		"a release that takes a second service down must fail the gate after 15 seconds of failed samples:\n%s", failed)
	l.setService("ts-auth", 2, 1, 1, "auth-1")
	for _, region := range []string{"fra", "gru"} {
		pending := l.waitStatus(ctx, region, region+" holds "+second.tag+" while the canary's rollback is pending", func(s pullrelease.Status) bool {
			require(s.Target == nil || s.Target.Tag() != second.tag, "%s took %s while the canary rolls it back:\n%s", region, second.tag, s)
			return strings.Contains(s.Reason, "sjc: failed the gate of "+second.tag)
		})
		fmt.Printf("%s holds %s while the canary's restore is refused: %s\n", region, pending.Target.Tag(), pending.Reason)
	}
	for _, id := range l.region("sjc") {
		must(os.Remove(filepath.Join(l.hosts[id].dir, "refuse-stop")))
	}
	rolled := l.rolledBack(ctx, second)
	for _, region := range []string{"fra", "gru"} {
		blocked := l.waitStatus(ctx, region, region+" holds "+second.tag+" behind the canary", func(s pullrelease.Status) bool {
			require(s.Target == nil || s.Target.Tag() != second.tag, "%s took %s, which the canary rolled back:\n%s", region, second.tag, s)
			return s.Updated.After(rolled.Updated) && strings.Contains(s.Reason, "sjc: failed the gate of "+second.tag)
		})
		fmt.Printf("%s holds %s: %s\n", region, blocked.Target.Tag(), blocked.Reason)
	}
	fmt.Printf("ts-auth's second replica never ready during the gate of %s -> rolled back and marked bad in the canary; fra and gru hold the previous release\n%s\n", second.tag, rolled)

	restart := l.publishGood("118", "c118")
	l.waitStatus(ctx, "sjc", "sjc samples the regional gate of "+restart.tag, gating(restart))
	l.setService("ts-auth", 2, 1, 1, "auth-2")
	restarted := l.waitStatus(ctx, "sjc", "sjc fails the gate of "+restart.tag+" on a restarted task", settled(restart))
	require(restarted.Passed.IsZero() && strings.Contains(restarted.Reason, "ts-auth task auth-1 stopped during the gate"),
		"a task that restarts during the gate must fail it at once:\n%s", restarted)
	l.rolledBack(ctx, restart)
	fmt.Printf("ts-auth task replaced during the gate of %s -> rolled back at once\n%s\n", restart.tag, restarted)

}

func started(s pullrelease.Status) time.Time {
	var first time.Time
	for _, host := range s.Hosts {
		if !host.Installed.IsZero() && (first.IsZero() || host.Installed.Before(first)) {
			first = host.Installed
		}
	}
	return first
}

func together(canary, fra, gru pullrelease.Status) {
	fraStart, gruStart := started(fra), started(gru)
	timelines := strings.Join(slices.Concat(canary.Timeline(), fra.Timeline(), gru.Timeline()), "\n")
	require(!fraStart.IsZero() && !gruStart.IsZero() && !fraStart.Before(canary.Passed) && !gruStart.Before(canary.Passed),
		"fra and gru must start only after the canary passed its gate:\n%s", timelines)
	fraEnd, gruEnd := cmp.Or(fra.Passed, fra.Updated), cmp.Or(gru.Passed, gru.Updated)
	require(fraStart.Before(gruEnd) && gruStart.Before(fraEnd), "fra and gru must roll out at the same time, not one after the other:\n%s", timelines)
}

func (l *lane) restartLease(ctx context.Context, done func(map[string]string) bool) map[string]string {
	fabric, err := nats.Connect(l.conn.ConnectedUrl(), nats.UserInfo(fabricUser, fabricSecret))
	must(err)
	defer fabric.Close()
	js, err := jetstream.New(fabric)
	must(err)
	kv, err := js.KeyValue(ctx, pullrelease.Bucket)
	must(err)
	watcher, err := kv.Watch(ctx, "restart")
	must(err)
	defer watcher.Stop()
	for {
		select {
		case entry := <-watcher.Updates():
			if entry == nil || entry.Operation() != jetstream.KeyValuePut {
				continue
			}
			hold := map[string]string{}
			var raw map[string]any
			must(json.Unmarshal(entry.Value(), &raw))
			for key, value := range raw {
				hold[key] = fmt.Sprint(value)
			}
			if done(hold) {
				return hold
			}
		case <-ctx.Done():
			panic("timed out waiting for the fleet restart lease to show a holder and a waiting region")
		}
	}
}
