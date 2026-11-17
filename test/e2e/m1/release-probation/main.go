package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

func step(format string, args ...any) {
	fmt.Printf("ok "+format+"\n", args...)
}

func buildRevision(path string) string {
	info, err := buildinfo.ReadFile(path)
	must(err)
	revision, dirty := "", ""
	for _, setting := range info.Settings {
		switch {
		case setting.Key == "vcs.revision":
			revision = setting.Value
		case setting.Key == "vcs.modified" && setting.Value == "true":
			dirty = "-dirty"
		}
	}
	require(revision != "", "the agent binary has no vcs.revision")
	return revision + dirty
}

func until(ctx context.Context, what string, check func() error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		err := check()
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			panic(fmt.Errorf("%s: %w (last: %v)", what, ctx.Err(), err))
		case <-tick.C:
		}
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

type paths struct{ trial, rollback, binary string }

func hostPaths(host *oraclehost.Host) paths {
	nats := filepath.Join(host.Dir, "state", "nats")
	return paths{filepath.Join(nats, "release-trial"), filepath.Join(nats, "release-rolled-back"), filepath.Join(host.Dir, "bin", "terrascale-orchestrator")}
}

func installAsRelease(host *oraclehost.Host, binary, revision, run string) int {
	p := hostPaths(host)
	data, err := os.ReadFile(binary)
	must(err)
	must(os.WriteFile(p.binary+".prev", data, 0o755))
	must(os.MkdirAll(filepath.Dir(p.trial), 0o700))
	trial, err := json.Marshal(map[string]any{"sha": revision, "run_id": run, "installed": time.Now().UTC(), "starts": 0})
	must(err)
	must(os.WriteFile(p.trial, trial, 0o600))
	last := host.LastRun()
	must(host.Signal(syscall.SIGHUP))
	return last
}

func journalCount(host *oraclehost.Host, line string) int {
	journal, err := os.ReadFile(filepath.Join(host.Dir, "journal.log"))
	if err != nil {
		return 0
	}
	return strings.Count(string(journal), line)
}

func confirmed(host *oraclehost.Host) error {
	p := hostPaths(host)
	switch {
	case exists(p.rollback):
		return errors.New("rolled back")
	case exists(p.trial):
		return errors.New("trial still pending")
	}
	return nil
}

func routeFirewall(ctx context.Context, host *oraclehost.Host, action string) {
	for _, rule := range [][]string{{"OUTPUT", "!", "-o", "lo"}, {"INPUT", "!", "-i", "lo"}} {
		args := append([]string{"netns", "exec", host.Namespace, "iptables", action}, rule...)
		args = append(args, "-p", "tcp", "--dport", "6222", "-j", "REJECT")
		output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		require(err == nil, "%s: ip %s: %v %s", host.Name, strings.Join(args, " "), err, output)
	}
}

func main() {
	if oraclehost.Main() {
		return
	}
	binary, work := os.Args[1], os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 330*time.Second)
	defer cancel()
	revision := buildRevision(binary)
	must(os.MkdirAll(filepath.Join(work, "registry"), 0o755))
	fleet, err := oraclehost.New(ctx, work, binary, filepath.Join(work, "registry"), []string{"gru"}, []int{2})
	must(err)
	defer fleet.Close()
	founder, worker := fleet.Hosts[0], fleet.Hosts[1]
	defer func() {
		if value := recover(); value != nil {
			fmt.Printf("FAIL: %v\n", value)
			for _, host := range fleet.Hosts {
				data, _ := os.ReadFile(filepath.Join(host.Dir, "journal.log"))
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				fmt.Printf("--- %s events: %+v\n--- %s journal\n%s\n", host.Name, host.Events(), host.Name, strings.Join(lines[max(0, len(lines)-40):], "\n"))
			}
			fleet.Close()
			os.Exit(1)
		}
	}()
	must(fleet.Boot(founder))
	_, err = founder.WaitReady(ctx, 0, "")
	must(err)
	_, err = fleet.WaitSecret(ctx, regionjoin.SecretName("gru"), func(value string) bool {
		var material regionjoin.Material
		return json.Unmarshal([]byte(value), &material) == nil && material.WorkerToken != "" && len(material.Routes) != 0
	})
	must(err)
	must(fleet.Boot(worker))
	_, err = worker.WaitReady(ctx, 0, "")
	must(err)
	for _, host := range fleet.Hosts {
		until(ctx, host.Name+" mesh starts", func() error {
			if journalCount(host, "mesh started") == 0 {
				return errors.New("no mesh started line yet")
			}
			return nil
		})
	}
	step("%s founded gru and %s joined it from Vault join material; both started their mesh", founder.Name, worker.Name)

	last := installAsRelease(founder, binary, revision, "1")
	_, err = founder.WaitReady(ctx, last, "")
	must(err)
	until(ctx, founder.Name+" confirms its release", func() error { return confirmed(founder) })
	step("the founder confirms its release once its local mesh and release subscriptions serve")

	last = installAsRelease(worker, binary, revision, "2")
	_, err = worker.WaitReady(ctx, last, "")
	must(err)
	until(ctx, worker.Name+" confirms its release", func() error { return confirmed(worker) })
	require(exists(hostPaths(worker).binary+".prev"), "a confirmed release keeps its previous binary")
	step("a joining worker confirms its release once it has a route to its region")

	routeFirewall(ctx, worker, "-I")
	started := journalCount(worker, "mesh started")
	last = installAsRelease(worker, binary, revision, "3")
	ready, err := worker.WaitReady(ctx, last, "")
	must(err)
	until(ctx, worker.Name+" starts its local mesh without a route", func() error {
		if journalCount(worker, "mesh started") == started {
			return errors.New("no new mesh started line yet")
		}
		return nil
	})
	exited, err := worker.WaitEvent(ctx, func(e oraclehost.Event) bool { return e.Kind == "exited" && e.Run == ready.Run })
	must(err)
	served := exited.At.Sub(ready.At)
	p := hostPaths(worker)
	var rollback struct {
		RunID  string `json:"run_id"`
		Reason string `json:"reason"`
	}
	data, err := os.ReadFile(p.rollback)
	must(err)
	must(json.Unmarshal(data, &rollback))
	require(rollback.RunID == "3" && rollback.Reason == "not serving 2m0s after start", "the rollback record names run 3 and the probation expiry: %s", data)
	require(!exists(p.binary+".prev"), "the rollback restored the previous binary")
	require(served >= 115*time.Second, "the candidate exited %s after READY=1, before its probation window ended", served)
	step("a joining worker that sends READY=1 and starts its local mesh but cannot route to its region is never confirmed and rolls back %s after READY=1: %s", served.Round(time.Second), rollback.Reason)
	routeFirewall(ctx, worker, "-D")
}
