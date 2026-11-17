package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

const meshKey = "ts-orch-mesh-key"

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

func main() {
	if oraclehost.Main() {
		return
	}
	binary, work := os.Args[1], os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 330*time.Second)
	defer cancel()
	revision := buildRevision(binary)
	must(os.MkdirAll(filepath.Join(work, "registry"), 0o755))
	fleet, err := oraclehost.New(ctx, work, binary, filepath.Join(work, "registry"), []string{"gru"}, []int{1})
	must(err)
	defer fleet.Close()
	host := fleet.Hosts[0]
	p := hostPaths(host)
	defer func() {
		if value := recover(); value != nil {
			data, _ := os.ReadFile(filepath.Join(host.Dir, "journal.log"))
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			fmt.Printf("FAIL: %v\nevents: %+v\n--- journal\n%s\n", value, host.Events(), strings.Join(lines[max(0, len(lines)-40):], "\n"))
			fleet.Close()
			os.Exit(1)
		}
	}()
	must(fleet.Boot(host))
	_, err = host.WaitReady(ctx, 0, "")
	must(err)
	original, err := fleet.WaitSecret(ctx, meshKey, func(value string) bool { return value != "" })
	must(err)
	until(ctx, "the mesh starts", func() error {
		journal, err := os.ReadFile(filepath.Join(host.Dir, "journal.log"))
		if err != nil || !strings.Contains(string(journal), "mesh started") {
			return errors.New("no mesh started line yet")
		}
		return nil
	})
	step("%s founded gru, sent READY=1 and started its mesh from Vault", host.Name)

	last := installAsRelease(host, binary, revision, "1")
	_, err = host.WaitReady(ctx, last, "")
	must(err)
	until(ctx, "the release trial is confirmed", func() error {
		switch {
		case exists(p.rollback):
			return errors.New("rolled back")
		case exists(p.trial):
			return errors.New("trial still pending")
		}
		return nil
	})
	require(exists(p.binary+".prev"), "a confirmed release keeps its previous binary")
	step("a release that joins its mesh and subscribes to its region's release subjects confirms its trial and keeps its binary")

	fleet.PutSecret(meshKey, "not a mesh key")
	last = installAsRelease(host, binary, revision, "2")
	ready, err := host.WaitReady(ctx, last, "")
	must(err)
	exited, err := host.WaitEvent(ctx, func(e oraclehost.Event) bool { return e.Kind == "exited" && e.Run == ready.Run })
	must(err)
	served := exited.At.Sub(ready.At)
	var rollback struct {
		RunID  string `json:"run_id"`
		Reason string `json:"reason"`
	}
	data, err := os.ReadFile(p.rollback)
	must(err)
	must(json.Unmarshal(data, &rollback))
	require(rollback.RunID == "2" && rollback.Reason == "not serving 2m0s after start", "the rollback record names run 2 and the probation expiry: %s", data)
	require(!exists(p.binary+".prev"), "the rollback restored the previous binary")
	require(served >= 115*time.Second, "the candidate exited %s after READY=1, before its probation window ended", served)
	step("a release that sends READY=1 but cannot start its mesh (Vault %s unreadable) is never confirmed and rolls back %s after READY=1: %s", meshKey, served.Round(time.Second), rollback.Reason)
	fleet.PutSecret(meshKey, original)
}
