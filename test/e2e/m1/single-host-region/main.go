package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

var started = time.Now()

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Errorf(format, args...))
	}
}

func step(format string, args ...any) {
	fmt.Printf("ok: %5.1fs %s\n", time.Since(started).Seconds(), fmt.Sprintf(format, args...))
}

func revision(path string) string {
	info, err := buildinfo.ReadFile(path)
	must(err)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	panic("the agent binary has no vcs.revision")
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

func healthy(ctx context.Context, host *oraclehost.Host, want string) {
	until(ctx, host.Name+" release health", func() error {
		reply, err := host.Health(ctx)
		if err != nil {
			return err
		}
		if reply.Health != "ok" || reply.Version != want {
			return fmt.Errorf("health %q version %s", reply.Health, reply.Version)
		}
		return nil
	})
}

func roles(fleet *oraclehost.Fleet) (managers, workers []*oraclehost.Host) {
	for _, region := range fleet.Regions {
		managers = append(managers, region.Hosts[0])
		workers = append(workers, region.Hosts[1:]...)
	}
	return managers, workers
}

func ready(ctx context.Context, fleet *oraclehost.Fleet, want string) {
	managers, workers := roles(fleet)
	for _, host := range fleet.Hosts {
		healthy(ctx, host, want)
	}
	step("release health ok with revision %s on %d managers and %d workers", want[:12], len(managers), len(workers))
	for _, manager := range managers {
		var output []byte
		until(ctx, manager.Name+" ts-orch status", func() error {
			var err error
			output, err = manager.Exec(ctx, "/usr/local/bin/ts-orch", "status")
			if err != nil {
				return fmt.Errorf("%w: %s", err, output)
			}
			for _, region := range fleet.Regions {
				if !bytes.Contains(output, []byte("\n"+region.Name+": ok;")) && !bytes.HasPrefix(output, []byte(region.Name+": ok;")) {
					return fmt.Errorf("region %s not ok: %s", region.Name, output)
				}
			}
			return nil
		})
		if manager == managers[0] {
			fmt.Printf("%s", output)
		}
	}
	step("ts-orch status reports every region ok from every manager")
	for _, manager := range managers {
		until(ctx, manager.Name+" mesh routes", func() error {
			peers, err := manager.Established(ctx, 6222)
			if err != nil {
				return err
			}
			for _, other := range managers {
				if other != manager && !slices.Contains(peers, other.NetBird) {
					return fmt.Errorf("no NetBird route to %s (%s) in %v", other.Name, other.NetBird, peers)
				}
			}
			for _, worker := range manager.Region.Hosts[1:] {
				if !slices.Contains(peers, worker.Address) {
					return fmt.Errorf("no in-region route to worker %s (%s) in %v", worker.Name, worker.Address, peers)
				}
			}
			return nil
		})
	}
	step("mesh routes: managers to each other over wt0, each worker to its manager over the VCN")
	for _, host := range fleet.Hosts {
		_, err := os.Stat(host.State("mesh/jetstream"))
		manager := slices.Contains(managers, host)
		require(manager == (err == nil), "%s: JetStream store present=%v, want %v", host.Name, err == nil, manager)
		for _, port := range []int{80, 443} {
			listening, err := host.Listening(ctx, port)
			must(err)
			require(listening == manager, "%s: edge :%d listening=%v, want %v", host.Name, port, listening, manager)
		}
	}
	step("JetStream fabric and edge :80/:443 run on managers only")
}

func main() {
	if oraclehost.Main() {
		return
	}
	if os.Args[1] == "fetch" {
		spec := workload(os.Args[2], os.Args[3])
		must(oraclehost.FetchImage(context.Background(), spec["image"].(string), os.Args[4]))
		return
	}
	binary, work, specFile, registry := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	first := revision(binary)
	spec := workload(specFile, filepath.Join(os.Args[3], "..", "images.json"))
	fleet, err := oraclehost.New(ctx, work, binary, registry, []string{"gru", "sjc", "fra"}, 2)
	must(err)
	defer fleet.Close()
	defer func() {
		if value := recover(); value != nil {
			fmt.Printf("FAIL: %v\nstand-in requests: %v\n", value, fleet.Requests())
			for _, host := range fleet.Hosts {
				fmt.Printf("--- %s journal\n%s\n", host.Name, tail(filepath.Join(host.Dir, "journal.log"), 25))
			}
			fleet.Close()
			os.Exit(1)
		}
	}()
	managers, workers := roles(fleet)
	step("%d hosts in their own network namespaces; IMDS, OCI federation, Vault, GitHub OIDC key and registry stand-ins up", len(fleet.Hosts))
	must(fleet.Boot(managers...))
	for _, manager := range managers {
		_, err := manager.WaitReady(ctx, 0, first)
		must(err)
	}
	step("founders sent READY=1")
	for _, region := range fleet.Regions {
		value, err := fleet.WaitSecret(ctx, regionjoin.SecretName(region.Name), func(value string) bool {
			var material regionjoin.Material
			return json.Unmarshal([]byte(value), &material) == nil && material.WorkerToken != "" && len(material.Routes) != 0
		})
		must(err)
		var material regionjoin.Material
		must(json.Unmarshal([]byte(value), &material))
		require(material.Founder == region.Hosts[0].Name && material.Manager == region.Hosts[0].Address+":4242", "%s join material names founder %s at %s", region.Name, material.Founder, material.Manager)
	}
	step("each founder claimed and published its region's join material in Vault")
	must(fleet.Boot(workers...))
	for _, worker := range workers {
		_, err := worker.WaitReady(ctx, 0, first)
		must(err)
	}
	step("workers joined from Vault join material and sent READY=1")
	applied := filepath.Join(work, "workload.json")
	data, err := json.Marshal(spec)
	must(err)
	must(os.WriteFile(applied, data, 0o644))
	output, err := managers[0].Exec(ctx, "/usr/local/bin/ts-orch", "service", "apply", "-f", applied)
	require(err == nil, "service apply on %s: %v: %s", managers[0].Name, err, output)
	step("applied %s on %s through the mesh: %s", spec["name"], managers[0].Name, bytes.TrimSpace(output))
	ready(ctx, fleet, first)

	for _, host := range fleet.Hosts {
		before := host.LastRun()
		must(host.Restart())
		_, err := host.WaitReady(ctx, before, first)
		must(err)
		healthy(ctx, host, first)
		step("%s restarted to READY and release health ok", host.Name)
	}
	ready(ctx, fleet, first)
	step("single-host-region lane passed in %s", time.Since(started).Round(time.Second))
}

func workload(specFile, imagesFile string) map[string]any {
	var spec map[string]any
	data, err := os.ReadFile(specFile)
	must(err)
	must(json.Unmarshal(data, &spec))
	var images map[string]map[string]string
	data, err = os.ReadFile(imagesFile)
	must(err)
	must(json.Unmarshal(data, &images))
	spec["image"] = images[spec["name"].(string)][runtime.GOARCH]
	return spec
}

func tail(path string, lines int) string {
	data, _ := os.ReadFile(path)
	all := strings.Split(strings.TrimSpace(string(data)), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n")
}
