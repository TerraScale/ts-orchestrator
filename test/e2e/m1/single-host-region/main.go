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

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
	"github.com/nats-io/nats.go"
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

func meshRoutes(ctx context.Context, fleet *oraclehost.Fleet) {
	managers, _ := roles(fleet)
	for _, host := range fleet.Hosts {
		until(ctx, host.Name+" mesh routes", func() error {
			peers, err := host.Established(ctx, 6222)
			if err != nil {
				return err
			}
			if slices.Contains(managers, host) {
				for _, other := range managers {
					if other != host && !slices.Contains(peers, other.NetBird) {
						return fmt.Errorf("no NetBird route to %s (%s) in %v", other.Name, other.NetBird, peers)
					}
				}
			}
			for _, peer := range host.Region.Hosts {
				if peer == host {
					continue
				}
				if !slices.Contains(peers, peer.Address) {
					return fmt.Errorf("no in-region VCN route to %s (%s) in %v", peer.Name, peer.Address, peers)
				}
				if slices.Contains(peers, peer.NetBird) {
					return fmt.Errorf("in-region route to %s over NetBird (%s) in %v", peer.Name, peer.NetBird, peers)
				}
			}
			return nil
		})
	}
}

func meshToken(host *oraclehost.Host, name string) string {
	data, err := os.ReadFile(host.State("mesh/" + name))
	must(err)
	return strings.TrimSpace(string(data))
}

func delivered(ctx context.Context, fleet *oraclehost.Fleet, from, to *oraclehost.Host) {
	terrabase, _ := fleet.Secret(mesh.TerraBaseTokenSecret)
	accounts := []struct {
		name       string
		credential func(*oraclehost.Host) nats.Option
	}{
		{mesh.OrchAccount, func(host *oraclehost.Host) nats.Option {
			return nats.UserInfo(mesh.OrchUser, meshToken(host, "client.token"))
		}},
		{mesh.FabricAccount, func(*oraclehost.Host) nats.Option { return nats.Token(strings.ToLower(strings.TrimSpace(terrabase))) }},
		{"ALERTS", func(host *oraclehost.Host) nats.Option {
			return nats.UserInfo(mesh.AlertsUser, meshToken(host, "alerts.token"))
		}},
	}
	address := fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort)
	for _, account := range accounts {
		subject := "terrabase.e2e." + from.Name + "." + to.Name
		receiver, err := nats.Connect(address, nats.SetCustomDialer(to), account.credential(to))
		must(err)
		subscription, err := receiver.SubscribeSync(subject)
		must(err)
		must(receiver.Flush())
		sender, err := nats.Connect(address, nats.SetCustomDialer(from), account.credential(from))
		must(err)
		until(ctx, fmt.Sprintf("%s delivery %s -> %s", account.name, from.Name, to.Name), func() error {
			if err := sender.Publish(subject, []byte(from.Name)); err != nil {
				return err
			}
			if err := sender.Flush(); err != nil {
				return err
			}
			message, err := subscription.NextMsg(time.Second)
			if err != nil {
				return err
			}
			if string(message.Data) != from.Name {
				return fmt.Errorf("received %q", message.Data)
			}
			return nil
		})
		sender.Close()
		receiver.Close()
	}
}

func statusLine(output []byte, region string) string {
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, region+": ") {
			return line
		}
	}
	return ""
}

func meshUp(ctx context.Context, fleet *oraclehost.Fleet) {
	meshRoutes(ctx, fleet)
	managers, _ := roles(fleet)
	for _, manager := range managers {
		until(ctx, manager.Name+" mesh answers", func() error {
			output, _ := manager.Exec(ctx, "/usr/local/bin/ts-orch", "status")
			for _, region := range fleet.Regions {
				if line := statusLine(output, region.Name); line == "" || line == region.Name+": unreachable" {
					return fmt.Errorf("region %s does not answer over the mesh: %s", region.Name, output)
				}
			}
			return nil
		})
	}
	step("every manager's mesh is up and every region answers ts-orch status over it")
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
				if !strings.HasPrefix(statusLine(output, region.Name), region.Name+": ok;") {
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
	meshRoutes(ctx, fleet)
	step("mesh routes: managers to each other over wt0, every in-region pair over the VCN and never over wt0")
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
	fleet, err := oraclehost.New(ctx, work, binary, registry, []string{"gru", "sjc", "fra"}, []int{3, 2, 2})
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
	gru := fleet.Regions[0]
	var stale regionjoin.Material
	must(json.Unmarshal([]byte(fleet.PinSecret(regionjoin.SecretName(gru.Name))), &stale))
	for _, worker := range gru.Hosts[1:] {
		require(!strings.Contains(strings.Join(stale.Routes, " "), "//"+worker.Address+":"), "%s pinned join material lists %s: %v", gru.Name, worker.Name, stale.Routes)
	}
	step("%s join material pinned at a version that lists neither %s nor %s: %v", gru.Name, gru.Hosts[1].Name, gru.Hosts[2].Name, stale.Routes)
	must(fleet.Boot(workers...))
	for _, worker := range workers {
		_, err := worker.WaitReady(ctx, 0, first)
		must(err)
	}
	step("workers joined from Vault join material and sent READY=1")
	meshUp(ctx, fleet)
	delivered(ctx, fleet, gru.Hosts[1], gru.Hosts[2])
	delivered(ctx, fleet, gru.Hosts[2], gru.Hosts[1])
	fleet.UnpinSecret(regionjoin.SecretName(gru.Name))
	step("%s and %s, joined from material that lists neither, route to each other over the VCN and deliver ORCH, TERRABASE and ALERTS both ways", gru.Hosts[1].Name, gru.Hosts[2].Name)
	applied := filepath.Join(work, "workload.json")
	data, err := json.Marshal(spec)
	must(err)
	must(os.WriteFile(applied, data, 0o644))
	output, err := managers[0].Exec(ctx, "/usr/local/bin/ts-orch", "service", "apply", "-f", applied)
	require(err == nil && !bytes.Contains(output, []byte("on this host only")), "service apply on %s did not go through the mesh: %v: %s", managers[0].Name, err, output)
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
