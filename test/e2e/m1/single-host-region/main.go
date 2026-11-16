package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

func refused(ctx context.Context, host *oraclehost.Host, region string, data []byte) {
	violations := make(chan error, 1)
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort), nats.SetCustomDialer(host),
		nats.UserInfo(mesh.OrchUser, meshToken(host, "client.token")),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case violations <- err:
			default:
			}
		}))
	must(err)
	defer conn.Close()
	must(conn.Publish(protocol.MeshWorkerPrefix+region+".routes", data))
	must(conn.Flush())
	select {
	case err := <-violations:
		require(strings.Contains(err.Error(), "Permissions Violation"), "%s publication of %s membership: %v", host.Name, region, err)
	case <-ctx.Done():
		panic(fmt.Errorf("%s published %s membership without a permissions violation", host.Name, region))
	}
}

func publish(ctx context.Context, host *oraclehost.Host, region string, data []byte) {
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort), nats.SetCustomDialer(host),
		nats.UserInfo(mesh.OrchUser, meshToken(host, "client.token")))
	must(err)
	defer conn.Close()
	must(conn.Publish(protocol.MeshWorkerPrefix+region+".routes", data))
	must(conn.FlushWithContext(ctx))
}

func metrics(ctx context.Context, host *oraclehost.Host) (string, error) {
	client := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
		return host.Dial(network, address)
	}}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9097/metrics", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func rejected(ctx context.Context, host *oraclehost.Host) int {
	var count int
	until(ctx, host.Name+" metrics", func() error {
		text, err := metrics(ctx, host)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(text, "\n") {
			if value, ok := strings.CutPrefix(line, "ts_orch_mesh_region_routes_rejected_total "); ok {
				_, err := fmt.Sscan(value, &count)
				return err
			}
		}
		return errors.New("no rejected-routes counter")
	})
	return count
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
	fleet, err := oraclehost.New(ctx, work, binary, registry, []string{"gru", "sjc", "fra"}, []int{4, 2, 2})
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
	gru := fleet.Regions[0]
	replacement := gru.Hosts[3]
	gru.Hosts = gru.Hosts[:3]
	fleet.Hosts = slices.DeleteFunc(fleet.Hosts, func(host *oraclehost.Host) bool { return host == replacement })
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
	decoy, err := net.Listen("tcp", net.JoinHostPort(oraclehost.GatewayAddress, "6222"))
	must(err)
	defer decoy.Close()
	var dialed atomic.Int64
	go func() {
		for {
			conn, err := decoy.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			conn.Close()
		}
	}()
	forged := []byte(`["` + oraclehost.GatewayAddress + `"]`)
	refused(ctx, gru.Hosts[1], gru.Name, forged)
	refused(ctx, fleet.Regions[1].Hosts[0], gru.Name, forged)
	step("a %s worker and a %s manager may not publish %s membership: both publications refused", gru.Name, fleet.Regions[1].Name, gru.Name)
	before := map[*oraclehost.Host]int{}
	for _, worker := range gru.Hosts[1:] {
		before[worker] = rejected(ctx, worker)
	}
	publish(ctx, gru.Hosts[0], gru.Name, []byte(`["`+oraclehost.GatewayAddress+`","192.0.2.1"]`))
	for _, worker := range gru.Hosts[1:] {
		until(ctx, worker.Name+" rejects membership outside the VCN", func() error {
			if count := rejected(ctx, worker); count <= before[worker] {
				return fmt.Errorf("rejected %d", count)
			}
			return nil
		})
	}
	require(dialed.Load() == 0, "a host dialed the forged member %s %d times", oraclehost.GatewayAddress, dialed.Load())
	step("%s workers drop and count membership naming an address outside the VCN; nobody dialed %s", gru.Name, oraclehost.GatewayAddress)
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

	departed := gru.Hosts[2]
	must(departed.Kill())
	gru.Hosts = []*oraclehost.Host{gru.Hosts[0], gru.Hosts[1], replacement}
	fleet.Hosts = append(slices.DeleteFunc(fleet.Hosts, func(host *oraclehost.Host) bool { return host == departed }), replacement)
	must(fleet.Boot(replacement))
	_, err = replacement.WaitReady(ctx, 0, first)
	must(err)
	meshRoutes(ctx, fleet)
	for _, host := range gru.Hosts {
		until(ctx, host.Name+" retires "+departed.Name+"'s route", func() error {
			text, err := metrics(ctx, host)
			if err != nil {
				return err
			}
			if strings.Contains(text, fmt.Sprintf("ts_orch_mesh_region_route_configured{address=%q}", departed.Address)) {
				return fmt.Errorf("%s still configured", departed.Address)
			}
			if !strings.Contains(text, fmt.Sprintf("ts_orch_mesh_region_route_configured{address=%q}", gru.Hosts[0].Address)) && host != gru.Hosts[0] {
				return fmt.Errorf("%s not configured", gru.Hosts[0].Address)
			}
			return nil
		})
	}
	require(dialed.Load() == 0, "a host dialed the forged member %s %d times", oraclehost.GatewayAddress, dialed.Load())
	step("%s replaced by %s at %s: every %s host routes to it over the VCN and no longer configures %s", departed.Name, replacement.Name, replacement.Address, gru.Name, departed.Address)
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
