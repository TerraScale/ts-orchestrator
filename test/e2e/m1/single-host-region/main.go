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
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
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

func regionRouteFirewall(ctx context.Context, manager *oraclehost.Host, action string) {
	for _, worker := range manager.Region.Hosts[1:] {
		for _, direction := range []struct{ chain, address string }{{"INPUT", "-s"}, {"OUTPUT", "-d"}} {
			output, err := exec.CommandContext(ctx, "ip", "netns", "exec", manager.Namespace, "iptables", action, direction.chain,
				direction.address, worker.Address, "-p", "tcp", "--dport", "6222", "-j", "REJECT").CombinedOutput()
			require(err == nil, "%s region route firewall: %v: %s", manager.Name, err, output)
		}
	}
}

func awaitIsolatedRoutes(ctx context.Context, region *oraclehost.Region) {
	for _, worker := range region.Hosts[1:] {
		until(ctx, worker.Name+" regional route rounds without its manager", func() error {
			text, err := metrics(ctx, worker)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(text, "\n") {
				if value, ok := strings.CutPrefix(line, "ts_orch_mesh_region_routes_rounds_total "); ok {
					rounds, err := strconv.Atoi(value)
					if err == nil && rounds >= 5 {
						return nil
					}
				}
			}
			return errors.New("regional route discovery has not completed five rounds")
		})
	}
	for _, worker := range region.Hosts[1:] {
		peers, err := worker.Established(ctx, 6222)
		must(err)
		for _, peer := range region.Hosts {
			if peer != worker {
				require(!slices.Contains(peers, peer.NetBird), "%s used NetBird to reach %s before its regional manager: %v", worker.Name, peer.Name, peers)
			}
		}
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

func memberState(ctx context.Context, manager *oraclehost.Host, hostname string) string {
	output, _ := manager.Exec(ctx, "/usr/local/bin/ts-orch", "member", "ls")
	for _, line := range strings.Split(string(output), "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 && fields[0] == hostname {
			return fields[2]
		}
	}
	return "absent"
}

func refused(ctx context.Context, host *oraclehost.Host, user, token, region string, data []byte) {
	violations := make(chan error, 1)
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort), nats.SetCustomDialer(host),
		nats.UserInfo(user, meshToken(host, token)),
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
		require(strings.Contains(err.Error(), "Permissions Violation"), "%s %s publication of %s membership: %v", host.Name, user, region, err)
	case <-ctx.Done():
		panic(fmt.Errorf("%s %s published %s membership without a permissions violation", host.Name, user, region))
	}
}

func publish(ctx context.Context, host *oraclehost.Host, region string, data []byte) {
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort), nats.SetCustomDialer(host),
		nats.UserInfo("membership", meshToken(host, "membership.token")))
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

func operatorRelease(ctx context.Context, fleet *oraclehost.Fleet, binary, repo, dir string) (string, error) {
	nodes := []nodelist.Node{}
	for index, host := range fleet.Hosts {
		output, err := host.Exec(ctx, "/usr/local/bin/ts-orch", "node", "keys")
		if err != nil {
			return "", fmt.Errorf("%s node keys: %w: %s", host.Name, err, output)
		}
		var keys nodelist.PublicKeys
		if err := json.Unmarshal(output, &keys); err != nil {
			return "", err
		}
		nodes = append(nodes, nodelist.Node{Name: host.Name, Region: host.Region.Name, PublicIP: fmt.Sprintf("198.51.100.%d", index+1), PrivateIP: host.Address,
			WGPublicKey: keys.WGPublicKey, TLSSPKISHA256: keys.TLSSPKISHA256})
	}
	inventory, err := json.Marshal(nodes)
	if err != nil {
		return "", err
	}
	inventoryPath, listPath := filepath.Join(dir, "inventory.json"), filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(inventoryPath, inventory, 0o644); err != nil {
		return "", err
	}
	if output, err := exec.CommandContext(ctx, binary, "node", "list", "build", "1", inventoryPath, listPath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ts-orch node list build: %w: %s", err, output)
	}
	list, err := os.ReadFile(listPath)
	if err != nil {
		return "", err
	}
	source := filepath.Join(repo, "deploy", "m1", "embed.go")
	original, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	embedded := regexp.MustCompile(`(?m)^const NodeList = .*$`).ReplaceAllLiteral(original, []byte("const NodeList = "+strconv.Quote(string(list))))
	if bytes.Equal(embedded, original) {
		return "", errors.New("deploy/m1/embed.go has no NodeList declaration")
	}
	overlaySource, overlay, out := filepath.Join(dir, "embed.go"), filepath.Join(dir, "overlay.json"), filepath.Join(dir, "release")
	if err := os.WriteFile(overlaySource, embedded, 0o644); err != nil {
		return "", err
	}
	replace, err := json.Marshal(map[string]map[string]string{"Replace": {source: overlaySource}})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(overlay, replace, 0o644); err != nil {
		return "", err
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	owner, err := os.Stat(repo)
	if err != nil {
		return "", err
	}
	build := []string{"env", "PATH=" + filepath.Dir(goTool) + ":/usr/bin:/bin", "GOFLAGS=-overlay=" + overlay, "bash", filepath.Join(repo, "test", "e2e", "m1", "build.sh"), out, "./cmd/terrascale-orchestrator"}
	if uid := owner.Sys().(*syscall.Stat_t).Uid; uid != uint32(os.Geteuid()) {
		build = append([]string{"sudo", "-H", "-u", fmt.Sprintf("#%d", uid)}, build...)
	}
	if output, err := exec.CommandContext(ctx, build[0], build[1:]...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("build the release that embeds node list sequence 1: %w: %s", err, output)
	}
	release := filepath.Join(out, "terrascale-orchestrator")
	require(revision(release) == revision(binary), "the release embedding the node list has revision %s, want %s", revision(release), revision(binary))
	return release, nil
}

func nodeListSequence(ctx context.Context, host *oraclehost.Host, want uint64) {
	until(ctx, fmt.Sprintf("%s node list sequence %d", host.Name, want), func() error {
		status := nodelist.StatusAt(filepath.Join(host.Dir, "state"))
		if status.Sequence != want || status.Refused != "" {
			return fmt.Errorf("%s", status)
		}
		return nil
	})
}

func edgeAnswer(ctx context.Context, host *oraclehost.Host, ca, url string) string {
	output, _ := exec.CommandContext(ctx, "ip", "netns", "exec", host.Namespace, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", "--cacert", ca,
		"--resolve", "whoami.e2e.test:80:127.0.0.1", url).Output()
	return string(output)
}

func unlisted(ctx context.Context, fleet *oraclehost.Fleet, want, ca string) {
	managers, workers := roles(fleet)
	for _, host := range fleet.Hosts {
		healthy(ctx, host, want)
		nodeListSequence(ctx, host, 0)
	}
	for _, manager := range managers {
		whoamiBackend(ctx, manager, ca)
	}
	for _, worker := range workers {
		ready, page := edgeAnswer(ctx, worker, ca, "http://127.0.0.1/edge/ready"), edgeAnswer(ctx, worker, ca, "http://whoami.e2e.test/")
		require(ready == "503" && page == "404", "%s without a node list: edge readiness %s and whoami %s, want 503 and 404 (no route, so no backend reached)", worker.Name, ready, page)
	}
	step("shipped node list (sequence 0, as production) on every host: release health ok everywhere, managers serve whoami as on main, workers' edges route nothing and stay release-healthy")
}

func installEdgeCert(fleet *oraclehost.Fleet) string {
	material, err := fleet.EdgeMaterial("whoami.e2e.test")
	must(err)
	for _, host := range fleet.Hosts {
		dir := host.State("edge-certs")
		must(os.MkdirAll(dir, 0o700))
		must(os.WriteFile(filepath.Join(dir, "whoami.e2e.test"), material, 0o600))
	}
	return filepath.Join(fleet.Work, "ca.pem")
}

func whoamiBody(ctx context.Context, host *oraclehost.Host, ca string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", host.Namespace, "curl", "-fsS", "--max-time", "5", "--cacert", ca, "--resolve", "whoami.e2e.test:443:127.0.0.1", "https://whoami.e2e.test/").CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", host.Name, err, output)
	}
	return output, nil
}

func whoamiBackend(ctx context.Context, host *oraclehost.Host, ca string) string {
	var backend string
	until(ctx, host.Name+" whoami via its edge", func() error {
		seen := ""
		for range 4 {
			body, err := whoamiBody(ctx, host, ca)
			if err != nil {
				return err
			}
			line := ""
			for _, row := range strings.Split(string(body), "\n") {
				row = strings.TrimRight(row, "\r")
				if strings.HasPrefix(row, "Hostname: ") {
					line = row
				}
			}
			if line == "" || !bytes.Contains(body, []byte("Host: whoami.e2e.test")) {
				return fmt.Errorf("body %q", body)
			}
			if seen == "" {
				seen = line
			}
			if line != seen {
				return fmt.Errorf("one edge answered %q and %q", seen, line)
			}
		}
		backend = seen
		return nil
	})
	return backend
}

func ready(ctx context.Context, fleet *oraclehost.Fleet, want, ca string) {
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
			require(listening, "%s: edge :%d listening=%v, want true", host.Name, port, listening)
		}
	}
	backends := map[string]string{}
	for _, manager := range managers {
		backends[manager.Region.Name] = whoamiBackend(ctx, manager, ca)
	}
	for _, worker := range workers {
		got := whoamiBackend(ctx, worker, ca)
		require(got == backends[worker.Region.Name], "%s balanced whoami to %q, want its manager's backend %q", worker.Name, got, backends[worker.Region.Name])
	}
	step("JetStream on managers; every host's edge listens and each worker balances whoami to its manager's backend")
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
	ca := installEdgeCert(fleet)
	defer fleet.Close()
	defer func() {
		if value := recover(); value != nil {
			fmt.Printf("FAIL: %v\nstand-in requests: %v\n", value, fleet.Requests())
			for _, host := range fleet.Hosts {
				fmt.Printf("--- %s journal\n%s\n", host.Name, tail(filepath.Join(host.Dir, "journal.log"), 25))
				fmt.Printf("--- %s mesh\n%s\n", host.Name, meshLines(filepath.Join(host.Dir, "journal.log"), 20))
				if text, err := metrics(context.Background(), host); err == nil {
					fmt.Printf("--- %s mesh metrics\n%s\n", host.Name, meshMetrics(text))
				}
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
	regionRouteFirewall(ctx, gru.Hosts[0], "-I")
	must(fleet.Boot(workers...))
	for _, worker := range workers {
		_, err := worker.WaitReady(ctx, 0, first)
		must(err)
	}
	step("workers joined from Vault join material and sent READY=1")
	awaitIsolatedRoutes(ctx, gru)
	step("%s workers completed five discovery rounds without their manager's route port and never dialed an in-region NetBird route", gru.Name)
	regionRouteFirewall(ctx, gru.Hosts[0], "-D")
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
	sjc := fleet.Regions[1]
	refused(ctx, gru.Hosts[1], mesh.OrchUser, "client.token", gru.Name, forged)
	refused(ctx, gru.Hosts[0], mesh.OrchUser, "client.token", gru.Name, forged)
	refused(ctx, sjc.Hosts[0], mesh.OrchUser, "client.token", gru.Name, forged)
	refused(ctx, sjc.Hosts[0], "membership", "membership.token", gru.Name, forged)
	refused(ctx, gru.Hosts[0], "membership", "membership.token", "ams", forged)
	step("only %s's membership publisher may publish %s membership: %s worker and manager ORCH, %s manager ORCH and membership, and %s's membership publisher for ams are all refused", gru.Name, gru.Name, gru.Name, sjc.Name, gru.Name)
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
	release := make(chan error, 1)
	var released string
	go func() {
		var err error
		released, err = operatorRelease(ctx, fleet, binary, filepath.Join(filepath.Dir(specFile), "..", "..", ".."), filepath.Dir(work))
		release <- err
	}()
	applies := make(chan error, 2)
	for _, service := range []map[string]any{peerCredentialService(spec), spec} {
		go func() {
			applied := filepath.Join(work, service["name"].(string)+".json")
			data, err := json.Marshal(service)
			if err == nil {
				err = os.WriteFile(applied, data, 0o644)
			}
			if err != nil {
				applies <- err
				return
			}
			output, err := managers[0].Exec(ctx, "/usr/local/bin/ts-orch", "service", "apply", "-f", applied)
			if err != nil || bytes.Contains(output, []byte("on this host only")) {
				applies <- fmt.Errorf("service apply of %s on %s did not go through the mesh: %v: %s", service["name"], managers[0].Name, err, output)
				return
			}
			step("applied %s on %s through the mesh: %s", service["name"], managers[0].Name, bytes.TrimSpace(output))
			applies <- nil
		}()
	}
	must(errors.Join(<-applies, <-applies))
	unlisted(ctx, fleet, first, ca)
	must(<-release)
	step("operator built the release embedding node list sequence 1 from every host's ts-orch node keys and ts-orch node list build")
	for _, host := range fleet.Hosts {
		before := host.LastRun()
		must(host.Install(released))
		must(host.Restart())
		_, err := host.WaitReady(ctx, before, first)
		must(err)
		healthy(ctx, host, first)
		nodeListSequence(ctx, host, 1)
		step("%s restarted on the release to READY, release health ok and node list sequence 1 adopted", host.Name)
	}
	ready(ctx, fleet, first, ca)

	flapped, survivor := gru.Hosts[2], gru.Hosts[1]
	configured := fmt.Sprintf("ts_orch_mesh_region_route_configured{address=%q}", flapped.Address)
	must(flapped.Signal(syscall.SIGSTOP))
	until(ctx, flapped.Name+" not READY", func() error {
		if state := memberState(ctx, gru.Hosts[0], flapped.Name); state == "READY" {
			return errors.New(state)
		}
		return nil
	})
	for _, host := range []*oraclehost.Host{gru.Hosts[0], survivor} {
		text, err := metrics(ctx, host)
		must(err)
		require(strings.Contains(text, configured), "%s retired %s's route while it was only not READY", host.Name, flapped.Name)
	}
	must(flapped.Signal(syscall.SIGCONT))
	until(ctx, flapped.Name+" READY again", func() error {
		if state := memberState(ctx, gru.Hosts[0], flapped.Name); state != "READY" {
			return errors.New(state)
		}
		return nil
	})
	reset, err := survivor.ResetRoutes(ctx, flapped, 6222)
	must(err)
	require(reset > 0, "no route sockets between %s and %s to reset", survivor.Name, flapped.Name)
	delivered(ctx, fleet, survivor, flapped)
	delivered(ctx, fleet, flapped, survivor)
	meshRoutes(ctx, fleet)
	step("%s went not READY and back: its route stayed configured, and after %d route sockets to %s were reset ORCH, TERRABASE and ALERTS deliver both ways over the VCN", flapped.Name, reset, survivor.Name)

	departed := gru.Hosts[2]
	left, err := gru.Hosts[0].Exec(ctx, "/usr/local/bin/ts-orch", "member", "leave", departed.Name)
	require(err == nil, "member leave %s: %v: %s", departed.Name, err, left)
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
	step("%s left and was replaced by %s at %s: every %s host routes to it over the VCN and no longer configures %s", departed.Name, replacement.Name, replacement.Address, gru.Name, departed.Address)
	step("single-host-region lane passed in %s", time.Since(started).Round(time.Second))
}

func peerCredentialService(whoami map[string]any) map[string]any {
	data, err := m1.Files.ReadFile("services/ts-auth.json")
	must(err)
	var auth struct {
		Secrets map[string]vaultsecret.Ref `json:"secrets"`
	}
	must(json.Unmarshal(data, &auth))
	ref, ok := auth.Secrets[edge.RequestProofKey]
	require(ok, "deploy/m1/services/ts-auth.json has no %s", edge.RequestProofKey)
	return map[string]any{
		"name":      "terrabase",
		"image":     whoami["image"],
		"args":      []string{"--port", "18082"},
		"port":      18082,
		"readyPath": "/health",
		"replicas":  1,
		"secrets":   map[string]vaultsecret.Ref{edge.RequestProofKey: ref},
	}
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

func meshLines(path string, lines int) string {
	data, _ := os.ReadFile(path)
	matched := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "mesh") && !strings.Contains(line, "module=grpc") {
			matched = append(matched, line)
		}
	}
	return strings.Join(matched[max(0, len(matched)-lines):], "\n")
}

func meshMetrics(text string) string {
	matched := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "ts_orch_mesh_region") {
			matched = append(matched, line)
		}
	}
	return strings.Join(matched, "\n")
}

func tail(path string, lines int) string {
	data, _ := os.ReadFile(path)
	all := strings.Split(strings.TrimSpace(string(data)), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n")
}
