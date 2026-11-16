package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
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

func meshRoutes(ctx context.Context, managers []*oraclehost.Host) {
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
	managers, _ := roles(fleet)
	meshRoutes(ctx, managers)
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
	build := []string{"env", "PATH=" + filepath.Dir(goTool) + ":/usr/bin:/bin", "GOFLAGS=-overlay=" + overlay, "bash", filepath.Join(repo, "test", "e2e", "m1", "build.sh"), out}
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
		reply, err := host.Health(ctx)
		if err != nil {
			return err
		}
		if reply.NodeList.Sequence != want || reply.NodeList.Refused != "" {
			return fmt.Errorf("node list %+v", reply.NodeList)
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
	meshRoutes(ctx, managers)
	step("mesh routes: managers to each other over wt0, each worker to its manager over the VCN")
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
	fleet, err := oraclehost.New(ctx, work, binary, registry, []string{"gru", "sjc", "fra"}, 2)
	must(err)
	ca := installEdgeCert(fleet)
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
	meshUp(ctx, fleet)
	release := make(chan error, 1)
	var released string
	go func() {
		var err error
		released, err = operatorRelease(ctx, fleet, binary, filepath.Join(filepath.Dir(specFile), "..", "..", ".."), filepath.Dir(work))
		release <- err
	}()
	for _, service := range []map[string]any{peerCredentialService(spec), spec} {
		applied := filepath.Join(work, service["name"].(string)+".json")
		data, err := json.Marshal(service)
		must(err)
		must(os.WriteFile(applied, data, 0o644))
		output, err := managers[0].Exec(ctx, "/usr/local/bin/ts-orch", "service", "apply", "-f", applied)
		require(err == nil && !bytes.Contains(output, []byte("on this host only")), "service apply on %s did not go through the mesh: %v: %s", managers[0].Name, err, output)
		step("applied %s on %s through the mesh: %s", service["name"], managers[0].Name, bytes.TrimSpace(output))
	}
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

func tail(path string, lines int) string {
	data, _ := os.ReadFile(path)
	all := strings.Split(strings.TrimSpace(string(data)), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n")
}
