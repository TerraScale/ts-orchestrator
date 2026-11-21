package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
)

const (
	repositoryAPI = "https://api.github.com/repos/" + releaseattest.Repository
	probeWait     = 10 * time.Second
	trustedMarker = `"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"`
)

var (
	started    = time.Now()
	asset      = releaseattest.AssetPrefix + runtime.GOARCH
	releaseTag = regexp.MustCompile(`^ci-([0-9a-f]{40})-run-([0-9]{1,20})$`)
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
	fmt.Printf("ok: %5.1fs %s\n", time.Since(started).Seconds(), fmt.Sprintf(format, args...))
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	must(err)
	return data
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func revision(path string) string {
	info, err := buildinfo.ReadFile(path)
	must(err)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	panic(path + " has no vcs.revision")
}

func github(url string) []byte {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	must(err)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := os.Getenv("GH_TOKEN"); token != "" && strings.HasPrefix(url, "https://api.github.com/") {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(request)
	must(err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	must(err)
	require(response.StatusCode == http.StatusOK, "GitHub %s: %s: %s", url, response.Status, data[:min(len(data), 300)])
	return data
}

func decode(data []byte, value any) {
	must(json.Unmarshal(data, value))
}

type pinnedRelease struct {
	Tag, SHA, Run string
}

func pinned(lineage string) pinnedRelease {
	type candidate struct {
		pinnedRelease
		RunID uint64
	}
	var candidates []candidate
	for page := 1; ; page++ {
		var releases []struct {
			Tag       string                  `json:"tag_name"`
			Draft     bool                    `json:"draft"`
			Published time.Time               `json:"published_at"`
			Assets    []struct{ Name string } `json:"assets"`
		}
		decode(github(fmt.Sprintf("%s/releases?per_page=100&page=%d", repositoryAPI, page)), &releases)
		for _, release := range releases {
			match := releaseTag.FindStringSubmatch(release.Tag)
			if release.Draft || release.Published.IsZero() || match == nil || match[1] == lineage {
				continue
			}
			binary, provenance := false, false
			for _, file := range release.Assets {
				binary = binary || file.Name == asset
				provenance = provenance || file.Name == releaseattest.BundleAsset
			}
			if !binary || !provenance {
				continue
			}
			run, err := strconv.ParseUint(match[2], 10, 64)
			must(err)
			candidates = append(candidates, candidate{pinnedRelease{release.Tag, match[1], match[2]}, run})
		}
		if len(releases) < 100 {
			break
		}
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		return cmp.Compare(b.RunID, a.RunID)
	})
	for _, release := range candidates {
		var comparison struct {
			Status  string `json:"status"`
			AheadBy int    `json:"ahead_by"`
		}
		decode(github(fmt.Sprintf("%s/compare/%s...%s?per_page=1", repositoryAPI, release.SHA, lineage)), &comparison)
		if comparison.Status != "ahead" || comparison.AheadBy == 0 {
			continue
		}
		var commit struct{ SHA string }
		decode(github(repositoryAPI+"/commits/"+release.Tag), &commit)
		require(commit.SHA == release.SHA, "release %s points at %s instead of %s", release.Tag, commit.SHA, release.SHA)
		message := fmt.Sprintf("pinned strict-ancestor release %s for %s (ahead by %d)\n", release.Tag, lineage, comparison.AheadBy)
		fmt.Print(message)
		if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
			file, err := os.OpenFile(summary, os.O_APPEND|os.O_WRONLY, 0)
			must(err)
			_, err = fmt.Fprint(file, message)
			must(err)
			must(file.Close())
		}
		return release.pinnedRelease
	}
	panic(fmt.Sprintf("no published release is a strict ancestor of %s", lineage))
}

func fetchPrevious(work string, pin pinnedRelease) {
	var release struct {
		Draft  bool `json:"draft"`
		Assets []struct {
			Name     string `json:"name"`
			Digest   string `json:"digest"`
			Download string `json:"browser_download_url"`
		} `json:"assets"`
	}
	decode(github(repositoryAPI+"/releases/tags/"+pin.Tag), &release)
	require(!release.Draft, "pinned release %s is a draft", pin.Tag)
	names := []string{}
	for _, file := range release.Assets {
		names = append(names, file.Name)
	}
	require(slices.Contains(names, releaseattest.BundleAsset), "pinned release %s was never published: it has no %s", pin.Tag, releaseattest.BundleAsset)
	for _, file := range release.Assets {
		if file.Name != asset {
			continue
		}
		data := github(file.Download)
		require("sha256:"+digest(data) == file.Digest, "pinned %s %s has digest %s, GitHub lists %s", pin.Tag, asset, digest(data), file.Digest)
		must(os.WriteFile(filepath.Join(work, "previous"), data, 0o755))
		require(revision(filepath.Join(work, "previous")) == pin.SHA, "pinned %s %s was not built from %s", pin.Tag, asset, pin.SHA)
		fmt.Printf("pinned previous release %s (%s sha256:%s)\n", pin.Tag, asset, digest(data))
		return
	}
	panic(fmt.Sprintf("pinned release %s has no %s", pin.Tag, asset))
}

func nextRevision(sha string) string {
	sum := sha256.Sum256([]byte("upgrade-gate: the next release after " + sha))
	return hex.EncodeToString(sum[:])[:40]
}

func workloads(lane string) []map[string]any {
	var whoami map[string]any
	decode(read(filepath.Join(lane, "whoami.json")), &whoami)
	var images map[string]map[string]string
	decode(read(filepath.Join(lane, "images.json")), &images)
	whoami["image"] = images[whoami["name"].(string)][runtime.GOARCH]
	var auth struct {
		Secrets map[string]vaultsecret.Ref `json:"secrets"`
	}
	data, err := m1.Files.ReadFile("services/ts-auth.json")
	must(err)
	decode(data, &auth)
	ref, ok := auth.Secrets[edge.RequestProofKey]
	require(ok, "deploy/m1/services/ts-auth.json has no %s", edge.RequestProofKey)
	terrabase := map[string]any{"name": "terrabase", "image": whoami["image"], "args": []string{"--port", "18082"}, "port": 18082,
		"readyPath": "/health", "replicas": 1, "secrets": map[string]vaultsecret.Ref{edge.RequestProofKey: ref}}
	return []map[string]any{terrabase, whoami}
}

func serve(ctx context.Context, fleet *oraclehost.Fleet, manager *oraclehost.Host, services []map[string]any, work string) {
	names := []string{}
	for _, service := range services {
		if hostnames, ok := service["hostnames"].([]any); ok {
			for _, name := range hostnames {
				names = append(names, name.(string))
			}
		}
	}
	for _, region := range fleet.Regions {
		names = append(names, region.Name+"."+mesh.Domain)
	}
	for _, name := range names {
		material, err := fleet.EdgeMaterial(name)
		must(err)
		for _, host := range fleet.Hosts {
			must(os.MkdirAll(host.State("edge-certs"), 0o700))
			must(os.WriteFile(filepath.Join(host.State("edge-certs"), name), material, 0o600))
		}
	}
	until(ctx, manager.Name+" reaches every region over the mesh", func() error {
		output, _ := manager.Exec(ctx, "/usr/local/bin/ts-orch", "status")
		for _, region := range fleet.Regions {
			if !bytes.Contains(output, []byte(region.Name+":")) || bytes.Contains(output, []byte(region.Name+": unreachable")) {
				return fmt.Errorf("region %s does not answer over the mesh: %s", region.Name, output)
			}
		}
		return nil
	})
	for _, service := range services {
		applied := filepath.Join(work, service["name"].(string)+".json")
		data, err := json.Marshal(service)
		must(err)
		must(os.WriteFile(applied, data, 0o644))
		output, err := manager.Exec(ctx, "/usr/local/bin/ts-orch", "service", "apply", "-f", applied)
		require(err == nil && !bytes.Contains(output, []byte("on this host only")), "service apply of %s on %s did not go through the mesh: %v: %s", service["name"], manager.Name, err, output)
	}
}

func fetch(mode, candidate, work, lineage, lane string) {
	head := revision(candidate)
	require(lineage == head, "lineage %s differs from candidate revision %s", lineage, head)
	pin := pinned(lineage)
	for _, service := range workloads(lane)[1:] {
		must(oraclehost.FetchImage(context.Background(), service["image"].(string), filepath.Join(work, "registry")))
	}
	if mode == "previous" {
		fetchPrevious(work, pin)
	}
	rewrite := func(body []byte) []byte { return bytes.ReplaceAll(body, []byte(lineage), []byte(head)) }
	base, served := pin.SHA, head
	if mode == "next" {
		base, served = head, nextRevision(head)
		rewrite = func(body []byte) []byte {
			return bytes.ReplaceAll(bytes.ReplaceAll(body, []byte(lineage), []byte(served)), []byte(pin.SHA), []byte(head))
		}
	}
	comparisons := map[string][]byte{}
	for page := 1; ; {
		body := github(fmt.Sprintf("%s/compare/%s...%s?per_page=1&page=%d", repositoryAPI, pin.SHA, lineage, page))
		var comparison struct {
			Status  string `json:"status"`
			AheadBy int    `json:"ahead_by"`
		}
		decode(body, &comparison)
		require(comparison.Status == "ahead", "GitHub compares the pinned release %s with %s as %q: the pin is not an ancestor of what this run releases; rebase onto main", pin.Tag, lineage, comparison.Status)
		comparisons[oraclehost.ComparisonKey(base, served, page)] = rewrite(body)
		fmt.Printf("lineage %s...%s page %d (%d bytes, ahead by %d) served as %s...%s\n", pin.SHA, lineage, page, len(body), comparison.AheadBy, base, served)
		if page != 1 || comparison.AheadBy <= 1 {
			break
		}
		page = comparison.AheadBy
	}
	body := github(fmt.Sprintf("%s/compare/%s...%s?per_page=1", repositoryAPI, lineage, pin.SHA))
	var reverse struct {
		Status   string `json:"status"`
		BehindBy int    `json:"behind_by"`
	}
	decode(body, &reverse)
	require(reverse.Status == "behind", "GitHub compares %s with the pinned release %s as %q, not behind", lineage, pin.Tag, reverse.Status)
	comparisons[oraclehost.ComparisonKey(served, base, 0)] = rewrite(body)
	fmt.Printf("lineage %s...%s (%d bytes, behind by %d) served as %s...%s\n", lineage, pin.SHA, len(body), reverse.BehindBy, served, base)
	releases := github(repositoryAPI + "/releases?per_page=30")
	fmt.Printf("recorded GitHub release list: %d bytes\n", len(releases))
	must(os.WriteFile(filepath.Join(work, "releases.json"), releases, 0o644))
	data, err := json.Marshal(comparisons)
	must(err)
	must(os.WriteFile(filepath.Join(work, "comparisons.json"), data, 0o644))
}

func withRevision(binary []byte, from, to string) []byte {
	old, replacement := []byte("vcs.revision="+from), []byte("vcs.revision="+to)
	require(bytes.Contains(binary, old), "the binary does not embed vcs.revision=%s", from)
	return bytes.ReplaceAll(binary, old, replacement)
}

func olderReleases(recorded []byte, run uint64) []byte {
	var releases []map[string]any
	decode(recorded, &releases)
	kept := []map[string]any{}
	for _, release := range releases {
		tag, _ := release["tag_name"].(string)
		if match := releaseTag.FindStringSubmatch(tag); match != nil {
			if number, err := strconv.ParseUint(match[2], 10, 64); err == nil && number >= run {
				continue
			}
		}
		kept = append(kept, release)
	}
	data, err := json.Marshal(kept)
	must(err)
	return data
}

func trusting(binary, trusted []byte) []byte {
	out := bytes.Clone(binary)
	patched := 0
	for offset := 0; ; {
		found := bytes.Index(out[offset:], []byte(trustedMarker))
		if found < 0 {
			break
		}
		start := bytes.LastIndexByte(out[:offset+found], '{')
		require(start >= offset && len(bytes.TrimSpace(out[start+1:offset+found])) == 0, "the embedded Sigstore trusted root does not open with its media type")
		decoder := json.NewDecoder(bytes.NewReader(out[start:]))
		var root json.RawMessage
		must(decoder.Decode(&root))
		length := int(decoder.InputOffset())
		require(len(trusted) <= length, "the lane's trusted root (%d bytes) is larger than the embedded one (%d bytes)", len(trusted), length)
		copy(out[start:], trusted)
		copy(out[start+len(trusted):start+length], bytes.Repeat([]byte(" "), length-len(trusted)))
		patched++
		offset = start + length
	}
	require(patched > 0, "the binary embeds no Sigstore trusted root")
	return out
}

func serving(ctx context.Context, host *oraclehost.Host, sha string, binary []byte) error {
	probe, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	reply, err := host.Health(probe)
	if err != nil {
		return err
	}
	if reply.Version != sha || reply.SHA256 != digest(binary) || reply.Health != "ok" {
		return fmt.Errorf("serves %s sha256:%s health %q state %q %s", reply.Version, reply.SHA256, reply.Health, reply.State, reply.Error)
	}
	if !bytes.Equal(read(filepath.Join(host.Dir, "bin", "terrascale-orchestrator")), binary) {
		return errors.New("the installed executable is not the expected release")
	}
	for _, record := range []string{"nats/release-trial", "nats/release-trial.staged", "nats/release-rolled-back"} {
		if _, err := os.Stat(host.State(record)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is present: probation has not confirmed the release (%v)", record, err)
		}
	}
	return nil
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

func releaseLines(path string, lines int) string {
	data, _ := os.ReadFile(path)
	matched := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "module=grpc") && (strings.Contains(lower, "release") || strings.Contains(lower, "preflight") || strings.Contains(lower, "refus")) {
			matched = append(matched, line)
		}
	}
	return strings.Join(matched[max(0, len(matched)-lines):], "\n")
}

func tail(path string, lines int) string {
	data, _ := os.ReadFile(path)
	all := strings.Split(strings.TrimSpace(string(data)), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n")
}

func journey(mode, candidatePath, work string, run uint64, lane string) {
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	authority := sigstore.New()
	trusted := authority.TrustedRoot()
	candidate := read(candidatePath)
	sha := revision(candidatePath)
	var installed, target []byte
	switch mode {
	case "previous":
		installed, target = trusting(read(filepath.Join(work, "previous")), trusted), trusting(candidate, trusted)
	case "next":
		installed = trusting(candidate, trusted)
		target = withRevision(installed, sha, nextRevision(sha))
		sha = nextRevision(sha)
		run++
	}
	installedPath := filepath.Join(work, "installed")
	must(os.WriteFile(installedPath, installed, 0o755))
	from := revision(installedPath)
	var comparisons map[string][]byte
	decode(read(filepath.Join(work, "comparisons.json")), &comparisons)
	registry := filepath.Join(work, "registry")
	must(os.MkdirAll(registry, 0o755))
	regions := mesh.Regions("gru")
	workerRegion := "sjc"
	if mode == "next" {
		workerRegion = mesh.EnvironmentOf("gru").Rollout[0]
	}
	workerIndex := slices.Index(regions, workerRegion)
	counts := []int{1, 1, 1}
	counts[workerIndex] = 2
	fleet, err := oraclehost.New(ctx, filepath.Join(work, "fleet"), installedPath, registry, regions, counts)
	must(err)
	defer fleet.Close()
	defer func() {
		if value := recover(); value != nil {
			fmt.Printf("FAIL: %v\nstand-in requests: %v\nGitHub requests:\n%s\n", value, fleet.Requests(), strings.Join(fleet.GitHub().Requests(), "\n"))
			for _, host := range fleet.Hosts {
				fmt.Printf("--- %s release decisions\n%s\n", host.Name, releaseLines(filepath.Join(host.Dir, "journal.log"), 25))
				fmt.Printf("--- %s journal\n%s\n", host.Name, tail(filepath.Join(host.Dir, "journal.log"), 40))
			}
			fleet.Close()
			os.Exit(1)
		}
	}()
	must(fleet.GitHub().Record(olderReleases(read(filepath.Join(work, "releases.json")), run), comparisons))
	upgraded := fleet.Regions[workerIndex]
	manager, worker := upgraded.Hosts[0], upgraded.Hosts[1]
	founders := make([]*oraclehost.Host, 0, len(fleet.Regions))
	for _, region := range fleet.Regions {
		founders = append(founders, region.Hosts[0])
	}
	must(fleet.Boot(founders...))
	for _, host := range founders {
		_, err := host.WaitReady(ctx, 0, from)
		must(err)
	}
	must(fleet.Boot(worker))
	_, err = worker.WaitReady(ctx, 0, from)
	must(err)
	serve(ctx, fleet, manager, workloads(lane), work)
	step("applied terrabase and e2e-whoami through %s's mesh, as production regions serve services", manager.Name)
	for _, host := range fleet.Hosts {
		until(ctx, host.Name+" serves the installed release", func() error { return serving(ctx, host, from, installed) })
	}
	step("gru, sjc and fra founders and the %s worker serve %s sha256:%s; GitHub lists no release of ours yet", workerRegion, from, digest(installed))
	tag := releaseattest.Tag(sha, strconv.FormatUint(run, 10))
	bundle := authority.Bundle(sigstore.MainIdentity, sha, strconv.FormatUint(run, 10), map[string][]byte{asset: target})
	fleet.GitHub().Publish(tag, map[string][]byte{asset: target, releaseattest.BundleAsset: bundle})
	step("published %s (%s sha256:%s) with its provenance", tag, asset, digest(target))
	for _, host := range upgraded.Hosts {
		until(ctx, host.Name+" installs "+tag+" through its updater and confirms it", func() error { return serving(ctx, host, sha, target) })
		require(bytes.Equal(read(filepath.Join(host.Dir, "bin", "terrascale-orchestrator.prev")), installed), "%s does not keep the replaced release as its rollback target", host.Name)
	}
	requests := strings.Join(fleet.GitHub().Requests(), "\n")
	require(strings.Contains(requests, "200 GET release-assets.githubusercontent.com"), "no host downloaded the release from GitHub's asset host:\n%s", requests)
	require(strings.Contains(requests, "200 GET api.github.com/repos/TerraScale/ts-orchestrator/compare/"+from+"..."+sha) || strings.Contains(requests, "200 GET api.github.com/repos/TerraScale/ts-orchestrator/compare/"+sha+"..."+from), "the installed updater never checked the release's lineage:\n%s", requests)
	step("%s installed %s on both %s hosts through discovery, lineage, provenance, preflight and probation; each keeps %s as its rollback target", from, tag, workerRegion, from)
}

func main() {
	if oraclehost.Main() {
		return
	}
	require(len(os.Args) == 7 && (os.Args[2] == "previous" || os.Args[2] == "next") && (os.Args[1] == "fetch" || os.Args[1] == "run"),
		"usage: upgrade-gate fetch previous|next <candidate> <work> <lineage sha> <lane dir> | upgrade-gate run previous|next <candidate> <work> <run id> <lane dir>")
	mode, candidate, work := os.Args[2], os.Args[3], os.Args[4]
	if os.Args[1] == "fetch" {
		fetch(mode, candidate, work, os.Args[5], os.Args[6])
		return
	}
	run, err := strconv.ParseUint(os.Args[5], 10, 64)
	must(err)
	journey(mode, candidate, work, run, os.Args[6])
}
