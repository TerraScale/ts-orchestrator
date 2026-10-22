package regionhost

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const defaultShape = "VM.Standard.A1.Flex"

// machine is a launch shape and its size.
type machine struct {
	shape       string
	ocpus, gb   float32
	arch, image string // arch is arm64 or amd64; image is the Ubuntu name filter
}

// sized is today's host (A1 2 OCPU/12 GB) or, with --shape, that shape's
// smallest host.
func sized(shape string) machine {
	m := machine{shape: shape, ocpus: 1, gb: 8, arch: "amd64"}
	if shape == "" {
		m = machine{shape: defaultShape, ocpus: 2, gb: 12}
	}
	if regexp.MustCompile(`\.A\d+\.`).MatchString(m.shape) { // Ampere A1/A2/A4
		m.arch = "arm64"
		if shape != "" {
			m.gb = 6
		}
	}
	return m
}

// live drops terminated and terminating instances.
func live(items []core.Instance) []core.Instance {
	return slices.DeleteFunc(items, func(i core.Instance) bool {
		return i.LifecycleState == core.InstanceLifecycleStateTerminated || i.LifecycleState == core.InstanceLifecycleStateTerminating
	})
}

// pick is the instance named name, or with name "" the region host: the
// oldest live instance, so gru-1-ctl-1 is adopted and no duplicate launched.
func pick(items []core.Instance, name string) (*core.Instance, error) {
	items = live(items)
	if name == "" {
		if len(items) == 0 {
			return nil, nil
		}
		oldest := slices.MinFunc(items, func(a, b core.Instance) int { return a.TimeCreated.Compare(b.TimeCreated.Time) })
		return &oldest, nil
	}
	items = slices.DeleteFunc(items, func(i core.Instance) bool { return deref(i.DisplayName) != name })
	if len(items) > 1 {
		return nil, fmt.Errorf("%d live instances named %s", len(items), name)
	}
	if len(items) == 0 {
		return nil, nil
	}
	return &items[0], nil
}

func (r *run) instances() ([]core.Instance, error) {
	var all []core.Instance
	req := core.ListInstancesRequest{CompartmentId: &r.compartment}
	for {
		page, err := r.compute.ListInstances(r.ctx, req)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.OpcNextPage == nil {
			return all, nil
		}
		req.Page = page.OpcNextPage
	}
}

// ensureInstance adopts or launches the host and returns it.
func (r *run) ensureInstance(host, shape string) (*core.Instance, error) {
	items, err := r.instances()
	if err != nil {
		return nil, err
	}
	found, err := pick(items, host)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, r.report("unchanged", "instance", deref(found.DisplayName), deref(found.Id))
	}
	if host == "" {
		host = "ts-" + r.code + "-1"
	}
	launched, err := r.launch(host, sized(shape))
	if err != nil {
		return nil, err
	}
	if launched == nil { // dry run
		return nil, r.report("created", "instance", host, "-")
	}
	return launched, r.report("created", "instance", host, deref(launched.Id))
}

func (r *run) launch(name string, m machine) (*core.Instance, error) {
	images, err := r.compute.ListImages(r.ctx, core.ListImagesRequest{CompartmentId: &r.compartment, OperatingSystem: new("Canonical Ubuntu"),
		OperatingSystemVersion: new("24.04"), Shape: &m.shape, SortBy: core.ListImagesSortByTimecreated, SortOrder: core.ListImagesSortOrderDesc})
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(images.Items, func(i core.Image) bool {
		n := deref(i.DisplayName)
		return strings.Contains(n, "aarch64") == (m.arch == "arm64") && !strings.Contains(n, "Minimal")
	})
	if i < 0 {
		return nil, fmt.Errorf("no Ubuntu 24.04 %s image for %s", m.arch, m.shape)
	}
	subnet, err := r.subnet()
	if err != nil {
		return nil, err
	}
	groups, err := r.net.ListNetworkSecurityGroups(r.ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: &r.compartment,
		LifecycleState: core.NetworkSecurityGroupLifecycleStateAvailable})
	if err != nil {
		return nil, err
	}
	var nsgs []string
	for _, g := range groups.Items {
		if strings.HasPrefix(deref(g.DisplayName), r.cell+"-") {
			nsgs = append(nsgs, *g.Id)
		}
	}
	url, sum, err := newestRelease(r.ctx, m.arch)
	if err != nil {
		return nil, err
	}
	script, err := userData(m1.Files, url, sum)
	if err != nil {
		return nil, err
	}
	ads, err := r.ids.ListAvailabilityDomains(r.ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &r.tenancy})
	if err != nil || r.dry { // a dry run checks every lookup, then launches nothing
		return nil, err
	}
	// Out of host capacity in one AD: try the next, at most twice.
	var launched core.LaunchInstanceResponse
	for n, ad := range ads.Items {
		if n == 2 {
			break
		}
		launched, err = r.compute.LaunchInstance(r.ctx, core.LaunchInstanceRequest{LaunchInstanceDetails: core.LaunchInstanceDetails{
			AvailabilityDomain: ad.Name, CompartmentId: &r.compartment, DisplayName: &name, Shape: &m.shape,
			ShapeConfig:   &core.LaunchInstanceShapeConfigDetails{Ocpus: &m.ocpus, MemoryInGBs: &m.gb},
			SourceDetails: core.InstanceSourceViaImageDetails{ImageId: images.Items[i].Id, BootVolumeSizeInGBs: new(int64(50))},
			CreateVnicDetails: &core.CreateVnicDetails{SubnetId: &subnet, AssignPublicIp: new(true), NsgIds: nsgs,
				HostnameLabel: &name},
			Metadata: map[string]string{"user_data": base64.StdEncoding.EncodeToString([]byte(script))},
		}})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("launch %s: %w", name, err)
	}
	inst := launched.Instance
	return &inst, poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
		g, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: inst.Id})
		inst = g.Instance
		return g.LifecycleState == core.InstanceLifecycleStateRunning, err
	})
}

// newestRelease is the newest CI release's ts-orch asset for arch and its
// sha256, as install.sh takes them.
func newestRelease(ctx context.Context, arch string) (url, sum string, err error) {
	const repo = "TerraScale/ts-orchestrator"
	tag, err := exec.CommandContext(ctx, "gh", "release", "list", "--repo", repo, "--exclude-drafts", "-L", "1", "--json", "tagName", "--jq", ".[0].tagName").Output()
	if err != nil {
		return "", "", fmt.Errorf("gh release list: %w", err)
	}
	data, err := exec.CommandContext(ctx, "gh", "release", "view", strings.TrimSpace(string(tag)), "--repo", repo, "--json", "assets").Output()
	if err != nil {
		return "", "", fmt.Errorf("gh release view: %w", err)
	}
	var release struct {
		Assets []struct{ Name, Digest, URL string }
	}
	if err := json.Unmarshal(data, &release, json.MatchCaseInsensitiveNames(true)); err != nil {
		return "", "", err
	}
	for _, a := range release.Assets {
		if a.Name == "terrascale-orchestrator-linux-"+arch {
			return a.URL, strings.TrimPrefix(a.Digest, "sha256:"), nil
		}
	}
	return "", "", errors.New("newest CI release has no terrascale-orchestrator-linux-" + arch)
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
