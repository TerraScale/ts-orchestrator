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

// live is a copy of items without terminated and terminating instances; the
// caller's slice stays intact (DeleteFunc zeroes the elements it drops).
func live(items []core.Instance) []core.Instance {
	return slices.DeleteFunc(slices.Clone(items), func(i core.Instance) bool {
		return i.LifecycleState == core.InstanceLifecycleStateTerminated || i.LifecycleState == core.InstanceLifecycleStateTerminating
	})
}

func pick(items []core.Instance, name string) (*core.Instance, error) {
	return pickFrom(live(items), name)
}

func pickFrom(items []core.Instance, name string) (*core.Instance, error) {
	items = slices.Clone(items)
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

func (r *run) ensureInstance(host, shape string) (*core.Instance, *core.Volume, error) {
	items, err := r.instances()
	if err != nil {
		return nil, nil, err
	}
	if err := r.finishTerminating(items, host); err != nil {
		return nil, nil, err
	}
	found, err := pick(items, host)
	if err != nil {
		return nil, nil, err
	}
	if found != nil {
		if found.LifecycleState == core.InstanceLifecycleStateStopped || found.LifecycleState == core.InstanceLifecycleStateStopping {
			return nil, nil, fmt.Errorf("host %s is %s; finish or abandon the removal before add", deref(found.Id), found.LifecycleState)
		}
		name := deref(found.DisplayName)
		volume, err := r.dataVolume(name)
		if err != nil {
			return nil, nil, err
		}
		if found.Metadata[dataFormatTag] == "true" && (volume == nil || found.Metadata[dataVolumeTag] != deref(volume.Id) || volume.FreeformTags[dataFormattedTag] != "yes" || !filesystemUUID.MatchString(volume.FreeformTags[dataUUIDTag])) {
			if r.dry {
				return nil, nil, fmt.Errorf("unfinished formatting instance %s must be terminated and replaced", deref(found.Id))
			}
			if err := r.stopInstance(found); err != nil {
				return nil, nil, err
			}
			bound := &core.Volume{Id: new(found.Metadata[dataVolumeTag])}
			if deref(bound.Id) != "" {
				attachment, err := r.dataAttachment(found, bound)
				if err != nil {
					return nil, nil, err
				}
				if attachment != nil {
					if err := r.detachDataVolume(found, bound); err != nil {
						return nil, nil, err
					}
				}
			}
			if err := r.terminateInstance(found); err != nil {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("terminated unfinished formatting instance %s; inspect volume %s (discovered %s) and set initialised tag and UUID before a new add", deref(found.Id), found.Metadata[dataVolumeTag], volumeID(volume))
		}
		if volume == nil || found.Metadata[dataVolumeTag] != deref(volume.Id) {
			return nil, nil, fmt.Errorf("instance %s launched for volume %s; refusing discovered volume %s", deref(found.Id), found.Metadata[dataVolumeTag], volumeID(volume))
		}
		if volume.FreeformTags[dataFormattedTag] != "yes" || !filesystemUUID.MatchString(volume.FreeformTags[dataUUIDTag]) {
			return nil, nil, fmt.Errorf("existing volume %s requires the terrascale-data-formatted tag and terrascale-data-uuid after inspection", deref(volume.Id))
		}
		if deref(volume.AvailabilityDomain) != deref(found.AvailabilityDomain) {
			return nil, nil, errors.New("host and data volume availability domains differ")
		}
		volume, err = r.ensureDataVolume(name, deref(found.AvailabilityDomain), volume)
		if err != nil {
			return nil, nil, err
		}
		if err := r.attachDataVolume(name, found, volume); err != nil {
			return nil, nil, err
		}
		return found, volume, r.report("unchanged", "instance", name, deref(found.Id))
	}
	if host == "" {
		host = "ts-" + r.code + "-1"
	}
	launched, volume, err := r.launch(host, sized(shape), live(items))
	if err != nil {
		return nil, nil, err
	}
	if launched == nil {
		return nil, nil, r.report("created", "instance", host, "-")
	}
	return launched, volume, r.report("created", "instance", host, deref(launched.Id))
}

// spread is where a new host may go beside the region's live hosts: their
// oldest host's availability domain and every fault domain none of them uses
// (PIVOT D16: an in-region ack lands on 2 fault domains), in order; the
// launch tries the next one when OCI is out of host capacity. With no live
// host any domain does; with every fault domain taken it is an error.
func spread(hosts []core.Instance, faultDomains func(ad string) ([]string, error)) (ad string, free []string, err error) {
	if len(hosts) == 0 {
		return "", nil, nil
	}
	oldest := slices.MinFunc(hosts, func(a, b core.Instance) int { return a.TimeCreated.Compare(b.TimeCreated.Time) })
	ad = deref(oldest.AvailabilityDomain)
	names, err := faultDomains(ad)
	if err != nil {
		return "", nil, err
	}
	for _, name := range names {
		if !slices.ContainsFunc(hosts, func(h core.Instance) bool {
			return deref(h.AvailabilityDomain) == ad && deref(h.FaultDomain) == name
		}) {
			free = append(free, name)
		}
	}
	if len(free) == 0 {
		return "", nil, fmt.Errorf("every fault domain of %s already holds a host of this region", ad)
	}
	return ad, free, nil
}

func (r *run) faultDomains(ad string) ([]string, error) {
	list, err := r.ids.ListFaultDomains(r.ctx, identity.ListFaultDomainsRequest{CompartmentId: &r.tenancy, AvailabilityDomain: &ad})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list.Items))
	for _, f := range list.Items {
		names = append(names, deref(f.Name))
	}
	slices.Sort(names)
	return names, nil
}

func (r *run) launch(name string, m machine, hosts []core.Instance) (*core.Instance, *core.Volume, error) {
	images, err := r.compute.ListImages(r.ctx, core.ListImagesRequest{CompartmentId: &r.compartment, OperatingSystem: new("Canonical Ubuntu"),
		OperatingSystemVersion: new("24.04"), Shape: &m.shape, SortBy: core.ListImagesSortByTimecreated, SortOrder: core.ListImagesSortOrderDesc})
	if err != nil {
		return nil, nil, err
	}
	i := slices.IndexFunc(images.Items, func(i core.Image) bool {
		n := deref(i.DisplayName)
		return strings.Contains(n, "aarch64") == (m.arch == "arm64") && !strings.Contains(n, "Minimal")
	})
	if i < 0 {
		return nil, nil, fmt.Errorf("no Ubuntu 24.04 %s image for %s", m.arch, m.shape)
	}
	subnet, err := r.subnet()
	if err != nil {
		return nil, nil, err
	}
	groups, err := r.net.ListNetworkSecurityGroups(r.ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: &r.compartment,
		LifecycleState: core.NetworkSecurityGroupLifecycleStateAvailable})
	if err != nil {
		return nil, nil, err
	}
	var nsgs []string
	for _, g := range groups.Items {
		if strings.HasPrefix(deref(g.DisplayName), r.cell+"-") {
			nsgs = append(nsgs, *g.Id)
		}
	}
	url, sum, err := newestRelease(r.ctx, m.arch)
	if err != nil {
		return nil, nil, err
	}
	ads, err := r.ids.ListAvailabilityDomains(r.ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &r.tenancy})
	if err != nil {
		return nil, nil, err
	}
	var ad string
	var free []string
	volume, err := r.dataVolume(name)
	if err != nil {
		return nil, nil, err
	}
	if volume == nil {
		ad, free, err = spread(hosts, r.faultDomains)
		if err != nil {
			return nil, nil, err
		}
	} else {
		if volume.FreeformTags[dataFormattedTag] != "yes" || !filesystemUUID.MatchString(volume.FreeformTags[dataUUIDTag]) {
			return nil, nil, errors.New("existing data volume requires the terrascale-data-formatted tag and terrascale-data-uuid before attachment; verify restored or interrupted provisioning data first")
		}
		ad = deref(volume.AvailabilityDomain)
		free, err = r.faultDomains(ad)
		if err != nil {
			return nil, nil, err
		}
		free = slices.DeleteFunc(free, func(fd string) bool {
			return slices.ContainsFunc(hosts, func(h core.Instance) bool {
				return deref(h.AvailabilityDomain) == ad && deref(h.FaultDomain) == fd
			})
		})
		if len(free) == 0 {
			return nil, nil, errors.New("no free fault domain in the retained data volume's availability domain")
		}
		if _, err := r.dataAttachment(nil, volume); err != nil {
			return nil, nil, err
		}
	}
	type place struct{ ad, fd *string }
	var places []place
	for _, fd := range free {
		places = append(places, place{&ad, &fd})
	}
	if ad == "" {
		for _, a := range ads.Items[:min(2, len(ads.Items))] {
			places = append(places, place{a.Name, nil})
		}
	}
	if len(places) == 0 {
		return nil, nil, errors.New("no availability domain for host")
	}
	if r.dry {
		volume, err = r.ensureDataVolume(name, deref(places[0].ad), volume)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, r.attachDataVolume(name, nil, volume)
	}
	volume, err = r.ensureDataVolume(name, deref(places[0].ad), volume)
	if err != nil {
		return nil, nil, err
	}
	var launched core.LaunchInstanceResponse
	for _, at := range places {
		if deref(volume.AvailabilityDomain) != deref(at.ad) {
			continue
		}
		mayFormat := r.createdVolumes[deref(volume.Id)]
		script, scriptErr := CloudInit(m1.Files, url, sum, deref(volume.Id), volume.FreeformTags[dataUUIDTag], volume.FreeformTags[dataSerialTag], mayFormat)
		if scriptErr != nil {
			return nil, nil, scriptErr
		}
		permission := "false"
		if mayFormat {
			permission = "true"
		}
		launched, err = r.compute.LaunchInstance(r.ctx, core.LaunchInstanceRequest{LaunchInstanceDetails: core.LaunchInstanceDetails{
			AvailabilityDomain: at.ad, FaultDomain: at.fd, CompartmentId: &r.compartment, DisplayName: &name, Shape: &m.shape,
			ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: &m.ocpus, MemoryInGBs: &m.gb},
			SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: images.Items[i].Id, BootVolumeSizeInGBs: new(int64(50))},
			CreateVnicDetails: &core.CreateVnicDetails{SubnetId: &subnet, AssignPublicIp: new(true), NsgIds: nsgs, HostnameLabel: &name},
			Metadata:          map[string]string{"user_data": base64.StdEncoding.EncodeToString([]byte(script)), dataVolumeTag: deref(volume.Id), dataFormatTag: permission},
		}})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("launch %s: %w", name, err)
	}
	inst := launched.Instance
	if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
		g, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: inst.Id})
		inst = g.Instance
		return g.LifecycleState == core.InstanceLifecycleStateRunning, err
	}); err != nil {
		return nil, nil, err
	}
	if err := r.bindDataVolume(&inst, volume); err != nil {
		return nil, nil, err
	}
	return &inst, volume, r.attachDataVolume(name, &inst, volume)
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

func volumeID(volume *core.Volume) string {
	if volume == nil {
		return "<missing>"
	}
	return deref(volume.Id)
}
