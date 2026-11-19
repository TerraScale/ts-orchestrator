package compute

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	dataDevice      = "/dev/oracleoci/oraclevdb"
	boundInstance   = "terrascale-data-instance"
	filesystemTag   = "terrascale-data-uuid"
	settleInterval  = 15 * time.Second
	settleAttempts  = 80
	runningInstance = "Running"
)

type Clients struct {
	Compute    core.ComputeClient
	Management core.ComputeManagementClient
	Storage    core.BlockstorageClient
}

type Place struct {
	AvailabilityDomain string
	FaultDomains       []string
}

type Launch struct {
	ImageID  string
	Metadata map[string]string
}

type Nodes struct {
	Label         string
	Compartment   string
	Shape         string
	OCPUs         float32
	MemoryGB      float32
	BootGB        int64
	DataGB        int64
	DataVPUsPerGB int64
	External      []string
	Min, Max      int
	SubnetID      string
	NSGID         string
	Places        []Place
	Key           func(kind, name string) ociresource.Key
	Launch        func(context.Context) (Launch, error)
}

type Pass struct {
	Clients
	Nodes
	Ownership ociresource.Ownership
	Out       ociresource.Out
}

func (p Pass) tags(kind, name string) map[string]string {
	return p.Ownership.Stamp(p.Key(kind, name), 1, "").Freeform
}

func (p Pass) owns(kind, name string, tags map[string]string) bool {
	return p.Ownership.Owns(p.Key(kind, name), ociresource.Tags{Freeform: tags})
}

func (p Pass) say(verb, kind, name, detail string) {
	w := p.Out.Changed
	if verb == "unchanged" || verb == "kept" {
		w = p.Out.Same
	}
	fmt.Fprintf(w, "%-9s %s %s\n", verb, p.Key(kind, name), detail)
}

func (p Pass) Run(ctx context.Context) error {
	slots, err := p.dataVolumes(ctx)
	if err != nil {
		return err
	}
	configuration, stale, err := p.configuration(ctx)
	if err != nil {
		return err
	}
	pool, err := p.pool(ctx, configuration)
	if err != nil {
		return err
	}
	for _, id := range stale {
		if _, err := p.Management.DeleteInstanceConfiguration(ctx, core.DeleteInstanceConfigurationRequest{InstanceConfigurationId: &id}); err != nil {
			return fmt.Errorf("delete replaced instance configuration %s: %w", id, err)
		}
		p.say("deleted", "instance-configuration", "node", id)
	}
	instances, err := p.settle(ctx, pool)
	if err != nil {
		return err
	}
	return p.volumes(ctx, instances, slots)
}

func (p Pass) configuration(ctx context.Context) (string, []string, error) {
	summaries, err := all(func(page *string) ([]core.InstanceConfigurationSummary, *string, error) {
		r, err := p.Management.ListInstanceConfigurations(ctx, core.ListInstanceConfigurationsRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return "", nil, fmt.Errorf("list instance configurations: %w", err)
	}
	launch, err := p.Launch(ctx)
	if err != nil {
		return "", nil, err
	}
	var current string
	var stale []string
	for _, summary := range summaries {
		if !p.owns("instance-configuration", "node", summary.FreeformTags) {
			continue
		}
		got, err := p.Management.GetInstanceConfiguration(ctx, core.GetInstanceConfigurationRequest{InstanceConfigurationId: summary.Id})
		if err != nil {
			return "", nil, err
		}
		if current == "" && p.matches(got.InstanceConfiguration, launch) {
			current = *summary.Id
			continue
		}
		stale = append(stale, *summary.Id)
	}
	if current != "" {
		p.say("unchanged", "instance-configuration", "node", current)
		return current, stale, nil
	}
	created, err := p.Management.CreateInstanceConfiguration(ctx, core.CreateInstanceConfigurationRequest{
		CreateInstanceConfiguration: core.CreateInstanceConfigurationDetails{
			CompartmentId: &p.Compartment, DisplayName: common.String(p.Label + "-node"), FreeformTags: p.tags("instance-configuration", "node"),
			InstanceDetails: core.ComputeInstanceDetails{LaunchDetails: &core.InstanceConfigurationLaunchInstanceDetails{
				CompartmentId: &p.Compartment, Shape: &p.Shape,
				ShapeConfig:       &core.InstanceConfigurationLaunchInstanceShapeConfigDetails{Ocpus: &p.OCPUs, MemoryInGBs: &p.MemoryGB},
				SourceDetails:     core.InstanceConfigurationInstanceSourceViaImageDetails{ImageId: &launch.ImageID, BootVolumeSizeInGBs: &p.BootGB},
				CreateVnicDetails: &core.InstanceConfigurationCreateVnicDetails{SubnetId: &p.SubnetID, AssignPublicIp: common.Bool(false), NsgIds: []string{p.NSGID}},
				Metadata:          launch.Metadata,
				FreeformTags:      p.tags("instance", "node"),
			}},
		},
		OpcRetryToken: common.String(uuid.New().String()),
	})
	if err != nil {
		return "", nil, fmt.Errorf("create instance configuration: %w", err)
	}
	p.say("created", "instance-configuration", "node", *created.Id+" image "+launch.ImageID)
	return *created.Id, stale, nil
}

func (p Pass) matches(configuration core.InstanceConfiguration, want Launch) bool {
	details, ok := configuration.InstanceDetails.(core.ComputeInstanceDetails)
	if !ok || details.LaunchDetails == nil {
		return false
	}
	launch := details.LaunchDetails
	source, ok := launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails)
	vnic := launch.CreateVnicDetails
	return ok && deref(source.ImageId) == want.ImageID && maps.Equal(launch.Metadata, want.Metadata) &&
		deref(launch.Shape) == p.Shape && launch.ShapeConfig != nil &&
		deref(launch.ShapeConfig.Ocpus) == p.OCPUs && deref(launch.ShapeConfig.MemoryInGBs) == p.MemoryGB &&
		deref(source.BootVolumeSizeInGBs) == p.BootGB && vnic != nil && deref(vnic.SubnetId) == p.SubnetID &&
		vnic.AssignPublicIp != nil && !*vnic.AssignPublicIp && slices.Equal(vnic.NsgIds, []string{p.NSGID})
}

func (p Pass) owned(ctx context.Context) ([]core.InstancePoolSummary, error) {
	summaries, err := all(func(page *string) ([]core.InstancePoolSummary, *string, error) {
		r, err := p.Management.ListInstancePools(ctx, core.ListInstancePoolsRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, fmt.Errorf("list instance pools: %w", err)
	}
	summaries = slices.DeleteFunc(summaries, func(s core.InstancePoolSummary) bool {
		return s.LifecycleState == core.InstancePoolSummaryLifecycleStateTerminated ||
			s.LifecycleState == core.InstancePoolSummaryLifecycleStateTerminating || !p.owns("instance-pool", "nodes", s.FreeformTags)
	})
	if len(summaries) > 1 {
		return nil, fmt.Errorf("%d instance pools carry %s; remove all but one by hand", len(summaries), p.Key("instance-pool", "nodes"))
	}
	return summaries, nil
}

type Pool struct {
	core.InstancePool
	Members []core.InstanceSummary
	Strays  []string
}

func (p Pass) Pool(ctx context.Context) (Pool, bool, error) {
	summaries, err := p.owned(ctx)
	if err != nil || len(summaries) == 0 {
		return Pool{}, false, err
	}
	got, err := p.Management.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: summaries[0].Id})
	if err != nil {
		return Pool{}, false, err
	}
	members, err := p.members(ctx, got.InstancePool)
	if err != nil {
		return Pool{}, false, err
	}
	instances, err := all(func(page *string) ([]core.Instance, *string, error) {
		r, err := p.Compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return Pool{}, false, fmt.Errorf("list instances: %w", err)
	}
	pool := Pool{InstancePool: got.InstancePool, Members: members}
	for _, instance := range instances {
		if instance.LifecycleState != core.InstanceLifecycleStateTerminated && instance.LifecycleState != core.InstanceLifecycleStateTerminating &&
			p.owns("instance", "node", instance.FreeformTags) && !slices.ContainsFunc(members, func(m core.InstanceSummary) bool { return deref(m.Id) == deref(instance.Id) }) {
			pool.Strays = append(pool.Strays, deref(instance.Id))
		}
	}
	slices.Sort(pool.Strays)
	return pool, true, nil
}

func (p Pass) Resize(ctx context.Context, pool Pool, size int) error {
	if _, err := p.Management.UpdateInstancePool(ctx, core.UpdateInstancePoolRequest{InstancePoolId: pool.Id,
		UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{Size: common.Int(size)}}); err != nil {
		return fmt.Errorf("resize instance pool %s to %d: %w", *pool.Id, size, err)
	}
	return nil
}

func (p Pass) pool(ctx context.Context, configuration string) (core.InstancePool, error) {
	summaries, err := p.owned(ctx)
	if err != nil {
		return core.InstancePool{}, err
	}
	if len(summaries) == 0 {
		var places []core.CreateInstancePoolPlacementConfigurationDetails
		for _, place := range p.Places {
			places = append(places, core.CreateInstancePoolPlacementConfigurationDetails{
				AvailabilityDomain: common.String(place.AvailabilityDomain), FaultDomains: place.FaultDomains, PrimarySubnetId: &p.SubnetID})
		}
		created, err := p.Management.CreateInstancePool(ctx, core.CreateInstancePoolRequest{CreateInstancePoolDetails: core.CreateInstancePoolDetails{
			CompartmentId: &p.Compartment, InstanceConfigurationId: &configuration, PlacementConfigurations: places, Size: common.Int(p.Min),
			DisplayName: common.String(p.Label + "-nodes"), FreeformTags: p.tags("instance-pool", "nodes"),
			InstanceDisplayNameFormatter: common.String(p.Label + "-node-${launchCount}"), InstanceHostnameFormatter: common.String(p.Label + "-node-${launchCount}"),
		}, OpcRetryToken: common.String(uuid.New().String())})
		if err != nil {
			return core.InstancePool{}, fmt.Errorf("create instance pool: %w", err)
		}
		p.say("created", "instance-pool", "nodes", fmt.Sprintf("%s size %d across %d availability domains", *created.Id, p.Min, len(places)))
		return created.InstancePool, nil
	}
	got, err := p.Management.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: summaries[0].Id})
	if err != nil {
		return core.InstancePool{}, err
	}
	pool := got.InstancePool
	update := core.UpdateInstancePoolDetails{}
	var changes []string
	if deref(pool.InstanceConfigurationId) != configuration {
		update.InstanceConfigurationId = &configuration
		changes = append(changes, "instance configuration "+configuration+" for new nodes")
	}
	if deref(pool.Size) < p.Min {
		update.Size = common.Int(p.Min)
		changes = append(changes, fmt.Sprintf("size %d -> %d", deref(pool.Size), p.Min))
	}
	if len(changes) == 0 {
		p.say("unchanged", "instance-pool", "nodes", fmt.Sprintf("%s size %d", *pool.Id, deref(pool.Size)))
		return pool, nil
	}
	if _, err := p.settle(ctx, pool); err != nil {
		return core.InstancePool{}, err
	}
	updated, err := p.Management.UpdateInstancePool(ctx, core.UpdateInstancePoolRequest{InstancePoolId: pool.Id, UpdateInstancePoolDetails: update})
	if err != nil {
		return core.InstancePool{}, fmt.Errorf("update instance pool: %w", err)
	}
	p.say("updated", "instance-pool", "nodes", *pool.Id+" "+strings.Join(changes, ", "))
	return updated.InstancePool, nil
}

func (p Pass) settle(ctx context.Context, pool core.InstancePool) ([]core.InstanceSummary, error) {
	var state string
	for range settleAttempts {
		got, err := p.Management.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: pool.Id})
		if err != nil {
			return nil, err
		}
		instances, err := p.members(ctx, pool)
		if err != nil {
			return nil, err
		}
		running := !slices.ContainsFunc(instances, func(i core.InstanceSummary) bool { return deref(i.State) != runningInstance })
		if got.LifecycleState == core.InstancePoolLifecycleStateRunning && running && len(instances) == deref(got.Size) {
			return instances, nil
		}
		state = fmt.Sprintf("%s with %d of %d instances running", got.LifecycleState, len(instances), deref(got.Size))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(settleInterval):
		}
	}
	return nil, fmt.Errorf("instance pool %s did not settle in %s: %s; nothing else changed", *pool.Id, settleInterval*settleAttempts, state)
}

func (p Pass) members(ctx context.Context, pool core.InstancePool) ([]core.InstanceSummary, error) {
	return all(func(page *string) ([]core.InstanceSummary, *string, error) {
		r, err := p.Management.ListInstancePoolInstances(ctx, core.ListInstancePoolInstancesRequest{CompartmentId: &p.Compartment, InstancePoolId: pool.Id, Page: page})
		return r.Items, r.OpcNextPage, err
	})
}

func (p Pass) Retire(ctx context.Context, pool Pool, instanceID string) error {
	got, err := p.Compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: &instanceID})
	if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if got.LifecycleState == core.InstanceLifecycleStateTerminated || got.LifecycleState == core.InstanceLifecycleStateTerminating {
		return nil
	}
	if !p.owns("instance", "node", got.FreeformTags) {
		return fmt.Errorf("instance %s lacks %s; refusing to remove it", instanceID, p.Key("instance", "node"))
	}
	if slices.ContainsFunc(pool.Members, func(i core.InstanceSummary) bool { return deref(i.Id) == instanceID }) {
		if _, err := p.Management.DetachInstancePoolInstance(ctx, core.DetachInstancePoolInstanceRequest{InstancePoolId: pool.Id,
			DetachInstancePoolInstanceDetails: core.DetachInstancePoolInstanceDetails{InstanceId: &instanceID, IsDecrementSize: common.Bool(true), IsAutoTerminate: common.Bool(false)}}); err != nil {
			return fmt.Errorf("detach %s from the pool: %w", instanceID, err)
		}
		if err := waitFor(ctx, func() (bool, error) {
			members, err := p.members(ctx, pool.InstancePool)
			return !slices.ContainsFunc(members, func(i core.InstanceSummary) bool { return deref(i.Id) == instanceID }), err
		}); err != nil {
			return fmt.Errorf("detach %s from the pool: %w", instanceID, err)
		}
	}
	if got.LifecycleState != core.InstanceLifecycleStateStopped {
		if got.LifecycleState != core.InstanceLifecycleStateStopping {
			if _, err := p.Compute.InstanceAction(ctx, core.InstanceActionRequest{InstanceId: &instanceID, Action: core.InstanceActionActionSoftstop}); err != nil {
				return fmt.Errorf("stop %s: %w", instanceID, err)
			}
		}
		if err := waitFor(ctx, func() (bool, error) {
			got, err := p.Compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: &instanceID})
			return got.LifecycleState == core.InstanceLifecycleStateStopped, err
		}); err != nil {
			return fmt.Errorf("stop %s: %w", instanceID, err)
		}
	}
	attachments, err := p.attachments(ctx)
	if err != nil {
		return err
	}
	for _, attachment := range attachments {
		if deref(attachment.GetInstanceId()) != instanceID {
			continue
		}
		if _, err := p.Compute.DetachVolume(ctx, core.DetachVolumeRequest{VolumeAttachmentId: attachment.GetId()}); err != nil {
			return fmt.Errorf("detach data volume from %s: %w", instanceID, err)
		}
		if err := waitFor(ctx, func() (bool, error) {
			got, err := p.Compute.GetVolumeAttachment(ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: attachment.GetId()})
			return got.VolumeAttachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateDetached, err
		}); err != nil {
			return err
		}
	}
	if _, err := p.Compute.TerminateInstance(ctx, core.TerminateInstanceRequest{InstanceId: &instanceID,
		PreserveBootVolume: common.Bool(false), PreserveDataVolumesCreatedAtLaunch: common.Bool(true)}); err != nil {
		return fmt.Errorf("terminate %s: %w", instanceID, err)
	}
	return nil
}

func (p Pass) attachments(ctx context.Context) ([]core.VolumeAttachment, error) {
	attachments, err := all(func(page *string) ([]core.VolumeAttachment, *string, error) {
		r, err := p.Compute.ListVolumeAttachments(ctx, core.ListVolumeAttachmentsRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	return slices.DeleteFunc(attachments, func(a core.VolumeAttachment) bool {
		state := a.GetLifecycleState()
		return state != core.VolumeAttachmentLifecycleStateAttached && state != core.VolumeAttachmentLifecycleStateAttaching
	}), err
}

type slot struct {
	name   string
	volume core.Volume
}

func (p Pass) dataVolumes(ctx context.Context) (map[string]core.Volume, error) {
	listed, err := all(func(page *string) ([]core.Volume, *string, error) {
		r, err := p.Storage.ListVolumes(ctx, core.ListVolumesRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	slots := map[string]core.Volume{}
	for n := 1; n <= p.Max+len(listed); n++ {
		name := fmt.Sprintf("data-%d", n)
		for _, volume := range listed {
			if volume.LifecycleState != core.VolumeLifecycleStateTerminated && volume.LifecycleState != core.VolumeLifecycleStateTerminating && p.owns("volume", name, volume.FreeformTags) {
				if err := p.checkSize(name, volume); err != nil {
					return nil, err
				}
				slots[name] = volume
			}
		}
	}
	for _, host := range p.External {
		name := "external-" + host
		for _, volume := range listed {
			if volume.LifecycleState == core.VolumeLifecycleStateTerminated || volume.LifecycleState == core.VolumeLifecycleStateTerminating || !p.ownsData(name, volume.FreeformTags) {
				continue
			}
			if _, duplicate := slots[name]; duplicate {
				return nil, fmt.Errorf("external host %s has multiple data volumes", host)
			}
			if err := p.checkSize(name, volume); err != nil {
				return nil, err
			}
			slots[name] = volume
		}
		if _, found := slots[name]; !found {
			return nil, fmt.Errorf("external host %s has no owned data volume", host)
		}
	}
	return slots, nil
}

func (p Pass) ownsData(name string, tags map[string]string) bool {
	if host, external := strings.CutPrefix(name, "external-"); external {
		return slices.Contains(p.External, host) && tags["terrascale-managed-by"] == "ts-orchestrator" &&
			tags["terrascale-resource"] == "data-volume" && tags["terrascale-host"] == host
	}
	return p.owns("volume", name, tags)
}

func (p Pass) volumes(ctx context.Context, instances []core.InstanceSummary, slots map[string]core.Volume) error {
	attachments, err := p.attachments(ctx)
	if err != nil {
		return err
	}
	attachedTo := map[string]string{}
	for _, attachment := range attachments {
		attachedTo[deref(attachment.GetVolumeId())] = deref(attachment.GetInstanceId())
	}
	if err := p.growExternal(ctx, slots, attachments); err != nil {
		return err
	}
	slices.SortFunc(instances, func(a, b core.InstanceSummary) int { return cmp.Compare(*a.Id, *b.Id) })
	for _, instance := range instances {
		got, err := p.Compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		if err != nil {
			return err
		}
		current := got.Instance
		if !p.owns("instance", "node", current.FreeformTags) {
			return fmt.Errorf("pool instance %s lacks %s", *instance.Id, p.Key("instance", "node"))
		}
		chosen, attached := p.pick(slots, attachedTo, current)
		if chosen.name != "" {
			if chosen, err = p.grow(ctx, chosen); err != nil {
				return err
			}
			slots[chosen.name] = chosen.volume
		}
		if !attached {
			if chosen.name == "" {
				if chosen, err = p.create(ctx, slots, current); err != nil {
					return err
				}
				slots[chosen.name] = chosen.volume
			}
			if err := p.attach(ctx, current, chosen); err != nil {
				return err
			}
			attachedTo[*chosen.volume.Id] = *current.Id
		}
		if err := p.bind(ctx, current, chosen); err != nil {
			return err
		}
	}
	for name, volume := range slots {
		if _, ok := attachedTo[*volume.Id]; !ok {
			p.say("kept", "volume", name, *volume.Id+" detached in "+deref(volume.AvailabilityDomain))
		}
	}
	return nil
}

func (p Pass) checkSize(name string, volume core.Volume) error {
	if volume.SizeInGBs == nil || *volume.SizeInGBs <= 0 {
		return fmt.Errorf("%s has no observed data volume size", p.Key("volume", name))
	}
	if *volume.SizeInGBs > p.DataGB {
		return fmt.Errorf("%s is %d GB: nodes.data_gb=%d would decrease storage; data volumes cannot shrink", p.Key("volume", name), *volume.SizeInGBs, p.DataGB)
	}
	return nil
}

func (p Pass) grow(ctx context.Context, chosen slot) (slot, error) {
	got, err := p.Storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: chosen.volume.Id})
	if err != nil {
		return slot{}, fmt.Errorf("read %s before growth: %w", p.Key("volume", chosen.name), err)
	}
	volume := got.Volume
	if !p.ownsData(chosen.name, volume.FreeformTags) {
		return slot{}, fmt.Errorf("%s lost ownership before growth", p.Key("volume", chosen.name))
	}
	if strings.HasPrefix(chosen.name, "external-") && volume.FreeformTags[boundInstance] != chosen.volume.FreeformTags[boundInstance] {
		return slot{}, fmt.Errorf("%s changed its external host binding before growth", p.Key("volume", chosen.name))
	}
	if err := p.checkSize(chosen.name, volume); err != nil {
		return slot{}, err
	}
	if *volume.SizeInGBs == p.DataGB {
		return slot{chosen.name, volume}, nil
	}
	if got.Etag == nil || *got.Etag == "" || volume.LifecycleState != core.VolumeLifecycleStateAvailable {
		return slot{}, fmt.Errorf("%s needs an AVAILABLE volume with an ETag for online growth", p.Key("volume", chosen.name))
	}
	before := *volume.SizeInGBs
	if _, err := p.Storage.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: volume.Id, IfMatch: got.Etag,
		UpdateVolumeDetails: core.UpdateVolumeDetails{SizeInGBs: &p.DataGB}}); err != nil {
		return slot{}, fmt.Errorf("grow %s to %d GB: %w", p.Key("volume", chosen.name), p.DataGB, err)
	}
	if err := waitFor(ctx, func() (bool, error) {
		got, err := p.Storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: volume.Id})
		volume = got.Volume
		return volume.LifecycleState == core.VolumeLifecycleStateAvailable && volume.SizeInGBs != nil && *volume.SizeInGBs >= p.DataGB, err
	}); err != nil {
		return slot{}, fmt.Errorf("confirm growth of %s: %w", p.Key("volume", chosen.name), err)
	}
	p.say("grown", "volume", chosen.name, fmt.Sprintf("%s %d -> %d GB online", *volume.Id, before, *volume.SizeInGBs))
	return slot{chosen.name, volume}, nil
}

func (p Pass) pick(slots map[string]core.Volume, attachedTo map[string]string, instance core.Instance) (slot, bool) {
	var free slot
	for _, name := range slices.Sorted(maps.Keys(slots)) {
		if strings.HasPrefix(name, "external-") {
			continue
		}
		volume := slots[name]
		switch {
		case attachedTo[*volume.Id] == *instance.Id:
			return slot{name, volume}, true
		case free.name == "" && attachedTo[*volume.Id] == "" && volume.LifecycleState == core.VolumeLifecycleStateAvailable &&
			deref(volume.AvailabilityDomain) == deref(instance.AvailabilityDomain):
			free = slot{name, volume}
		}
	}
	return free, false
}

func (p Pass) create(ctx context.Context, slots map[string]core.Volume, instance core.Instance) (slot, error) {
	name := ""
	for n := 1; n <= p.Max && name == ""; n++ {
		if _, used := slots[fmt.Sprintf("data-%d", n)]; !used {
			name = fmt.Sprintf("data-%d", n)
		}
	}
	if name == "" {
		return slot{}, fmt.Errorf("node %s in %s has no data volume and all %d data volumes are in use or in other availability domains", *instance.Id, deref(instance.AvailabilityDomain), p.Max)
	}
	tags := p.tags("volume", name)
	tags[filesystemTag] = uuid.New().String()
	created, err := p.Storage.CreateVolume(ctx, core.CreateVolumeRequest{CreateVolumeDetails: core.CreateVolumeDetails{
		CompartmentId: &p.Compartment, AvailabilityDomain: instance.AvailabilityDomain, DisplayName: common.String(p.Label + "-" + name),
		SizeInGBs: &p.DataGB, VpusPerGB: &p.DataVPUsPerGB, FreeformTags: tags,
	}, OpcRetryToken: common.String(uuid.New().String())})
	if err != nil {
		return slot{}, fmt.Errorf("create %s: %w", p.Key("volume", name), err)
	}
	volume := created.Volume
	if err := waitFor(ctx, func() (bool, error) {
		got, err := p.Storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: volume.Id})
		volume = got.Volume
		return volume.LifecycleState == core.VolumeLifecycleStateAvailable, err
	}); err != nil {
		return slot{}, err
	}
	p.say("created", "volume", name, fmt.Sprintf("%s %d GB %d VPU/GB in %s", *volume.Id, p.DataGB, p.DataVPUsPerGB, deref(volume.AvailabilityDomain)))
	return slot{name, volume}, nil
}

func (p Pass) attach(ctx context.Context, instance core.Instance, chosen slot) error {
	attached, err := p.Compute.AttachVolume(ctx, core.AttachVolumeRequest{AttachVolumeDetails: core.AttachParavirtualizedVolumeDetails{
		InstanceId: instance.Id, VolumeId: chosen.volume.Id, Device: common.String(dataDevice), IsReadOnly: common.Bool(false), IsShareable: common.Bool(false),
	}})
	if err != nil {
		return fmt.Errorf("attach %s to %s: %w", p.Key("volume", chosen.name), *instance.Id, err)
	}
	if err := waitFor(ctx, func() (bool, error) {
		got, err := p.Compute.GetVolumeAttachment(ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: attached.VolumeAttachment.GetId()})
		return got.VolumeAttachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateAttached, err
	}); err != nil {
		return err
	}
	p.say("attached", "volume", chosen.name, *chosen.volume.Id+" to "+*instance.Id+" "+deref(instance.DisplayName))
	return nil
}

func (p Pass) bind(ctx context.Context, instance core.Instance, chosen slot) error {
	if instance.Metadata[nodeinit.VolumeKey] == *chosen.volume.Id {
		p.say("unchanged", "volume", chosen.name, *chosen.volume.Id+" on "+deref(instance.DisplayName))
		return nil
	}
	mayFormat := slices.Contains([]string{"", *instance.Id}, chosen.volume.FreeformTags[boundInstance])
	tags := maps.Clone(chosen.volume.FreeformTags)
	tags[boundInstance] = *instance.Id
	if _, err := p.Storage.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: chosen.volume.Id, UpdateVolumeDetails: core.UpdateVolumeDetails{FreeformTags: tags}}); err != nil {
		return fmt.Errorf("record %s on %s: %w", *instance.Id, p.Key("volume", chosen.name), err)
	}
	metadata := maps.Clone(instance.Metadata)
	maps.Copy(metadata, nodeinit.PoolBinding(*chosen.volume.Id, chosen.volume.FreeformTags[filesystemTag], mayFormat))
	if _, err := p.Compute.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: instance.Id, UpdateInstanceDetails: core.UpdateInstanceDetails{Metadata: metadata}}); err != nil {
		return fmt.Errorf("bind %s to %s: %w", p.Key("volume", chosen.name), *instance.Id, err)
	}
	p.say("bound", "volume", chosen.name, fmt.Sprintf("%s to %s, may format %t", *chosen.volume.Id, deref(instance.DisplayName), mayFormat))
	return nil
}

func waitFor(ctx context.Context, done func() (bool, error)) error {
	for range settleAttempts {
		ok, err := done()
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(settleInterval):
		}
	}
	return errors.New("OCI resource did not reach its state in " + (settleInterval * settleAttempts).String())
}

func all[T any](call func(page *string) ([]T, *string, error)) ([]T, error) {
	var items []T
	var page *string
	for {
		next, token, err := call(page)
		if err != nil {
			return nil, err
		}
		items = append(items, next...)
		if token == nil || *token == "" {
			return items, nil
		}
		page = token
	}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
