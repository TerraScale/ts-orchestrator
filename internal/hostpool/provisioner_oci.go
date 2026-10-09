package hostpool

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// Freeform tags on every pool host. Only an instance carrying this cell's
// tags is ever reported, adopted or terminated.
const (
	tagCell        = "ts-cell"
	tagPool        = "ts-pool"
	tagLaunchToken = "ts-launch-token"
	// replayWindow is how long a journaled launch is replayed with its
	// retry token. OCI keeps a token for 24 hours; after that it cannot
	// dedupe, and a host its launch created would long be listed.
	replayWindow = 23 * time.Hour
	gib          = 1 << 30
)

var faultDomainRE = regexp.MustCompile(`^fault-domain-[1-3]$`)

// OCITemplate is where pool hosts launch: the cell's managed OCI region
// config. Shape is a flex shape that each pool sizes.
type OCITemplate struct {
	CompartmentID           string
	AvailabilityDomain      string
	SubnetID                string
	NetworkSecurityGroupIDs []string
	Shape                   string
	BootVolumeVPUsPerGB     int64
	// Metadata is the launch material every host gets, such as the public
	// host enrollment bundle.
	Metadata map[string]string
}

// ociCompute is the slice of the OCI Compute API the provisioner calls.
type ociCompute interface {
	ListInstances(ctx context.Context, request core.ListInstancesRequest) (core.ListInstancesResponse, error)
	LaunchInstance(ctx context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error)
	TerminateInstance(ctx context.Context, request core.TerminateInstanceRequest) (core.TerminateInstanceResponse, error)
}

// LaunchRecord is one pool host's journaled launch: the OCI retry token,
// the exact request it was minted for, and how many times it was sent.
// Attempts is counted before each request, so a crash after sending still
// counts it.
type LaunchRecord struct {
	Token    string         `json:"token"`
	Request  jsontext.Value `json:"request"`
	Minted   time.Time      `json:"minted"`
	Attempts int            `json:"attempts"`
}

// LaunchJournal keeps launch records across uncertain launches and
// failovers.
type LaunchJournal interface {
	Read(ctx context.Context, node string) (LaunchRecord, bool, error)
	Write(ctx context.Context, node string, record LaunchRecord) error
	Delete(ctx context.Context, node string) error
}

// OCIProvisioner launches and terminates one cell's pool hosts over the OCI
// Compute API. A host boots the qualified host image with a static boot
// descriptor naming it, and enrolls like any static host.
type OCIProvisioner struct {
	// Cell is the NATS cell (gru) and Region its catalog code (GRU).
	Cell     string
	Region   string
	Template OCITemplate
	Compute  ociCompute
	Journal  LaunchJournal
	// Image chooses the qualified image a new host boots, the cell spec's
	// launch image or the fleet pin, and the spec version that chose it.
	// Admit qualifies that image again under that version and holds the
	// cell spec until release, which comes after the OCI launch returns.
	Image func(context.Context) (image, version string, err error)
	Admit func(ctx context.Context, image, version string) (release func(), err error)
	Now   func() time.Time
}

var _ Provisioner = (*OCIProvisioner)(nil)

// Instances lists the cell's pool hosts OCI has not terminated. A host with
// this cell's pool tags but no pool host name, or two live hosts with one
// name, fail the listing: the scaler then holds rather than guess.
func (p *OCIProvisioner) Instances(ctx context.Context) ([]Instance, error) {
	items, err := p.list(ctx, "")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(items))
	instances := make([]Instance, 0, len(items))
	for _, item := range items {
		node, pool := deref(item.DisplayName), item.FreeformTags[tagPool]
		if _, ok := (NodePool{Name: pool}).Ordinal(p.Cell, node); !ok {
			return nil, fmt.Errorf("pool host %s of pool %q has no pool host name", deref(item.Id), pool)
		}
		if seen[node] {
			return nil, fmt.Errorf("two live pool hosts are named %s", node)
		}
		seen[node] = true
		instance := Instance{Node: node, Pool: pool,
			Terminating: item.LifecycleState == core.InstanceLifecycleStateTerminating}
		if item.TimeCreated != nil {
			instance.Created = item.TimeCreated.Time
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

// list returns this cell's pool hosts, or those named node, that OCI has
// not terminated. An instance with node's name but not this cell's pool
// tags is refused: it is never adopted or terminated.
func (p *OCIProvisioner) list(ctx context.Context, node string) ([]core.Instance, error) {
	var found []core.Instance
	request := core.ListInstancesRequest{CompartmentId: common.String(p.Template.CompartmentID),
		AvailabilityDomain: common.String(p.Template.AvailabilityDomain)}
	if node != "" {
		request.DisplayName = common.String(node)
	}
	for range 100 {
		response, err := p.Compute.ListInstances(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("list pool hosts: %w", err)
		}
		for _, item := range response.Items {
			if item.LifecycleState == core.InstanceLifecycleStateTerminated {
				continue
			}
			owned := item.FreeformTags[tagCell] == p.Cell && item.FreeformTags[tagPool] != ""
			if node != "" && !owned {
				return nil, fmt.Errorf("instance %s holds the name %s without this cell's pool tags", deref(item.Id), node)
			}
			if owned {
				found = append(found, item)
			}
		}
		if response.OpcNextPage == nil {
			return found, nil
		}
		request.Page = response.OpcNextPage
	}
	return nil, errors.New("list pool hosts: too many pages")
}

// Launch creates launch.Node unless OCI already holds it. The retry token
// is journaled before the request and replayed while the launch is
// uncertain, so neither a lost response nor a failover launches it twice.
func (p *OCIProvisioner) Launch(ctx context.Context, _ uint64, pool NodePool, launch Launch) error {
	ordinal, ok := pool.Ordinal(p.Cell, launch.Node)
	if !ok || pool.NodeName(p.Cell, ordinal) != launch.Node || !faultDomainRE.MatchString(launch.FailureDomain) {
		return fmt.Errorf("launch %s: not a host of pool %s in an OCI fault domain", launch.Node, pool.Name)
	}
	existing, err := p.list(ctx, launch.Node)
	if err != nil {
		return err
	}
	for _, item := range existing {
		if item.FreeformTags[tagPool] != pool.Name {
			return fmt.Errorf("launch %s: the name belongs to pool %q", launch.Node, item.FreeformTags[tagPool])
		}
		if item.LifecycleState == core.InstanceLifecycleStateTerminating {
			return fmt.Errorf("launch %s: the previous host is still terminating", launch.Node)
		}
		return nil
	}
	now := p.Now()
	record, found, err := p.Journal.Read(ctx, launch.Node)
	if err != nil {
		return err
	}
	var details core.LaunchInstanceDetails
	var image, version string
	if found && now.Sub(record.Minted) < replayWindow {
		// A launch already sent may have created the host: replay its
		// exact request and token, whatever the pool or image is now.
		if details, err = decodeRequest(record.Request); err != nil {
			return fmt.Errorf("launch %s: journaled request: %w", launch.Node, err)
		}
		if source, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails); ok && source.ImageId != nil {
			image = *source.ImageId
		}
	} else {
		// No launch was sent, or its token expired with no host listed
		// under the name: OCI never created one or it is gone.
		if image, version, err = p.Image(ctx); err != nil {
			return fmt.Errorf("launch %s: %w", launch.Node, err)
		}
		if details, err = p.details(pool, launch, image); err != nil {
			return err
		}
		token := entityid.New()
		details.FreeformTags[tagLaunchToken] = token
		request, err := encodeRequest(details)
		if err != nil {
			return err
		}
		record = LaunchRecord{Token: token, Request: request, Minted: now}
	}
	release, err := p.Admit(ctx, image, version)
	if err != nil {
		return fmt.Errorf("launch %s: %w", launch.Node, err)
	}
	defer release()
	record.Attempts++
	if err := p.Journal.Write(ctx, launch.Node, record); err != nil {
		return err
	}
	// One attempt per tick: the journaled token makes the next tick the
	// retry, and an SDK retry would hide whether OCI saw the request.
	response, err := p.Compute.LaunchInstance(ctx, core.LaunchInstanceRequest{LaunchInstanceDetails: details,
		OpcRetryToken: common.String(record.Token), RequestMetadata: common.RequestMetadata{
			RetryPolicy: new(common.NoRetryPolicy())}})
	if err == nil {
		return nil
	}
	if record.Attempts == 1 && response.Id == nil && ociclient.MutationRejected(err, response.RawResponse) {
		// The only request ever sent with this token was refused without
		// effect: the next launch may mint a new one. A refused replay
		// proves nothing about an earlier request, so it keeps the token.
		return errors.Join(fmt.Errorf("launch %s: %w", launch.Node, err), p.Journal.Delete(ctx, launch.Node))
	}
	return fmt.Errorf("launch %s: %w", launch.Node, err)
}

// encodeRequest freezes a launch request; decodeRequest must reproduce
// the exact bytes, or a replay could send other parameters under the token.
func encodeRequest(details core.LaunchInstanceDetails) (jsontext.Value, error) {
	wire, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("freeze launch request: %w", err)
	}
	return jsontext.Value(wire), nil
}

func decodeRequest(wire jsontext.Value) (core.LaunchInstanceDetails, error) {
	var details core.LaunchInstanceDetails
	if err := json.Unmarshal(wire, &details); err != nil {
		return details, err
	}
	again, err := encodeRequest(details)
	if err != nil || !bytes.Equal(again, wire) {
		return details, errors.New("request does not round-trip exactly")
	}
	return details, nil
}

// details is the exact launch request of a pool host booting image,
// without its token.
func (p *OCIProvisioner) details(pool NodePool, launch Launch, image string) (core.LaunchInstanceDetails, error) {
	descriptor, err := hostboot.Static(p.Cell, p.Region, launch.Node).CanonicalBytes()
	if err != nil {
		return core.LaunchInstanceDetails{}, fmt.Errorf("launch %s: %w", launch.Node, err)
	}
	metadata := maps.Clone(p.Template.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	for key, value := range map[string]string{hostboot.MetadataKey: string(descriptor), "terrascale_host_node": launch.Node} {
		if _, reserved := metadata[key]; reserved {
			return core.LaunchInstanceDetails{}, fmt.Errorf("launch %s: launch material sets the reserved key %s", launch.Node, key)
		}
		metadata[key] = value
	}
	bootGB := (pool.Shape.DiskBytes + gib - 1) / gib
	memoryGB := pool.Shape.MemoryBytes / gib
	if bootGB < 50 || memoryGB < 1 || pool.Shape.MemoryBytes%gib != 0 {
		return core.LaunchInstanceDetails{}, fmt.Errorf("launch %s: pool %s needs whole GiB of memory and a 50 GB disk",
			launch.Node, pool.Name)
	}
	return core.LaunchInstanceDetails{
		DisplayName:        common.String(launch.Node),
		CompartmentId:      common.String(p.Template.CompartmentID),
		AvailabilityDomain: common.String(p.Template.AvailabilityDomain),
		FaultDomain:        common.String(strings.ToUpper(launch.FailureDomain)),
		Shape:              common.String(p.Template.Shape),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       common.Float32(float32(pool.Shape.CPU)),
			MemoryInGBs: common.Float32(float32(memoryGB)),
		},
		SourceDetails: core.InstanceSourceViaImageDetails{ImageId: common.String(image),
			BootVolumeSizeInGBs: common.Int64(bootGB), BootVolumeVpusPerGB: common.Int64(p.Template.BootVolumeVPUsPerGB)},
		// The SDK decodes absent polymorphic lists as empty: start empty, so
		// the frozen request round-trips exactly.
		LaunchVolumeAttachments: []core.LaunchAttachVolumeDetails{},
		LicensingConfigs:        []core.LaunchInstanceLicensingConfig{},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: common.String(p.Template.SubnetID),
			NsgIds: append([]string(nil), p.Template.NetworkSecurityGroupIDs...), HostnameLabel: common.String(launch.Node),
			AssignPublicIp: common.Bool(false)},
		Metadata:     metadata,
		FreeformTags: map[string]string{tagCell: p.Cell, tagPool: pool.Name},
	}, nil
}

// Reclaim terminates node and its boot volume if OCI holds it for pool.
// The scaler calls it only for a host without allocations; pool hosts
// never hold a TerraBase seat, and only this cell's tagged pool hosts are
// ever terminated.
func (p *OCIProvisioner) Reclaim(ctx context.Context, _ uint64, pool NodePool, node string) error {
	if _, ok := pool.Ordinal(p.Cell, node); !ok {
		return fmt.Errorf("reclaim %s: not a host of pool %s", node, pool.Name)
	}
	existing, err := p.list(ctx, node)
	if err != nil {
		return err
	}
	for _, item := range existing {
		if item.FreeformTags[tagPool] != pool.Name {
			return fmt.Errorf("reclaim %s: the host belongs to pool %q", node, item.FreeformTags[tagPool])
		}
		if item.LifecycleState == core.InstanceLifecycleStateTerminating {
			continue
		}
		if _, err := p.Compute.TerminateInstance(ctx, core.TerminateInstanceRequest{InstanceId: item.Id,
			PreserveBootVolume: common.Bool(false)}); err != nil {
			return fmt.Errorf("terminate %s: %w", node, err)
		}
	}
	return p.Journal.Delete(ctx, node)
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// LaunchBucket holds the pool hosts' launch records; a record carries its
// request with the launch material.
const (
	LaunchBucket   = "TS_HOSTPOOL_LAUNCHES"
	maxRecordBytes = 64 << 10
)

// KVLaunchJournal is the replicated LaunchJournal of a cell.
type KVLaunchJournal struct{ kv jetstream.KeyValue }

// OpenLaunchJournal opens the cell's launch journal.
func OpenLaunchJournal(ctx context.Context, js jetstream.JetStream, replicas int) (*KVLaunchJournal, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("pool host launch journal requires replicated JetStream")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: LaunchBucket, History: 1,
		MaxValueSize: maxRecordBytes, MaxBytes: 64 << 20, Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return nil, fmt.Errorf("open pool host launch journal: %w", err)
	}
	return &KVLaunchJournal{kv: kv}, nil
}

func (j *KVLaunchJournal) Read(ctx context.Context, node string) (LaunchRecord, bool, error) {
	entry, err := j.kv.Get(ctx, node)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return LaunchRecord{}, false, nil
	}
	if err != nil {
		return LaunchRecord{}, false, fmt.Errorf("read launch of %s: %w", node, err)
	}
	var record LaunchRecord
	if err := protocol.DecodeStrict(entry.Value(), &record, maxRecordBytes); err != nil {
		return LaunchRecord{}, false, fmt.Errorf("decode launch of %s: %w", node, err)
	}
	return record, true, nil
}

func (j *KVLaunchJournal) Write(ctx context.Context, node string, record LaunchRecord) error {
	wire, err := protocol.EncodeJSON(record)
	if err == nil {
		_, err = j.kv.Put(ctx, node, wire)
	}
	if err != nil {
		return fmt.Errorf("journal launch of %s: %w", node, err)
	}
	return nil
}

func (j *KVLaunchJournal) Delete(ctx context.Context, node string) error {
	if err := j.kv.Delete(ctx, node); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("forget launch of %s: %w", node, err)
	}
	return nil
}
