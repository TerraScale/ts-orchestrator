package main

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func computeGrowth(privateKey string) {
	ownership := ociresource.Ownership{Owner: "fleet"}
	key := func(kind, name string) ociresource.Key {
		return ociresource.Key{Region: "gru-1", Kind: kind, Name: name}
	}
	tags := func(kind, name string) map[string]string { return ownership.Stamp(key(kind, name), 1, "").Freeform }
	volumes := []core.Volume{}
	instances := []core.Instance{}
	members := []core.InstanceSummary{}
	for n := 1; n <= 2; n++ {
		id, host := fmt.Sprintf("volume-%d", n), fmt.Sprintf("node-%d", n)
		volumes = append(volumes, core.Volume{Id: &id, SizeInGBs: common.Int64(int64(n + 2)), LifecycleState: core.VolumeLifecycleStateAvailable,
			FreeformTags: tags("volume", fmt.Sprintf("data-%d", n))})
		instances = append(instances, core.Instance{Id: &host, DisplayName: &host, FreeformTags: tags("instance", "node"), Metadata: map[string]string{nodeinit.VolumeKey: id}})
		members = append(members, core.InstanceSummary{Id: &host, State: common.String("Running")})
	}
	configuration := core.InstanceConfiguration{Id: common.String("configuration"), FreeformTags: tags("instance-configuration", "node"),
		InstanceDetails: core.ComputeInstanceDetails{LaunchDetails: &core.InstanceConfigurationLaunchInstanceDetails{
			Shape: common.String("shape"), ShapeConfig: &core.InstanceConfigurationLaunchInstanceShapeConfigDetails{Ocpus: common.Float32(1), MemoryInGBs: common.Float32(8)},
			SourceDetails:     core.InstanceConfigurationInstanceSourceViaImageDetails{ImageId: common.String("image"), BootVolumeSizeInGBs: common.Int64(50)},
			CreateVnicDetails: &core.InstanceConfigurationCreateVnicDetails{SubnetId: common.String("subnet"), AssignPublicIp: common.Bool(false), NsgIds: []string{"nsg"}},
		}}}
	pool := core.InstancePool{Id: common.String("pool"), Size: common.Int(2), InstanceConfigurationId: configuration.Id,
		LifecycleState: core.InstancePoolLifecycleStateRunning, FreeformTags: tags("instance-pool", "nodes")}
	updates := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("etag", "journey")
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		var reply any
		switch r.Method + " " + strings.Join(parts[1:], "/") {
		case "GET volumes":
			reply = volumes
		case "GET volumes/volume-1", "GET volumes/volume-2":
			for _, volume := range volumes {
				if *volume.Id == parts[2] {
					reply = volume
				}
			}
		case "PUT volumes/volume-1":
			must(r.Header.Get("if-match") == "journey", "volume growth lacks its observed ETag")
			var body map[string]int64
			must(json.UnmarshalRead(r.Body, &body) == nil && len(body) == 1 && body["sizeInGBs"] == 4, "growth changed more than size or attempted shrink")
			updates++
			volumes[0].SizeInGBs = common.Int64(4)
			reply = volumes[0]
		case "GET instanceConfigurations":
			reply = []core.InstanceConfiguration{configuration}
		case "GET instanceConfigurations/configuration":
			reply = configuration
		case "GET instancePools":
			reply = []core.InstancePool{pool}
		case "GET instancePools/pool":
			reply = pool
		case "GET instancePools/pool/instances":
			reply = members
		case "GET instances/node-1", "GET instances/node-2":
			for _, instance := range instances {
				if *instance.Id == parts[2] {
					reply = instance
				}
			}
		case "GET volumeAttachments":
			reply = []object{
				{"id": "attachment-1", "attachmentType": "paravirtualized", "instanceId": "node-1", "volumeId": "volume-1", "lifecycleState": "ATTACHED"},
				{"id": "attachment-2", "attachmentType": "paravirtualized", "instanceId": "node-2", "volumeId": "volume-2", "lifecycleState": "ATTACHED"},
			}
		default:
			panic("unexpected compute effect: " + r.Method + " " + r.URL.Path)
		}
		must(json.MarshalWrite(w, reply) == nil, "encode compute response")
	}))
	defer api.Close()
	provider := common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "00:00", privateKey, nil)
	storage, err := core.NewBlockstorageClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	storage.Host = api.URL
	management, err := core.NewComputeManagementClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	management.Host = api.URL
	nodes, err := core.NewComputeClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	nodes.Host = api.URL
	pass := compute.Pass{Clients: compute.Clients{Storage: storage, Management: management, Compute: nodes}, Ownership: ownership,
		Out: ociresource.Out{Same: io.Discard, Changed: io.Discard},
		Nodes: compute.Nodes{Label: "gru-1", Compartment: "cell", Shape: "shape", OCPUs: 1, MemoryGB: 8, BootGB: 50,
			DataGB: 2, Min: 2, Max: 2, SubnetID: "subnet", NSGID: "nsg", Key: key,
			Launch: func(context.Context) (compute.Launch, error) { return compute.Launch{ImageID: "image"}, nil }}}
	err = pass.Run(context.Background())
	must(err != nil && strings.Contains(err.Error(), "cannot shrink") && updates == 0, fmt.Sprint("decrease was not refused before effects: ", err))
	pass.DataGB = 4
	must(pass.Run(context.Background()) == nil, "attached data volume did not grow")
	must(updates == 1 && *volumes[0].SizeInGBs == 4 && *volumes[1].SizeInGBs == 4, "growth did not reconcile both attached volumes")
	must(pass.Run(context.Background()) == nil && updates == 1, "repeated compute apply resized again")
	fmt.Println("compute volume: decreases refused before effects; attached 3 -> 4 GB uses If-Match, equal volume unchanged, repeated apply unchanged")
}
