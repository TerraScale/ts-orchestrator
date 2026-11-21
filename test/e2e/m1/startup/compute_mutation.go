package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func computeMutationJourney(ctx context.Context, region fleet.Region, factory *ociclient.Factory) error {
	mode := ""
	resolved, exists, rejected, replaced, bound := false, false, false, false, false
	size, revision, reads, creates, updates, readsAfterBind := 0, 0, 0, 0, 0, 0
	var sizes []int
	configuration := "old-config"
	ownership := ociresource.Ownership{Owner: fleet.Owner}
	pool := func() map[string]any {
		return map[string]any{"id": "pool", "compartmentId": region.CompartmentID, "instanceConfigurationId": configuration, "size": size, "lifecycleState": "RUNNING", "freeformTags": ownership.Stamp(region.Key("instance-pool", "nodes"), 1, "journey").Freeform}
	}
	volume := func(index int) map[string]any {
		tags := ownership.Stamp(region.Key("volume", fmt.Sprintf("data-%d", index+1)), 1, "journey").Freeform
		tags["terrascale-data-instance"] = fmt.Sprintf("pool-instance-%d", index)
		return map[string]any{"id": fmt.Sprintf("volume-%d", index), "availabilityDomain": "AD-1", "lifecycleState": "AVAILABLE", "freeformTags": tags}
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id, state := "instance-0", "RUNNING"
		if mode == "replacement" && resolved {
			id = "instance-replacement"
		}
		if mode == "stop-before-write" && resolved || mode == "stop-after-write" && creates > 0 || mode == "concurrent-growth" && reads >= 4 {
			state = "STOPPED"
		}
		var body any
		if member, found := strings.CutPrefix(r.URL.Path, "/20160918/instances/pool-instance-"); found {
			body = map[string]any{"id": "pool-instance-" + member, "displayName": region.Label + "-node-" + member, "availabilityDomain": "AD-1", "lifecycleState": "RUNNING",
				"freeformTags": ownership.Stamp(region.Key("instance", "node"), 1, "journey").Freeform, "metadata": map[string]string{nodeinit.VolumeKey: "volume-" + member}}
			if err := json.NewEncoder(w).Encode(body); err != nil {
				panic(err)
			}
			return
		}
		switch r.URL.Path {
		case "/20160918/volumes":
			body = []any{}
			for i := range size {
				body = append(body.([]any), volume(i))
			}
		case "/20160918/volumes/volume-0", "/20160918/volumes/volume-1":
			index, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/20160918/volumes/volume-"))
			if err != nil {
				panic(err)
			}
			body = volume(index)
			if index == size-1 {
				bound, replaced = true, mode == "member-replaced" || mode == "no-external-replaced"
			}
		case "/20160918/volumeAttachments":
			body = []any{}
			for i := range size {
				body = append(body.([]any), map[string]any{"attachmentType": "paravirtualized", "id": fmt.Sprintf("attachment-%d", i), "availabilityDomain": "AD-1",
					"instanceId": fmt.Sprintf("pool-instance-%d", i), "volumeId": fmt.Sprintf("volume-%d", i), "lifecycleState": "ATTACHED", "device": "/dev/oracleoci/oraclevdb"})
			}
		case "/launch":
			resolved = true
			body = compute.Launch{ImageID: "image"}
		case "/20160918/instances":
			body = []any{map[string]any{"id": id, "displayName": "ts-gru-1", "compartmentId": region.CompartmentID, "lifecycleState": state}}
		case "/20160918/instances/instance-0", "/20160918/instances/instance-replacement":
			if mode == "etag-race" && reads >= 3 && size == 1 {
				size, revision = 3, revision+1
			}
			body = map[string]any{"id": id, "displayName": "ts-gru-1", "compartmentId": region.CompartmentID, "lifecycleState": state}
		case "/20160918/vnicAttachments":
			body = []any{map[string]any{"instanceId": id, "vnicId": "primary", "lifecycleState": "ATTACHED"}}
		case "/20160918/vnics/primary":
			body = map[string]any{"id": "primary", "isPrimary": true, "subnetId": "host-subnet"}
		case "/20160918/subnets/host-subnet":
			body = map[string]any{"id": "host-subnet", "vcnId": "regional-vcn", "compartmentId": region.CompartmentID}
		case "/20160918/instanceConfigurations":
			body = []any{}
			if r.Method == http.MethodPost {
				body = map[string]any{"id": "config"}
			}
		case "/20160918/instancePools":
			body = []any{}
			if exists {
				body = []any{pool()}
			}
			if r.Method == http.MethodPost {
				var details core.CreateInstancePoolDetails
				if err := json.NewDecoder(r.Body).Decode(&details); err != nil || details.Size == nil {
					panic("invalid pool create")
				}
				size, creates, exists, configuration = *details.Size, creates+1, true, "config"
				body = pool()
			}
		case "/20160918/instancePools/pool":
			if r.Method == http.MethodGet {
				reads++
				if bound {
					readsAfterBind++
				}
				if mode == "concurrent-growth" && reads == 2 {
					size, revision = 3, revision+1
				}
				w.Header().Set("etag", strconv.Itoa(revision))
			} else if r.Method == http.MethodPut {
				if r.Header.Get("if-match") != strconv.Itoa(revision) {
					rejected = true
					w.WriteHeader(http.StatusPreconditionFailed)
					fmt.Fprint(w, `{"code":"NoEtagMatch","message":"pool changed concurrently"}`)
					return
				}
				var details core.UpdateInstancePoolDetails
				if err := json.NewDecoder(r.Body).Decode(&details); err != nil {
					panic(err)
				}
				updates++
				if details.Size != nil {
					sizes = append(sizes, *details.Size)
					size = *details.Size
				}
				if details.InstanceConfigurationId != nil {
					configuration = *details.InstanceConfigurationId
				}
				revision++
			}
			body = pool()
		case "/20160918/instancePools/pool/instances":
			body = []any{}
			for i := range size {
				if replaced && i == size-1 {
					i = size
				}
				body = append(body.([]any), map[string]any{"id": fmt.Sprintf("pool-instance-%d", i), "state": "Running"})
			}
		default:
			http.Error(w, "unexpected compute request: "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			panic(err)
		}
	}))
	defer endpoint.Close()
	clients := compute.Clients{}
	var err error
	if clients.Compute, err = factory.Compute(); err != nil {
		return err
	}
	if clients.Management, err = factory.ComputeManagement(); err != nil {
		return err
	}
	if clients.Storage, err = factory.Blockstorage(); err != nil {
		return err
	}
	network, err := factory.Network()
	if err != nil {
		return err
	}
	clients.Compute.Host, clients.Management.Host, clients.Storage.Host, network.Host = endpoint.URL, endpoint.URL, endpoint.URL, endpoint.URL
	for _, scenario := range []string{"stop-before-write", "replacement", "stop-after-write", "concurrent-growth", "etag-race", "member-replaced", "bound", "no-external-replaced"} {
		settled := scenario == "member-replaced" || scenario == "bound" || scenario == "no-external-replaced"
		mode, resolved, exists, rejected, replaced, bound = scenario, false, scenario == "concurrent-growth" || scenario == "etag-race" || settled, false, false, false
		size, revision, reads, creates, updates, readsAfterBind, sizes, configuration = 0, 1, 0, 0, 0, 0, nil, "old-config"
		if exists {
			size = 1
		}
		if settled {
			size, configuration = 2, "config"
		}
		external, err := fleet.VerifyExternal(ctx, region, clients.Compute, clients.Management, network, "regional-vcn")
		if err != nil {
			return err
		}
		pass := compute.Pass{Clients: clients, Ownership: ownership, Out: ociresource.Out{Same: io.Discard, Changed: io.Discard, Apply: true},
			Nodes: compute.Nodes{Label: region.Label, Compartment: region.CompartmentID, Min: 2, Max: 3, Key: region.Key,
				SubnetID: "private-subnet", Places: []compute.Place{{AvailabilityDomain: "AD-1", FaultDomains: []string{"FAULT-DOMAIN-1"}}},
				Launch: func(ctx context.Context) (compute.Launch, error) {
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/launch", nil)
					if err != nil {
						return compute.Launch{}, err
					}
					response, err := http.DefaultClient.Do(request)
					if err != nil {
						return compute.Launch{}, err
					}
					defer response.Body.Close()
					var launch compute.Launch
					err = json.NewDecoder(response.Body).Decode(&launch)
					return launch, err
				}},
			VerifyCapacity: func(ctx context.Context, separatelyCheckedPool string) (map[string]string, error) {
				return fleet.RecheckExternal(ctx, region, clients.Compute, clients.Management, network, "regional-vcn", external, separatelyCheckedPool)
			}}
		if scenario == "no-external-replaced" {
			pass.VerifyCapacity = nil
		}
		err = pass.Run(ctx)
		if scenario == "bound" || scenario == "no-external-replaced" {
			if err != nil || !bound || scenario == "no-external-replaced" && readsAfterBind != 0 || scenario == "bound" && readsAfterBind != 1 {
				return fmt.Errorf("compute %s: bound=%t pool reads after binding=%d error=%v", scenario, bound, readsAfterBind, err)
			}
			fmt.Printf("ok compute %s: completed after binding both members, pool reads after binding %d\n", scenario, readsAfterBind)
			continue
		}
		if err == nil {
			return fmt.Errorf("compute %s reported success after capacity changed", scenario)
		}
		switch scenario {
		case "replacement":
			if creates != 0 || !strings.Contains(err.Error(), "identities changed") {
				return fmt.Errorf("replacement external identity passed: %v", err)
			}
		case "stop-before-write":
			if creates != 0 || !strings.Contains(err.Error(), "must be RUNNING") {
				return fmt.Errorf("stopped external reached pool write: %v", err)
			}
		case "stop-after-write":
			if creates != 1 || !strings.Contains(err.Error(), "must be RUNNING") {
				return fmt.Errorf("compute did not recheck capacity after pool creation: %v", err)
			}
		case "concurrent-growth":
			if size != 3 || updates != 1 || len(sizes) != 0 || !strings.Contains(err.Error(), "must be RUNNING") {
				return fmt.Errorf("compute lowered concurrent growth: size=%d updates=%d sizes=%v error=%v", size, updates, sizes, err)
			}
		case "member-replaced":
			if !replaced || !strings.Contains(err.Error(), "members changed") || !strings.Contains(err.Error(), "pool-instance-2") {
				return fmt.Errorf("compute accepted a pool member it never bound: %v", err)
			}
		case "etag-race":
			if !rejected || updates != 0 || size != 3 || !strings.Contains(err.Error(), "update instance pool") {
				return fmt.Errorf("compute overwrote a racing writer: size=%d rejected=%t error=%v", size, rejected, err)
			}
		}
		fmt.Printf("ok compute %s: created %d, updated %d, size %d, size writes %v, stale revision refused %t\n", scenario, creates, updates, size, sizes, rejected)
	}
	return nil
}
