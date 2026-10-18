package rootcapacity

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func capacitySafetyAttempt() attempt {
	return attempt{receipt: budget.Reservation{OperationID: "original-birth", CompartmentID: "ocid1.compartment.oc1..fixture"},
		recipe: nodescale.Recipe{Cell: "gru", Capacity: nodescale.Capacity{Role: nodescale.RoleContainer, Architecture: "arm64", Shape: nodescale.PreferredShape},
			ImageID: "ocid1.image.oc1..fixture", SubnetID: "ocid1.subnet.oc1..fixture", NSGIDs: []string{"ocid1.networksecuritygroup.oc1..fixture"},
			AvailabilityDomains: []string{"AD-1", "AD-2"}, OCPUs: 2, MemoryGB: 12, Metadata: map[string]string{"base": "signed"}}}
}

// Every pool DTO below comes from a signed real SDK GET before validation.
func TestRootCapacityPoolIdentityAndPlacementOCIProtocol(t *testing.T) {
	if capacityProtocolUserNamespace(t) {
		return
	}
	provider := capacityProtocolProvider(t)
	for _, encoding := range []string{"primary subnet", "primary VNIC subnet"} {
		for _, change := range []string{"unchanged", "id", "compartment", "name", "missing size", "negative size", "oversize", "load balancer", "AD count", "AD order", "AD value", "subnet"} {
			t.Run(encoding+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				a := capacitySafetyAttempt()
				poolID := "ocid1.instancepool.oc1..fixture"
				poolName := nodescale.PoolName(a.recipe.Cell, a.recipe.Capacity)
				pool := core.InstancePool{Id: new(poolID), CompartmentId: new(a.receipt.CompartmentID), DisplayName: new(poolName), Size: new(0)}
				for _, ad := range a.recipe.AvailabilityDomains {
					placement := core.InstancePoolPlacementConfiguration{AvailabilityDomain: new(ad)}
					if encoding == "primary VNIC subnet" {
						placement.PrimaryVnicSubnets = &core.InstancePoolPlacementPrimarySubnet{SubnetId: new(a.recipe.SubnetID)}
					} else {
						placement.PrimarySubnetId = new(a.recipe.SubnetID)
					}
					pool.PlacementConfigurations = append(pool.PlacementConfigurations, placement)
				}
				switch change {
				case "id":
					pool.Id = new("ocid1.instancepool.oc1..foreign")
				case "compartment":
					pool.CompartmentId = new("ocid1.compartment.oc1..foreign")
				case "name":
					pool.DisplayName = new("foreign-pool")
				case "missing size":
					pool.Size = nil
				case "negative size":
					pool.Size = new(-1)
				case "oversize":
					pool.Size = new(nodescale.MaxPoolNodes + 1)
				case "load balancer":
					pool.LoadBalancers = []core.InstancePoolLoadBalancerAttachment{{}}
				case "AD count":
					pool.PlacementConfigurations = pool.PlacementConfigurations[:1]
				case "AD order":
					slices.Reverse(pool.PlacementConfigurations)
				case "AD value":
					pool.PlacementConfigurations[0].AvailabilityDomain = new("foreign-AD")
				case "subnet":
					if encoding == "primary VNIC subnet" {
						pool.PlacementConfigurations[0].PrimaryVnicSubnets.SubnetId = new("ocid1.subnet.oc1..foreign")
					} else {
						pool.PlacementConfigurations[0].PrimarySubnetId = new("ocid1.subnet.oc1..foreign")
					}
				}
				var gets, writes atomic.Int32
				capacityProtocolTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						writes.Add(1)
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}
					gets.Add(1)
					if r.URL.Path != "/20160918/instancePools/"+poolID || r.URL.RawQuery != "" || r.TLS == nil || !strings.Contains(r.Header.Get("Authorization"), `signature="`) {
						t.Errorf("unexpected signed pool GET: %s %s", r.Method, r.URL)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if err := json.MarshalWrite(w, pool); err != nil {
						t.Error(err)
					}
				}))
				observed, management := capacityProtocolObservation(t, ctx, provider)
				observed.record.CapacityPools = map[string]region.PoolResourceRecord{poolID: {CompartmentID: a.receipt.CompartmentID, PoolName: poolName}}
				response, err := management.GetInstancePool(observed.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(poolID)})
				if err != nil {
					t.Fatal("pool read did not traverse the real SDK boundary", err)
				}
				err = observed.checkPool(response.InstancePool, poolID)
				if change == "unchanged" && err != nil {
					t.Fatal("exact original pool readback was rejected", err)
				}
				if change != "unchanged" && err == nil {
					t.Fatal("changed actual pool identity, size or placement passed")
				}
				if gets.Load() != 1 || writes.Load() != 0 {
					t.Fatalf("pool validation sent gets=%d writes=%d; want one GET only", gets.Load(), writes.Load())
				}
			})
		}
	}
}

// Failure-only vendor SDK dispatch tests wire contracts; it grants no controller admission.
func TestRootCapacityLaunchContractAndRetryFailuresOCIProtocol(t *testing.T) {
	provider := capacityProtocolProvider(t)
	tokens := map[string]string{}
	for _, effect := range []string{"configuration", "pool", "launch"} {
		for _, refusal := range []struct {
			status int
			code   string
		}{{500, "OutOfHostCapacity"}, {412, "NoEtagMatch"}} {
			t.Run(fmt.Sprintf("%s/%s", effect, refusal.code), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				type dispatched struct {
					body        []byte
					token, path string
				}
				traffic := make(chan dispatched, 32)
				capacityProtocolTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
					if err != nil {
						t.Error(err)
					}
					if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.TLS == nil || !strings.Contains(r.Header.Get("Authorization"), `signature="`) {
						t.Errorf("unexpected failure-only SDK dispatch: %s %s", r.Method, r.URL)
					}
					traffic <- dispatched{body: body, token: r.Header.Get("opc-retry-token"), path: r.URL.Path}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(refusal.status)
					if err := json.MarshalWrite(w, map[string]string{"code": refusal.code, "message": "intentional fixture refusal"}); err != nil {
						t.Error(err)
					}
				}))
				// A concrete vendor client reaches only rejecting loopback TLS; no HomeIAM or write-authority seam is supplied.
				management, err := core.NewComputeManagementClientWithConfigurationProvider(provider)
				if err != nil {
					t.Fatal(err)
				}
				a := capacitySafetyAttempt()
				child := region.PoolChildRecord{ConfigurationID: "original-configuration", Node: "ts-gru-4", AvailabilityDomain: "AD-1", Descriptor: "original-descriptor"}
				configuration, pool, launch := a.configurationRequest(), a.poolRequest(child.ConfigurationID), a.launchRequest(child)
				a.recipe.Metadata["base"] = "changed after request construction"
				dispatch := func(replacement bool) error {
					if replacement {
						next := capacitySafetyAttempt()
						next.receipt.OperationID = "next-original-birth"
						configuration, pool, launch = next.configurationRequest(), next.poolRequest(child.ConfigurationID), next.launchRequest(child)
					}
					switch effect {
					case "configuration":
						_, err := management.CreateInstanceConfiguration(ctx, configuration)
						return err
					case "pool":
						_, err := management.CreateInstancePool(ctx, pool)
						return err
					default:
						_, err := management.LaunchInstanceConfiguration(ctx, launch)
						return err
					}
				}
				for attempt := range 3 {
					err := dispatch(attempt == 2)
					service, ok := common.IsServiceError(err)
					if !ok || service.GetHTTPStatusCode() != refusal.status || service.GetCode() != refusal.code {
						t.Fatalf("SDK hid original provider refusal: %v", err)
					}
					if len(traffic) != attempt+1 {
						t.Fatalf("SDK retried a failed mutation automatically: dispatched=%d explicit=%d", len(traffic), attempt+1)
					}
				}
				first, replay, next := <-traffic, <-traffic, <-traffic
				for previousEffect, token := range tokens {
					if previousEffect != effect && token == first.token {
						t.Fatal("different actual lifecycle effects reused a retry identity")
					}
				}
				tokens[effect] = first.token
				if first.token == "" || replay.token != first.token || !bytes.Equal(first.body, replay.body) || replay.path != first.path || next.token == first.token {
					t.Fatal("failed same-operation replay changed immutable body/token or a new operation reused identity")
				}
				wantPath := "/20160918/instanceConfigurations"
				if effect == "pool" {
					wantPath = "/20160918/instancePools"
				}
				if effect == "launch" {
					wantPath += "/original-configuration/actions/launch"
				}
				if first.path != wantPath || next.path != wantPath {
					t.Fatal("SDK failure escaped the exact current lifecycle endpoint")
				}
				if effect == "pool" {
					var captured core.CreateInstancePoolDetails
					if err := json.Unmarshal(first.body, &captured); err != nil {
						t.Fatal(err)
					}
					if captured.Size == nil || *captured.Size != 0 || value(captured.InstanceConfigurationId) != child.ConfigurationID || value(captured.CompartmentId) != "ocid1.compartment.oc1..fixture" || len(captured.PlacementConfigurations) != 2 {
						t.Fatal("actual pool request can implicitly create children or changed exact inception scope")
					}
					continue
				}
				var captured core.ComputeInstanceDetails
				if effect == "configuration" {
					var configuration core.CreateInstanceConfigurationDetails
					if err := json.Unmarshal(first.body, &configuration); err != nil {
						t.Fatal(err)
					}
					var ok bool
					captured, ok = configuration.InstanceDetails.(core.ComputeInstanceDetails)
					if !ok {
						t.Fatal("configuration SDK body lost compute instance details")
					}
				} else if err := json.Unmarshal(first.body, &captured); err != nil {
					t.Fatal(err)
				}
				details := captured.LaunchDetails
				if details == nil {
					t.Fatal("captured SDK body omitted actual launch details")
				}
				source, ok := details.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails)
				if !ok || value(source.ImageId) != "ocid1.image.oc1..fixture" || value(source.BootVolumeSizeInGBs) != nodescale.BootVolumeGB ||
					value(details.CompartmentId) != "ocid1.compartment.oc1..fixture" || value(details.Shape) != nodescale.PreferredShape || details.ShapeConfig == nil || value(details.ShapeConfig.Ocpus) != 2 || value(details.ShapeConfig.MemoryInGBs) != 12 ||
					details.InstanceOptions == nil || details.InstanceOptions.AreLegacyImdsEndpointsDisabled == nil || !*details.InstanceOptions.AreLegacyImdsEndpointsDisabled || details.CreateVnicDetails == nil || value(details.CreateVnicDetails.SubnetId) != "ocid1.subnet.oc1..fixture" || details.CreateVnicDetails.AssignPublicIp == nil || *details.CreateVnicDetails.AssignPublicIp || !slices.Equal(details.CreateVnicDetails.NsgIds, []string{"ocid1.networksecuritygroup.oc1..fixture"}) || details.Metadata["base"] != "signed" {
					t.Fatal("actual SDK body changed original image/resources/network/metadata/IMDS contract")
				}
				if effect == "launch" && (value(details.DisplayName) != child.Node || value(details.AvailabilityDomain) != child.AvailabilityDomain || details.Metadata[hostboot.MetadataKey] != child.Descriptor) {
					t.Fatal("actual launch wire lost exact child placement or descriptor")
				}
			})
		}
	}
}
