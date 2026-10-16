//go:build fixturetest

package fixturegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func assertPacketComputeObserver(t *testing.T, provider common.ConfigurationProvider,
	compute *core.ComputeClient, network *core.VirtualNetworkClient,
	observed ObservedController, vnic GuestObservation,
	instance core.GetInstanceResponse, primary core.GetVnicResponse,
	config production.Config,
) int {
	t.Helper()
	observer, err := bootstrapstart.NewOCIInstanceObserverWithClients(oci.RegionGRU,
		provider, compute, network)
	if err != nil {
		t.Fatalf("production OCI observer construction: %v", err)
	}
	actual, err := observer.ObserveInstance(t.Context(), observed.InstanceOCID)
	if err != nil || actual.InstanceOCID != observed.InstanceOCID || actual.ETag != observed.ETag ||
		actual.CompartmentOCID != *instance.CompartmentId || actual.ImageOCID != *instance.ImageId ||
		actual.AvailabilityDomain != *instance.AvailabilityDomain ||
		actual.FaultDomain != *instance.FaultDomain || actual.Shape != *instance.Shape ||
		actual.SubnetOCID != *primary.SubnetId || actual.PrimaryVNICOCID != vnic.PrimaryVNICOCID ||
		actual.PrimaryPrivateIP != vnic.PrimaryPrivateIP || !actual.PrimaryVNIC ||
		actual.LifecycleState != string(core.InstanceLifecycleStateRunning) ||
		!slices.Equal(actual.NSGOCIDs, primary.NsgIds) {
		t.Fatalf("production OCI observer rejected packet Compute evidence: %+v, %v", actual, err)
	}
	if config.DescriptorSlot == "controller-a" {
		assertPacketObserverRejections(t, config, observed, vnic, instance, primary)
	}
	return 4
}

func assertPacketObserverRejections(t *testing.T, config production.Config, observed ObservedController,
	vnic GuestObservation, instance core.GetInstanceResponse, primary core.GetVnicResponse,
) {
	t.Helper()
	attachmentRequest, err := (core.ListVnicAttachmentsRequest{CompartmentId: instance.CompartmentId,
		InstanceId: new(observed.InstanceOCID), Limit: new(50)}).HTTPRequest(http.MethodGet, "/20160918/vnicAttachments", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"/20160918/instances/" + observed.InstanceOCID, attachmentRequest.URL.RequestURI(),
		"/20160918/vnics/" + vnic.PrimaryVNICOCID, "/20160918/subnets/" + *primary.SubnetId}
	for _, scenario := range []struct {
		name   string
		path   string
		change func(any)
		reads  int
	}{
		{"exact primary and observational create key", paths[0], nil, 4},
		{"wrong VNIC compartment", paths[2], func(body any) { body.(map[string]any)["compartmentId"] = "ocid1.compartment.oc1..foreign" }, 4},
		{"wrong subnet compartment", paths[3], func(body any) { body.(map[string]any)["compartmentId"] = "ocid1.compartment.oc1..foreign" }, 4},
		{"wrong subnet identity", paths[3], func(body any) { body.(map[string]any)["id"] = "ocid1.subnet.oc1.sa-saopaulo-1.foreign" }, 4},
		{"wrong VCN region", paths[3], func(body any) { body.(map[string]any)["vcnId"] = "ocid1.vcn.oc1.us-ashburn-1.foreign" }, 4},
		{"missing VCN", paths[3], func(body any) { delete(body.(map[string]any), "vcnId") }, 4},
		{"subnet unavailable", paths[3], func(body any) { body.(map[string]any)["lifecycleState"] = "TERMINATED" }, 4},
		{"foreign attachment", paths[1], func(body any) {
			body.([]any)[0].(map[string]any)["instanceId"] = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
		}, 2},
		{"missing primary", paths[2], func(body any) { body.(map[string]any)["isPrimary"] = false }, 4},
		{"candidate mismatch", paths[0], func(body any) { body.(map[string]any)["id"] = "ocid1.instance.oc1.sa-saopaulo-1.foreign" }, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			variant := config
			variant.Reads = slices.Clone(config.Reads)
			found := false
			for i, read := range config.Reads {
				variant.Reads[i].Body = bytes.Clone(read.Body)
				if read.Host != "iaas.sa-saopaulo-1.oraclecloud.com" {
					continue
				}
				if read.RequestURI == paths[0] || read.RequestURI == scenario.path {
					var body any
					if err := json.Unmarshal(read.Body, &body); err != nil {
						t.Fatal(err)
					}
					if read.RequestURI == paths[0] {
						// This provider tag is observation, never signed admission scope.
						body.(map[string]any)["freeformTags"] = map[string]any{"BootstrapCreateKey": "reviewed-seed-create"}
					}
					baseline, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					if read.RequestURI == scenario.path {
						found = true
						if scenario.change != nil {
							scenario.change(body)
						}
					}
					variant.Reads[i].Body, err = json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("provider response %s original_sha256=%x baseline_sha256=%x served_sha256=%x", read.RequestURI,
						sha256.Sum256(read.Body), sha256.Sum256(baseline), sha256.Sum256(variant.Reads[i].Body))
				}
			}
			if !found {
				t.Fatal("negative case has no exact provider response")
			}
			simulator, dispatcher := newPacketSimulatorDispatcher(t, variant)
			provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region("sa-saopaulo-1"),
				func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) { return dispatcher, nil })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.KeyID(); err != nil {
				t.Fatalf("local instance principal federation: %v", err)
			}
			compute, err := core.NewComputeClientWithConfigurationProvider(provider)
			if err != nil {
				t.Fatal(err)
			}
			network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
			if err != nil {
				t.Fatal(err)
			}
			compute.HTTPClient, network.HTTPClient = dispatcher, dispatcher
			observer, err := bootstrapstart.NewOCIInstanceObserverWithClients(oci.RegionGRU, provider, &compute, &network)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			actual, err := observer.ObserveInstance(ctx, observed.InstanceOCID)
			if scenario.change == nil {
				if err != nil || actual.InstanceOCID != observed.InstanceOCID || actual.ETag != observed.ETag ||
					actual.CompartmentOCID != *instance.CompartmentId || actual.ImageOCID != *instance.ImageId ||
					actual.AvailabilityDomain != *instance.AvailabilityDomain || actual.FaultDomain != *instance.FaultDomain ||
					actual.Shape != *instance.Shape || actual.SubnetOCID != *primary.SubnetId ||
					actual.PrimaryVNICOCID != vnic.PrimaryVNICOCID || actual.PrimaryPrivateIP != vnic.PrimaryPrivateIP ||
					!actual.PrimaryVNIC || actual.LifecycleState != string(core.InstanceLifecycleStateRunning) ||
					!slices.Equal(actual.NSGOCIDs, primary.NsgIds) || actual.BootstrapCreateKey != "reviewed-seed-create" {
					t.Fatalf("exact primary observation = %+v, %v", actual, err)
				}
			} else if !errors.Is(err, bootstrapstart.ErrInstanceObservation) {
				t.Fatalf("expected observer validation rejection, got %+v, %v", actual, err)
			}
			var got []string
			for _, request := range simulator.Requests() {
				if !request.Listed || request.Status != http.StatusOK {
					t.Fatalf("SDK did not receive successful listed responses: %+v", request)
				}
				if request.Host == "iaas.sa-saopaulo-1.oraclecloud.com" {
					got = append(got, request.RouteSHA256)
				}
			}
			var want []string
			for _, path := range paths[:scenario.reads] {
				want = append(want, fmt.Sprintf("%x", sha256.Sum256([]byte("GET\niaas.sa-saopaulo-1.oraclecloud.com\n"+path))))
			}
			if !slices.Equal(got, want) || simulator.OverflowCount() != 0 {
				t.Fatalf("observer read sequence = %v, want %v; overflow=%d", got, want, simulator.OverflowCount())
			}
		})
	}
}
