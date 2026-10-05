package cellscale

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// readOnly fails the test on any OCI call that could change the tenancy.
type readOnly struct {
	computeAPI
	t *testing.T
}

func (r readOnly) LaunchInstance(context.Context, core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	r.t.Fatal("live read-only test tried to launch an instance")
	return core.LaunchInstanceResponse{}, nil
}

func (r readOnly) UpdateInstance(context.Context, core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
	r.t.Fatal("live read-only test tried to update an instance")
	return core.UpdateInstanceResponse{}, nil
}

func (r readOnly) TerminateInstance(context.Context, core.TerminateInstanceRequest) (core.TerminateInstanceResponse, error) {
	r.t.Fatal("live read-only test tried to terminate an instance")
	return core.TerminateInstanceResponse{}, nil
}

// TestOCIReadOnlyAgainstRealAPI runs List and Preflight against a real
// tenancy with the operator's DEFAULT profile. It only reads. The image and
// subnet default to the newest Oracle Linux image for the shape and a
// subnet OCID that does not exist, whose 404 must surface as one problem.
func TestOCIReadOnlyAgainstRealAPI(t *testing.T) {
	values := tier.Qualification(t, "TS_CELLSCALE_OCI_REGION", "TS_CELLSCALE_OCI_COMPARTMENT")
	region, compartment := values[0], values[1]
	entry, ok := catalog.CellForOCIRegion(region)
	if !ok {
		t.Fatalf("TS_CELLSCALE_OCI_REGION %q is not a catalog region", region)
	}
	ctx := t.Context()
	factory, err := ociclient.OperatorConfig(region)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	network, err := factory.Network()
	if err != nil {
		t.Fatal(err)
	}
	quota, err := factory.Limits()
	if err != nil {
		t.Fatal(err)
	}
	template := Template{Region: region, CompartmentID: compartment, Shape: "VM.Standard.A1.Flex",
		AvailabilityDomain: os.Getenv("TS_CELLSCALE_OCI_AD"), ImageID: os.Getenv("TS_CELLSCALE_OCI_IMAGE"),
		SubnetID: os.Getenv("TS_CELLSCALE_OCI_SUBNET")}
	if template.AvailabilityDomain == "" {
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil {
			t.Fatal(err)
		}
		iam, err := factory.Identity()
		if err != nil {
			t.Fatal(err)
		}
		domains, err := iam.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: common.String(tenancy)})
		if err != nil || len(domains.Items) == 0 {
			t.Fatalf("list availability domains: %d, %v", len(domains.Items), err)
		}
		template.AvailabilityDomain = *domains.Items[0].Name
	}
	if template.ImageID == "" {
		images, err := compute.ListImages(ctx, core.ListImagesRequest{CompartmentId: common.String(compartment),
			OperatingSystem: common.String("Oracle Linux"), Shape: common.String(template.Shape),
			SortBy: core.ListImagesSortByTimecreated, SortOrder: core.ListImagesSortOrderDesc, Limit: common.Int(1)})
		if err != nil || len(images.Items) == 0 {
			t.Fatalf("list images for %s: %d, %v", template.Shape, len(images.Items), err)
		}
		template.ImageID = *images.Items[0].Id
	}
	wantProblems := 0
	if template.SubnetID == "" {
		template.SubnetID = "ocid1.subnet.oc1." + region + ".aaaaaaaacellscalepreflightmissingsubnet"
		wantProblems = 1
	}
	cloud, err := newOCICloud(entry.Name()+"-1", template, readOnly{computeAPI: compute, t: t}, sdkReads{network, quota})
	if err != nil {
		t.Fatal(err)
	}
	instances, err := cloud.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, instance := range instances {
		if instance.ID == "" || instance.Running() && instance.Shape.OCPUs <= 0 {
			t.Fatalf("listed instance without identity or shape: %+v", instance)
		}
	}
	report, err := cloud.Preflight(ctx, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cell %s in %s: %d nodes, image %s, preflight %+v", entry.Name()+"-1", template.AvailabilityDomain,
		len(instances), template.ImageID, report)
	if len(report.Problems) != wantProblems || wantProblems == 1 && !strings.Contains(report.Problems[0], "subnet") {
		t.Fatalf("problems = %q", report.Problems)
	}
	if report.CoresAvailable <= 0 || report.MemoryGBAvailable <= 0 {
		t.Fatalf("quota headroom was not read: %+v", report)
	}
}
