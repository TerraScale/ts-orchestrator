package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const maxObservedVNICAttachments = 64

var ErrInstanceObservation = errors.New("OCI instance or primary VNIC observation is invalid")

type computeObservationAPI interface {
	GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error)
	ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error)
}

type networkObservationAPI interface {
	GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error)
	GetSubnet(context.Context, core.GetSubnetRequest) (core.GetSubnetResponse, error)
}

// OCIInstanceObserver uses an authenticated provider supplied by the caller.
// Its constructor pins the Compute and Networking endpoints to the root-baked
// region before any request; it never uses the IMDS descriptor as a URL.
type OCIInstanceObserver struct {
	compute computeObservationAPI
	network networkObservationAPI
}

func NewOCIInstanceObserver(region oci.Region, provider common.ConfigurationProvider) (*OCIInstanceObserver, error) {
	ociRegion, err := observerRegion(region, provider)
	if err != nil {
		return nil, err
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Compute observer: %w", err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Networking observer: %w", err)
	}
	compute.SetRegion(ociRegion)
	network.SetRegion(ociRegion)
	compute.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("configure OCI Compute HTTP transport: %w", err)
	}
	network.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("configure OCI Networking HTTP transport: %w", err)
	}
	return &OCIInstanceObserver{compute: &compute, network: &network}, nil
}

func observerRegion(region oci.Region, provider common.ConfigurationProvider) (string, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil || provider == nil {
		return "", ErrInstanceObservation
	}
	providerRegion, err := provider.Region()
	if err != nil || providerRegion != ociRegion {
		return "", ErrInstanceObservation
	}
	return ociRegion, nil
}

// ObserveInstance positively identifies the candidate instance and exactly one
// attached primary VNIC. OCI metadata and instance tags supply no signed scope.
func (observer *OCIInstanceObserver) ObserveInstance(ctx context.Context, candidateID string) (InstanceObservation, error) {
	if observer == nil || observer.compute == nil || observer.network == nil ||
		!instanceIDRE.MatchString(candidateID) {
		return InstanceObservation{}, ErrInstanceObservation
	}
	response, err := observer.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(candidateID)})
	if err != nil {
		return InstanceObservation{}, fmt.Errorf("GetInstance exact IMDS candidate: %w", err)
	}
	instance := response.Instance
	if value(instance.Id) != candidateID || !strings.HasPrefix(value(instance.CompartmentId), "ocid1.compartment.") ||
		!strings.HasPrefix(value(instance.ImageId), "ocid1.image.") || value(instance.AvailabilityDomain) == "" ||
		value(instance.FaultDomain) == "" || value(instance.Shape) == "" {
		return InstanceObservation{}, ErrInstanceObservation
	}
	observation := InstanceObservation{
		InstanceOCID: candidateID, CompartmentOCID: value(instance.CompartmentId),
		ImageOCID: value(instance.ImageId), ETag: value(response.Etag),
		AvailabilityDomain: value(instance.AvailabilityDomain), FaultDomain: value(instance.FaultDomain),
		Shape: value(instance.Shape), LifecycleState: string(instance.LifecycleState),
	}
	if instance.FreeformTags != nil {
		observation.BootstrapCreateKey = instance.FreeformTags["BootstrapCreateKey"]
	}
	var page *string
	seenPages := make(map[string]struct{})
	count := 0
	for {
		attachments, err := observer.compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
			CompartmentId: new(observation.CompartmentOCID), InstanceId: new(candidateID),
			Limit: new(50), Page: page,
		})
		if err != nil {
			return InstanceObservation{}, fmt.Errorf("ListVnicAttachments exact instance: %w", err)
		}
		count += len(attachments.Items)
		if count > maxObservedVNICAttachments || len(attachments.Items) == 0 && attachments.OpcNextPage != nil {
			return InstanceObservation{}, ErrInstanceObservation
		}
		for _, attachment := range attachments.Items {
			if value(attachment.InstanceId) != candidateID ||
				value(attachment.CompartmentId) != observation.CompartmentOCID {
				return InstanceObservation{}, ErrInstanceObservation
			}
			if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				continue
			}
			vnicID := value(attachment.VnicId)
			if !strings.HasPrefix(vnicID, "ocid1.vnic.") {
				return InstanceObservation{}, ErrInstanceObservation
			}
			vnicResponse, err := observer.network.GetVnic(ctx, core.GetVnicRequest{VnicId: new(vnicID)})
			if err != nil {
				return InstanceObservation{}, fmt.Errorf("GetVnic attached to exact instance: %w", err)
			}
			vnic := vnicResponse.Vnic
			if value(vnic.Id) != vnicID ||
				value(vnic.AvailabilityDomain) != observation.AvailabilityDomain ||
				vnic.LifecycleState != core.VnicLifecycleStateAvailable ||
				value(vnic.SubnetId) != value(attachment.SubnetId) {
				return InstanceObservation{}, ErrInstanceObservation
			}
			subnetResponse, err := observer.network.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: vnic.SubnetId})
			if err != nil {
				return InstanceObservation{}, fmt.Errorf("GetSubnet attached VNIC: %w", err)
			}
			if !vnicSubnetMatches(vnic, subnetResponse.Subnet, candidateID) {
				return InstanceObservation{}, ErrInstanceObservation
			}
			if vnic.IsPrimary == nil || !*vnic.IsPrimary {
				continue
			}
			if observation.PrimaryVNIC {
				return InstanceObservation{}, fmt.Errorf("%w: multiple attached primary VNICs", ErrInstanceObservation)
			}
			observation.PrimaryVNIC = true
			observation.PrimaryVNICOCID = vnicID
			observation.PrimaryPrivateIP = value(vnic.PrivateIp)
			observation.SubnetOCID = value(vnic.SubnetId)
			observation.NSGOCIDs = append([]string(nil), vnic.NsgIds...)
		}
		if attachments.OpcNextPage == nil || *attachments.OpcNextPage == "" {
			break
		}
		if _, exists := seenPages[*attachments.OpcNextPage]; exists {
			return InstanceObservation{}, ErrInstanceObservation
		}
		seenPages[*attachments.OpcNextPage] = struct{}{}
		page = attachments.OpcNextPage
	}
	if !observation.PrimaryVNIC || !validPrivateIPv4(observation.PrimaryPrivateIP) {
		return InstanceObservation{}, ErrInstanceObservation
	}
	return observation, nil
}

// The VNIC belongs to the subnet's network compartment, which can differ from
// the instance and VNIC attachment's control compartment. Callers separately
// compare the observed subnet OCID with their signed launch intent.
func vnicSubnetMatches(vnic core.Vnic, subnet core.Subnet, instanceID string) bool {
	subnetID := value(vnic.SubnetId)
	region := regionalOCID(instanceID, "instance")
	return region != "" && regionalOCID(value(vnic.Id), "vnic") == region &&
		regionalOCID(subnetID, "subnet") == region &&
		regionalOCID(value(subnet.VcnId), "vcn") == region &&
		value(subnet.Id) == subnetID &&
		strings.HasPrefix(value(subnet.CompartmentId), "ocid1.compartment.") &&
		value(vnic.CompartmentId) == value(subnet.CompartmentId) &&
		subnet.LifecycleState == core.SubnetLifecycleStateAvailable &&
		(subnet.AvailabilityDomain == nil || value(subnet.AvailabilityDomain) == value(vnic.AvailabilityDomain))
}

func regionalOCID(id, resource string) string {
	parts := strings.Split(id, ".")
	if len(parts) != 5 || parts[0] != "ocid1" || parts[1] != resource ||
		parts[2] != "oc1" || parts[3] == "" || parts[4] == "" {
		return ""
	}
	return parts[3]
}

func value(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
