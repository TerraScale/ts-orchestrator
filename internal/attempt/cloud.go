package attempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

// Instance is the normalized Compute instance state the attempt reads.
type Instance struct {
	ID, DisplayName, LifecycleState string
	// The launch identity, compared with a retained launch input.
	CompartmentID, AvailabilityDomain, FaultDomain, Shape, ImageID string
	// OCPUs and MemoryInGBs size a flexible shape, which its name does not.
	OCPUs, MemoryInGBs     float32
	Metadata, FreeformTags map[string]string
}

// Cloud is the typed OCI seam of an attempt. The default implementation is
// the in-binary OCI Go SDK over the operator's ~/.oci/config; tests supply a
// fake. No attempt phase runs the Python OCI CLI.
type Cloud interface {
	// PolicyStatements returns a policy's statements and its ETag.
	PolicyStatements(ctx context.Context, policyID string) ([]string, string, error)
	// ReplacePolicyStatements replaces the statements of the policy version
	// identified by etag.
	ReplacePolicyStatements(ctx context.Context, policyID, etag string, statements []string) error
	ListObjects(ctx context.Context, namespace, bucket, prefix string) ([]string, error)
	// GetObject returns an object's bytes, or found=false when it is absent.
	GetObject(ctx context.Context, namespace, bucket, name string) (data []byte, found bool, err error)
	// LaunchInstance submits one launch. The retry token makes a replay of
	// the same launch input within 24 hours return the original instance.
	LaunchInstance(ctx context.Context, details core.LaunchInstanceDetails, retryToken string) (core.Instance, string, error)
	GetInstance(ctx context.Context, id string) (Instance, error)
	ListInstances(ctx context.Context, compartment string) ([]Instance, error)
}

// seedLaunch is the launch input `oci-region preview seed-launch` writes. It
// is the document the Python CLI accepted with `compute instance launch
// --from-json`: subnetId, privateIp, nsgIds and assignPublicIp are CLI
// conveniences that the API carries in createVnicDetails.
type seedLaunch struct {
	AvailabilityDomain string `json:"availabilityDomain"`
	FaultDomain        string `json:"faultDomain"`
	CompartmentID      string `json:"compartmentId"`
	DisplayName        string `json:"displayName"`
	Shape              string `json:"shape"`
	ShapeConfig        struct {
		OCPUs       float32 `json:"ocpus"`
		MemoryInGBs float32 `json:"memoryInGBs"`
	} `json:"shapeConfig"`
	SourceDetails struct {
		SourceType          string `json:"sourceType"`
		ImageID             string `json:"imageId"`
		BootVolumeSizeInGBs int64  `json:"bootVolumeSizeInGBs"`
		BootVolumeVpusPerGB int64  `json:"bootVolumeVpusPerGB"`
	} `json:"sourceDetails"`
	SubnetID       string            `json:"subnetId"`
	PrivateIP      string            `json:"privateIp"`
	NSGIDs         []string          `json:"nsgIds"`
	AssignPublicIP *bool             `json:"assignPublicIp"`
	Metadata       map[string]string `json:"metadata"`
	FreeformTags   map[string]string `json:"freeformTags"`
}

// LaunchDetails decodes a controller launch input into the SDK launch
// request. Every member must be known and present: an unknown member would
// otherwise be dropped silently from the launch.
func LaunchDetails(wire []byte) (core.LaunchInstanceDetails, error) {
	var input seedLaunch
	if err := json.Unmarshal(wire, &input, json.RejectUnknownMembers(true)); err != nil {
		return core.LaunchInstanceDetails{}, fmt.Errorf("decode controller launch input: %w", err)
	}
	source := input.SourceDetails
	if input.AvailabilityDomain == "" || input.FaultDomain == "" || input.CompartmentID == "" || input.DisplayName == "" ||
		input.Shape == "" || input.ShapeConfig.OCPUs <= 0 || input.ShapeConfig.MemoryInGBs <= 0 ||
		source.SourceType != "image" || source.ImageID == "" || source.BootVolumeSizeInGBs <= 0 || source.BootVolumeVpusPerGB <= 0 ||
		input.SubnetID == "" || input.PrivateIP == "" || len(input.NSGIDs) == 0 || input.AssignPublicIP == nil ||
		len(input.Metadata) == 0 || len(input.FreeformTags) == 0 {
		return core.LaunchInstanceDetails{}, errors.New("controller launch input lacks a required member")
	}
	return core.LaunchInstanceDetails{
		AvailabilityDomain: &input.AvailabilityDomain, FaultDomain: &input.FaultDomain, CompartmentId: &input.CompartmentID,
		DisplayName: &input.DisplayName, Shape: &input.Shape,
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{Ocpus: &input.ShapeConfig.OCPUs, MemoryInGBs: &input.ShapeConfig.MemoryInGBs},
		SourceDetails: core.InstanceSourceViaImageDetails{ImageId: &source.ImageID,
			BootVolumeSizeInGBs: &source.BootVolumeSizeInGBs, BootVolumeVpusPerGB: &source.BootVolumeVpusPerGB},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: &input.SubnetID, PrivateIp: &input.PrivateIP,
			NsgIds: input.NSGIDs, AssignPublicIp: input.AssignPublicIP},
		Metadata: input.Metadata, FreeformTags: input.FreeformTags,
	}, nil
}

// LaunchRetryToken binds an OCI retry token to the exact launch input bytes.
func LaunchRetryToken(wire []byte) string {
	sum := sha256.Sum256(wire)
	return "ts-attempt-" + hex.EncodeToString(sum[:])[:48]
}

type sdkCloud struct {
	compute  core.ComputeClient
	objects  objectstorage.ObjectStorageClient
	identity identity.IdentityClient
}

func newSDKCloud(region string) (Cloud, error) {
	factory, err := ociclient.OperatorConfig(region)
	if err != nil {
		return nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	iam, err := factory.Identity()
	if err != nil {
		return nil, err
	}
	return &sdkCloud{compute: compute, objects: objects, identity: iam}, nil
}

// maxPages bounds every paginated list so a misbehaving endpoint cannot loop.
const maxPages = 256

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (c *sdkCloud) PolicyStatements(ctx context.Context, policyID string) ([]string, string, error) {
	response, err := c.identity.GetPolicy(ctx, identity.GetPolicyRequest{PolicyId: &policyID})
	if err != nil {
		return nil, "", fmt.Errorf("get OCI policy: %w", err)
	}
	return response.Statements, deref(response.Etag), nil
}

func (c *sdkCloud) ReplacePolicyStatements(ctx context.Context, policyID, etag string, statements []string) error {
	if etag == "" {
		return errors.New("refusing an OCI policy update without an If-Match ETag")
	}
	request := identity.UpdatePolicyRequest{PolicyId: &policyID, IfMatch: &etag,
		UpdatePolicyDetails: identity.UpdatePolicyDetails{Statements: statements}}
	if _, err := c.identity.UpdatePolicy(ctx, request); err != nil {
		return fmt.Errorf("update OCI policy: %w", err)
	}
	return nil
}

func (c *sdkCloud) ListObjects(ctx context.Context, namespace, bucket, prefix string) ([]string, error) {
	names := []string{}
	var start *string
	for range maxPages {
		response, err := c.objects.ListObjects(ctx, objectstorage.ListObjectsRequest{NamespaceName: &namespace,
			BucketName: &bucket, Prefix: &prefix, Start: start})
		if err != nil {
			return nil, fmt.Errorf("list OCI objects: %w", err)
		}
		for _, item := range response.Objects {
			names = append(names, deref(item.Name))
		}
		if response.NextStartWith == nil || *response.NextStartWith == "" {
			return names, nil
		}
		start = response.NextStartWith
	}
	return nil, errors.New("OCI object list exceeds its page bound")
}

// maxObjectBytes bounds an accepted-install marker read.
const maxObjectBytes = 1 << 20

func (c *sdkCloud) GetObject(ctx context.Context, namespace, bucket, name string) ([]byte, bool, error) {
	response, err := c.objects.GetObject(ctx, objectstorage.GetObjectRequest{NamespaceName: &namespace,
		BucketName: &bucket, ObjectName: &name})
	if err != nil {
		if failure, ok := common.IsServiceError(err); ok && failure.GetHTTPStatusCode() == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get OCI object: %w", err)
	}
	defer response.Content.Close()
	var data bytes.Buffer
	if _, err := io.Copy(&data, io.LimitReader(response.Content, maxObjectBytes+1)); err != nil {
		return nil, false, fmt.Errorf("read OCI object: %w", err)
	}
	if data.Len() > maxObjectBytes {
		return nil, false, fmt.Errorf("OCI object %s exceeds %d bytes", name, maxObjectBytes)
	}
	return data.Bytes(), true, nil
}

func (c *sdkCloud) LaunchInstance(ctx context.Context, details core.LaunchInstanceDetails, retryToken string) (core.Instance, string, error) {
	response, err := c.compute.LaunchInstance(ctx, core.LaunchInstanceRequest{LaunchInstanceDetails: details, OpcRetryToken: &retryToken})
	if err != nil {
		return core.Instance{}, "", fmt.Errorf("launch OCI instance: %w", err)
	}
	return response.Instance, deref(response.OpcWorkRequestId), nil
}

func instance(item core.Instance) Instance {
	image := deref(item.ImageId)
	if source, ok := item.SourceDetails.(core.InstanceSourceViaImageDetails); ok {
		image = deref(source.ImageId)
	}
	launched := Instance{ID: deref(item.Id), DisplayName: deref(item.DisplayName), LifecycleState: string(item.LifecycleState),
		CompartmentID: deref(item.CompartmentId), AvailabilityDomain: deref(item.AvailabilityDomain),
		FaultDomain: deref(item.FaultDomain), Shape: deref(item.Shape), ImageID: image,
		Metadata: item.Metadata, FreeformTags: item.FreeformTags}
	if config := item.ShapeConfig; config != nil && config.Ocpus != nil && config.MemoryInGBs != nil {
		launched.OCPUs, launched.MemoryInGBs = *config.Ocpus, *config.MemoryInGBs
	}
	return launched
}

// launchedFrom reports whether instance is the launch of details: the same
// name, compartment, placement, shape and its OCPUs and memory, boot image,
// metadata and tags.
func launchedFrom(instance Instance, details core.LaunchInstanceDetails) bool {
	source, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	config := details.ShapeConfig
	return ok && config != nil && config.Ocpus != nil && config.MemoryInGBs != nil &&
		instance.OCPUs == *config.Ocpus && instance.MemoryInGBs == *config.MemoryInGBs &&
		instance.DisplayName == deref(details.DisplayName) && instance.CompartmentID == deref(details.CompartmentId) &&
		instance.AvailabilityDomain == deref(details.AvailabilityDomain) && instance.FaultDomain == deref(details.FaultDomain) &&
		instance.Shape == deref(details.Shape) && instance.ImageID == deref(source.ImageId) &&
		maps.Equal(instance.Metadata, details.Metadata) && maps.Equal(instance.FreeformTags, details.FreeformTags)
}

func (c *sdkCloud) GetInstance(ctx context.Context, id string) (Instance, error) {
	response, err := c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: &id})
	if err != nil {
		return Instance{}, fmt.Errorf("get OCI instance: %w", err)
	}
	return instance(response.Instance), nil
}

func (c *sdkCloud) ListInstances(ctx context.Context, compartment string) ([]Instance, error) {
	var instances []Instance
	var page *string
	for range maxPages {
		response, err := c.compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &compartment, Page: page})
		if err != nil {
			return nil, fmt.Errorf("list OCI instances: %w", err)
		}
		for _, item := range response.Items {
			instances = append(instances, instance(item))
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return instances, nil
		}
		page = response.OpcNextPage
	}
	return nil, errors.New("OCI instance list exceeds its page bound")
}
