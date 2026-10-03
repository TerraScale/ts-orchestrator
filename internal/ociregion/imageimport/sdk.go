package imageimport

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/objectstorage/transfer"
	"github.com/oracle/oci-go-sdk/v65/workrequests"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

// maxPages bounds every paginated list so a misbehaving endpoint cannot loop.
const maxPages = 64

type sdkClient struct {
	compute     core.ComputeClient
	objects     objectstorage.ObjectStorageClient
	workRequest workrequests.WorkRequestClient
	upload      *transfer.UploadManager
	// uploadRetry treats the content-addressed part PUTs as replayable: a part
	// upload of the same bytes to the same part number is idempotent, and the
	// commit refuses to overwrite an existing object.
	uploadRetry common.RetryPolicy
}

// NewSDKClient builds the in-binary OCI client for one region from the
// operator's ~/.oci/config DEFAULT profile, through the shared rate-limited
// factory.
func NewSDKClient(region string) (API, error) {
	factory, err := ociclient.OperatorConfig(region)
	if err != nil {
		return nil, err
	}
	return NewClient(factory, "")
}

// NewClient builds the SDK client over an existing factory. An empty endpoint
// addresses the factory region's public OCI endpoints. A non-empty endpoint
// pins the Compute, Object Storage and work request clients to that one
// origin. No flag or environment variable reaches it: only Go callers pass
// it, and the promotion tests use it to aim the real client at a local OCI
// stand-in.
func NewClient(factory *ociclient.Factory, endpoint string) (API, error) {
	return newSDKClient(factory, endpoint)
}

func newSDKClient(factory *ociclient.Factory, endpoint string) (*sdkClient, error) {
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	work, err := factory.WorkRequests()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&compute.BaseClient, endpoint)
	ociclient.PinHost(&objects.BaseClient, endpoint)
	ociclient.PinHost(&work.BaseClient, endpoint)
	return &sdkClient{compute: compute, objects: objects, workRequest: work, upload: transfer.NewUploadManager(),
		uploadRetry: ociclient.IdempotentPutRetryPolicy(ociclient.RetryOptions{})}, nil
}

func page(next *string) (*string, bool) {
	if next == nil || *next == "" {
		return nil, false
	}
	return next, true
}

func (c *sdkClient) ListImages(ctx context.Context, compartment, displayName string) ([]Image, error) {
	var images []Image
	var cursor *string
	for range maxPages {
		response, err := c.compute.ListImages(ctx, core.ListImagesRequest{CompartmentId: new(compartment),
			DisplayName: new(displayName), Page: cursor})
		if err != nil {
			return nil, fmt.Errorf("list OCI images: %w", err)
		}
		for _, item := range response.Items {
			images = append(images, image(item))
		}
		var more bool
		if cursor, more = page(response.OpcNextPage); !more {
			return images, nil
		}
	}
	return nil, errors.New("OCI image list exceeds its page bound")
}

func image(item core.Image) Image {
	return Image{ID: deref(item.Id), LifecycleState: string(item.LifecycleState), BillableSizeGB: item.BillableSizeInGBs}
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (c *sdkClient) GetImage(ctx context.Context, id string) (Image, error) {
	response, err := c.compute.GetImage(ctx, core.GetImageRequest{ImageId: new(id)})
	if err != nil {
		return Image{}, fmt.Errorf("get OCI image: %w", err)
	}
	return image(response.Image), nil
}

func (c *sdkClient) HeadObject(ctx context.Context, namespace, bucket, object string) (bool, map[string]string, error) {
	response, err := c.objects.HeadObject(ctx, objectstorage.HeadObjectRequest{NamespaceName: new(namespace),
		BucketName: new(bucket), ObjectName: new(object)})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("head OCI object: %w", err)
	}
	return true, response.OpcMeta, nil
}

func (c *sdkClient) UploadObject(ctx context.Context, request UploadRequest) error {
	_, err := c.upload.UploadFile(ctx, transfer.UploadFileRequest{
		UploadRequest: transfer.UploadRequest{
			NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
			PartSize: new(request.PartSize), NumberOfGoroutines: new(request.Parallelism),
			AllowMultipartUploads: new(true), AllowParrallelUploads: new(true),
			EnableMultipartChecksumVerification: new(true),
			ObjectStorageClient:                 &c.objects, IfNoneMatch: new("*"), Metadata: request.Metadata,
			RequestMetadata: common.RequestMetadata{RetryPolicy: &c.uploadRetry},
		},
		FilePath: request.Path,
	})
	if err != nil {
		return fmt.Errorf("upload OCI object: %w", err)
	}
	return nil
}

func (c *sdkClient) ImportImage(ctx context.Context, request ImportRequest) (Image, string, error) {
	response, err := c.compute.CreateImage(ctx, core.CreateImageRequest{
		CreateImageDetails: core.CreateImageDetails{
			CompartmentId: new(request.Compartment), DisplayName: new(request.DisplayName),
			LaunchMode: core.CreateImageDetailsLaunchModeParavirtualized,
			ImageSourceDetails: core.ImageSourceViaObjectStorageTupleDetails{
				NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
				SourceImageType: core.ImageSourceDetailsSourceImageTypeQcow2,
				OperatingSystem: new("Custom"), OperatingSystemVersion: new("Custom"),
			},
		},
		// A retry token lets the shared policy replay a lost CreateImage safely.
		OpcRetryToken: new(common.RetryToken()),
	})
	if err != nil {
		return Image{}, "", fmt.Errorf("import OCI image: %w", err)
	}
	return image(response.Image), deref(response.OpcWorkRequestId), nil
}

func (c *sdkClient) GetWorkRequest(ctx context.Context, id string) (WorkRequestStatus, error) {
	response, err := c.workRequest.GetWorkRequest(ctx, workrequests.GetWorkRequestRequest{WorkRequestId: new(id)})
	if err != nil {
		return "", fmt.Errorf("get OCI work request: %w", err)
	}
	return WorkRequestStatus(response.Status), nil
}

func (c *sdkClient) ListCapabilitySchemas(ctx context.Context, compartment, imageID string) ([]string, error) {
	var ids []string
	var cursor *string
	for range maxPages {
		response, err := c.compute.ListComputeImageCapabilitySchemas(ctx, core.ListComputeImageCapabilitySchemasRequest{
			CompartmentId: new(compartment), ImageId: new(imageID), Page: cursor})
		if err != nil {
			return nil, fmt.Errorf("list OCI image capability schemas: %w", err)
		}
		for _, item := range response.Items {
			ids = append(ids, deref(item.Id))
		}
		var more bool
		if cursor, more = page(response.OpcNextPage); !more {
			return ids, nil
		}
	}
	return nil, errors.New("OCI capability schema list exceeds its page bound")
}

func capabilitySchema(id *string, data map[string]core.ImageCapabilitySchemaDescriptor) CapabilitySchema {
	schema := CapabilitySchema{ID: deref(id), Data: make(map[string]Capability, len(data))}
	for key, descriptor := range data {
		switch value := descriptor.(type) {
		case core.EnumStringImageCapabilitySchemaDescriptor:
			schema.Data[key] = Capability{Values: value.Values, Default: deref(value.DefaultValue)}
		case core.BooleanImageCapabilitySchemaDescriptor:
			schema.Data[key] = Capability{Boolean: true, BoolDefault: value.DefaultValue != nil && *value.DefaultValue}
		}
	}
	return schema
}

func (c *sdkClient) GetCapabilitySchema(ctx context.Context, id string) (CapabilitySchema, error) {
	response, err := c.compute.GetComputeImageCapabilitySchema(ctx, core.GetComputeImageCapabilitySchemaRequest{
		ComputeImageCapabilitySchemaId: new(id)})
	if err != nil {
		return CapabilitySchema{}, fmt.Errorf("get OCI image capability schema: %w", err)
	}
	return capabilitySchema(response.Id, response.SchemaData), nil
}

func (c *sdkClient) GlobalCapabilitySchemaVersion(ctx context.Context) (string, error) {
	// The first listed schema is used, as with the CLI's --all listing; a
	// first page that is empty but has more pages is followed.
	var cursor *string
	for range maxPages {
		response, err := c.compute.ListComputeGlobalImageCapabilitySchemas(ctx,
			core.ListComputeGlobalImageCapabilitySchemasRequest{Page: cursor})
		if err != nil {
			return "", fmt.Errorf("list OCI global image capability schemas: %w", err)
		}
		if len(response.Items) > 0 {
			return deref(response.Items[0].CurrentVersionName), nil
		}
		var more bool
		if cursor, more = page(response.OpcNextPage); !more {
			return "", errors.New("OCI returned no global capability schema")
		}
	}
	return "", errors.New("OCI global capability schema list exceeds its page bound")
}

func (c *sdkClient) CreateCapabilitySchema(ctx context.Context, compartment, imageID, displayName, version string, data map[string]Capability) (CapabilitySchema, error) {
	descriptors := make(map[string]core.ImageCapabilitySchemaDescriptor, len(data))
	for key, capability := range data {
		if capability.Boolean {
			descriptors[key] = core.BooleanImageCapabilitySchemaDescriptor{Source: core.ImageCapabilitySchemaDescriptorSourceImage,
				DefaultValue: new(capability.BoolDefault)}
			continue
		}
		descriptors[key] = core.EnumStringImageCapabilitySchemaDescriptor{Source: core.ImageCapabilitySchemaDescriptorSourceImage,
			Values: capability.Values, DefaultValue: new(capability.Default)}
	}
	response, err := c.compute.CreateComputeImageCapabilitySchema(ctx, core.CreateComputeImageCapabilitySchemaRequest{
		CreateComputeImageCapabilitySchemaDetails: core.CreateComputeImageCapabilitySchemaDetails{
			CompartmentId: new(compartment), ImageId: new(imageID), DisplayName: new(displayName),
			ComputeGlobalImageCapabilitySchemaVersionName: new(version), SchemaData: descriptors,
		},
		OpcRetryToken: new(common.RetryToken()),
	})
	if err != nil {
		return CapabilitySchema{}, fmt.Errorf("create OCI image capability schema: %w", err)
	}
	return capabilitySchema(response.Id, response.SchemaData), nil
}

func (c *sdkClient) ListShapes(ctx context.Context, imageID string) ([]ShapeEntry, error) {
	var entries []ShapeEntry
	var cursor *string
	for range maxPages {
		response, err := c.compute.ListImageShapeCompatibilityEntries(ctx, core.ListImageShapeCompatibilityEntriesRequest{
			ImageId: new(imageID), Page: cursor})
		if err != nil {
			return nil, fmt.Errorf("list OCI image shape compatibility: %w", err)
		}
		for _, item := range response.Items {
			entry := ShapeEntry{Shape: deref(item.Shape)}
			if item.OcpuConstraints != nil && item.OcpuConstraints.Min != nil && item.OcpuConstraints.Max != nil {
				entry.OCPU = &Range{Min: *item.OcpuConstraints.Min, Max: *item.OcpuConstraints.Max}
			}
			if item.MemoryConstraints != nil && item.MemoryConstraints.MinInGBs != nil && item.MemoryConstraints.MaxInGBs != nil {
				entry.MemoryGB = &Range{Min: *item.MemoryConstraints.MinInGBs, Max: *item.MemoryConstraints.MaxInGBs}
			}
			entries = append(entries, entry)
		}
		var more bool
		if cursor, more = page(response.OpcNextPage); !more {
			return entries, nil
		}
	}
	return nil, errors.New("OCI shape compatibility list exceeds its page bound")
}

func (c *sdkClient) AddShape(ctx context.Context, imageID string, entry ShapeEntry) error {
	details := core.AddImageShapeCompatibilityEntryDetails{}
	if entry.OCPU != nil {
		details.OcpuConstraints = &core.ImageOcpuConstraints{Min: new(entry.OCPU.Min), Max: new(entry.OCPU.Max)}
	}
	if entry.MemoryGB != nil {
		details.MemoryConstraints = &core.ImageMemoryConstraints{MinInGBs: new(entry.MemoryGB.Min), MaxInGBs: new(entry.MemoryGB.Max)}
	}
	_, err := c.compute.AddImageShapeCompatibilityEntry(ctx, core.AddImageShapeCompatibilityEntryRequest{
		ImageId: new(imageID), ShapeName: new(entry.Shape), AddImageShapeCompatibilityEntryDetails: details})
	if err != nil {
		return fmt.Errorf("add OCI image shape compatibility: %w", err)
	}
	return nil
}

func (c *sdkClient) RemoveShape(ctx context.Context, imageID, shape string) error {
	_, err := c.compute.RemoveImageShapeCompatibilityEntry(ctx, core.RemoveImageShapeCompatibilityEntryRequest{
		ImageId: new(imageID), ShapeName: new(shape)})
	if err != nil {
		return fmt.Errorf("remove OCI image shape compatibility: %w", err)
	}
	return nil
}
