package ocicost

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

type searchAPI interface {
	SearchResources(ctx context.Context, request resourcesearch.SearchResourcesRequest) (resourcesearch.SearchResourcesResponse, error)
}

type computeAPI interface {
	GetInstance(ctx context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error)
	UpdateInstance(ctx context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error)
	GetImage(ctx context.Context, request core.GetImageRequest) (core.GetImageResponse, error)
	UpdateImage(ctx context.Context, request core.UpdateImageRequest) (core.UpdateImageResponse, error)
}

type blockAPI interface {
	GetBootVolume(ctx context.Context, request core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error)
	UpdateBootVolume(ctx context.Context, request core.UpdateBootVolumeRequest) (core.UpdateBootVolumeResponse, error)
	GetVolume(ctx context.Context, request core.GetVolumeRequest) (core.GetVolumeResponse, error)
	UpdateVolume(ctx context.Context, request core.UpdateVolumeRequest) (core.UpdateVolumeResponse, error)
	GetBootVolumeBackup(ctx context.Context, request core.GetBootVolumeBackupRequest) (core.GetBootVolumeBackupResponse, error)
	UpdateBootVolumeBackup(ctx context.Context, request core.UpdateBootVolumeBackupRequest) (core.UpdateBootVolumeBackupResponse, error)
	GetVolumeBackup(ctx context.Context, request core.GetVolumeBackupRequest) (core.GetVolumeBackupResponse, error)
	UpdateVolumeBackup(ctx context.Context, request core.UpdateVolumeBackupRequest) (core.UpdateVolumeBackupResponse, error)
}

type objectAPI interface {
	GetNamespace(ctx context.Context, request objectstorage.GetNamespaceRequest) (objectstorage.GetNamespaceResponse, error)
	GetBucket(ctx context.Context, request objectstorage.GetBucketRequest) (objectstorage.GetBucketResponse, error)
	UpdateBucket(ctx context.Context, request objectstorage.UpdateBucketRequest) (objectstorage.UpdateBucketResponse, error)
}

type balancerAPI interface {
	GetLoadBalancer(ctx context.Context, request loadbalancer.GetLoadBalancerRequest) (loadbalancer.GetLoadBalancerResponse, error)
	UpdateLoadBalancer(ctx context.Context, request loadbalancer.UpdateLoadBalancerRequest) (loadbalancer.UpdateLoadBalancerResponse, error)
}

// OCITags is the Resource Search and per-type update view of one OCI region.
// Compartments, when set, scope the search; a controller leaves it empty and
// its IAM limits what it sees.
type OCITags struct {
	Compartments []string
	search       searchAPI
	compute      computeAPI
	blocks       blockAPI
	objects      objectAPI
	balancers    balancerAPI
	namespace    string // cached Object Storage namespace
}

const (
	searchLimit    = 1000
	maxSearchPages = 20
	// searchQuery lists the billable types; the lifecycle clause drops what
	// OCI has already removed.
	searchQuery = "query instance, bootvolume, volume, bootvolumebackup, volumebackup, image, bucket, loadbalancer " +
		"resources where lifecycleState != 'TERMINATED' && lifecycleState != 'TERMINATING' && lifecycleState != 'DELETED'"
)

// compartmentPattern keeps a compartment OCID out of the query string unless
// it is exactly one.
var compartmentPattern = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+$`)

// CheckCompartment refuses any compartment value that is not an OCID.
func CheckCompartment(compartment string) error {
	if !compartmentPattern.MatchString(compartment) {
		return fmt.Errorf("compartment %q is not a compartment OCID", compartment)
	}
	return nil
}

// ConnectTags builds the OCITags of factory's region.
func ConnectTags(factory *ociclient.Factory, compartments []string) (*OCITags, error) {
	search, err := factory.Search()
	if err != nil {
		return nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	blocks, err := factory.Blockstorage()
	if err != nil {
		return nil, err
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	balancers, err := factory.LoadBalancer()
	if err != nil {
		return nil, err
	}
	return &OCITags{Compartments: compartments, search: search, compute: compute, blocks: blocks,
		objects: objects, balancers: balancers}, nil
}

// Resources lists the billable resources in the region, every page.
func (t *OCITags) Resources(ctx context.Context) ([]Resource, error) {
	query := searchQuery
	if len(t.Compartments) > 0 {
		clauses := make([]string, 0, len(t.Compartments))
		for _, compartment := range t.Compartments {
			if err := CheckCompartment(compartment); err != nil {
				return nil, err
			}
			clauses = append(clauses, "compartmentId = '"+compartment+"'")
		}
		query += " && (" + strings.Join(clauses, " || ") + ")"
	}
	var resources []Resource
	var page *string
	for range maxSearchPages {
		response, err := t.search.SearchResources(ctx, resourcesearch.SearchResourcesRequest{
			SearchDetails: resourcesearch.StructuredSearchDetails{Query: common.String(query)},
			Limit:         common.Int(searchLimit),
			Page:          page,
		})
		if err != nil {
			return nil, fmt.Errorf("search OCI resources: %w", err)
		}
		for _, item := range response.Items {
			resources = append(resources, resourceOf(item))
		}
		if response.OpcNextPage == nil {
			return resources, nil
		}
		page = response.OpcNextPage
	}
	return nil, fmt.Errorf("OCI resource search returned more than %d pages", maxSearchPages)
}

func resourceOf(item resourcesearch.ResourceSummary) Resource {
	resource := Resource{ID: stringOf(item.Identifier), Type: stringOf(item.ResourceType),
		Name: stringOf(item.DisplayName), Compartment: stringOf(item.CompartmentId), Tags: item.FreeformTags}
	if item.TimeCreated != nil {
		resource.Created = item.TimeCreated.Time
	}
	return resource
}

func stringOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// tagWriter writes the whole freeform tag set back under the read's ETag.
type tagWriter func(ctx context.Context, tags map[string]string, etag *string) error

// Retag merges tags into the resource's freeform tags, keeping the rest. The
// update is conditional on the ETag of the read, so a concurrent edit makes
// it fail with ErrChanged instead of being overwritten.
func (t *OCITags) Retag(ctx context.Context, resource Resource, tags map[string]string) error {
	current, etag, write, err := t.load(ctx, resource)
	if err != nil {
		return fmt.Errorf("read OCI %s: %w", resource.Type, tagError(err))
	}
	merged := make(map[string]string, len(current)+len(tags))
	maps.Copy(merged, current)
	maps.Copy(merged, tags)
	if maps.Equal(merged, current) {
		return nil
	}
	if err := write(ctx, merged, etag); err != nil {
		return fmt.Errorf("update OCI %s tags: %w", resource.Type, tagError(err))
	}
	return nil
}

// load returns a resource's freeform tags, its ETag and the writer that
// stores tags back under that ETag.
func (t *OCITags) load(ctx context.Context, resource Resource) (map[string]string, *string, tagWriter, error) {
	id := common.String(resource.ID)
	switch resource.Type {
	case "Instance":
		read, err := t.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: id, IfMatch: etag,
				UpdateInstanceDetails: core.UpdateInstanceDetails{FreeformTags: tags}})
			return err
		}, err
	case "BootVolume":
		read, err := t.blocks.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.blocks.UpdateBootVolume(ctx, core.UpdateBootVolumeRequest{BootVolumeId: id, IfMatch: etag,
				UpdateBootVolumeDetails: core.UpdateBootVolumeDetails{FreeformTags: tags}})
			return err
		}, err
	case "Volume":
		read, err := t.blocks.GetVolume(ctx, core.GetVolumeRequest{VolumeId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.blocks.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: id, IfMatch: etag,
				UpdateVolumeDetails: core.UpdateVolumeDetails{FreeformTags: tags}})
			return err
		}, err
	case "BootVolumeBackup":
		read, err := t.blocks.GetBootVolumeBackup(ctx, core.GetBootVolumeBackupRequest{BootVolumeBackupId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.blocks.UpdateBootVolumeBackup(ctx, core.UpdateBootVolumeBackupRequest{BootVolumeBackupId: id, IfMatch: etag,
				UpdateBootVolumeBackupDetails: core.UpdateBootVolumeBackupDetails{FreeformTags: tags}})
			return err
		}, err
	case "VolumeBackup":
		read, err := t.blocks.GetVolumeBackup(ctx, core.GetVolumeBackupRequest{VolumeBackupId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.blocks.UpdateVolumeBackup(ctx, core.UpdateVolumeBackupRequest{VolumeBackupId: id, IfMatch: etag,
				UpdateVolumeBackupDetails: core.UpdateVolumeBackupDetails{FreeformTags: tags}})
			return err
		}, err
	case "Image":
		read, err := t.compute.GetImage(ctx, core.GetImageRequest{ImageId: id})
		return read.FreeformTags, read.Etag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.compute.UpdateImage(ctx, core.UpdateImageRequest{ImageId: id, IfMatch: etag,
				UpdateImageDetails: core.UpdateImageDetails{FreeformTags: tags}})
			return err
		}, err
	case "LoadBalancer":
		read, err := t.balancers.GetLoadBalancer(ctx, loadbalancer.GetLoadBalancerRequest{LoadBalancerId: id})
		return read.FreeformTags, read.ETag, func(ctx context.Context, tags map[string]string, etag *string) error {
			_, err := t.balancers.UpdateLoadBalancer(ctx, loadbalancer.UpdateLoadBalancerRequest{LoadBalancerId: id, IfMatch: etag,
				UpdateLoadBalancerDetails: loadbalancer.UpdateLoadBalancerDetails{FreeformTags: tags}})
			return err
		}, err
	case "Bucket":
		namespace, err := t.namespaceName(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		// The bucket read carries no ETag in this SDK, so the write is not
		// conditional; the merge still keeps every tag the read returned.
		read, err := t.objects.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: common.String(namespace),
			BucketName: common.String(resource.Name)})
		return read.FreeformTags, nil, func(ctx context.Context, tags map[string]string, _ *string) error {
			_, err := t.objects.UpdateBucket(ctx, objectstorage.UpdateBucketRequest{NamespaceName: common.String(namespace),
				BucketName: common.String(resource.Name), UpdateBucketDetails: objectstorage.UpdateBucketDetails{FreeformTags: tags}})
			return err
		}, err
	}
	return nil, nil, nil, fmt.Errorf("no tag update for OCI type %q", resource.Type)
}

func (t *OCITags) namespaceName(ctx context.Context) (string, error) {
	if t.namespace != "" {
		return t.namespace, nil
	}
	response, err := t.objects.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return "", fmt.Errorf("read Object Storage namespace: %w", err)
	}
	if stringOf(response.Value) == "" {
		return "", errors.New("Object Storage namespace is empty")
	}
	t.namespace = *response.Value
	return t.namespace, nil
}

// tagError maps the OCI answers Retag acts on to the pass's sentinels; any
// other error passes through.
func tagError(err error) error {
	var service common.ServiceError
	if !errors.As(err, &service) {
		return err
	}
	switch service.GetHTTPStatusCode() {
	case http.StatusPreconditionFailed:
		return fmt.Errorf("%w: %w", ErrChanged, err)
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %w", ErrNotPermitted, err)
	}
	return err
}
