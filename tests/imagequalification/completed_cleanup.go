package imagequalification

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// verifyCompletedCleanup only observes settled resources after the disposable
// principal is gone; issuer credentials never replace its mutation authority.
func verifyCompletedCleanup(ctx context.Context, p Prepared, observer *ociclient.Factory, path string) error {
	if ctx == nil || observer == nil || observer.Region() != p.approval.OCIRegion {
		return errors.New("original regional cleanup observer required")
	}
	tenancy, err := observer.Provider().TenancyOCID()
	if err != nil || tenancy != p.approval.Tenancy {
		return errors.New("completed cleanup observer differs from original tenancy")
	}
	c := &cloud{prepared: p, now: time.Now}
	guard := func(ctx context.Context) error { return c.check(ctx, true) }
	if err := guard(ctx); err != nil {
		return err
	}
	bounded, cancel := context.WithDeadline(ctx, p.approval.CleanupUntil)
	defer cancel()
	bounded = ociclient.WithAuthority(ociclient.WithRequestGuard(bounded, guard), guard)
	j, err := c.loadExisting(path)
	if err != nil {
		return err
	}
	if len(j.RetainedReaderProof) != 0 {
		if _, err := c.retainImage(j); err != nil {
			return err
		}
	}
	if j.ImageManifestSHA256 != "" && !validHash(j.ImageManifestSHA256) {
		return errors.New("completed cleanup immutable image reference is invalid")
	}
	for operation := range j.Intents {
		if !j.resolved(operation) {
			return errors.New("completed cleanup has unresolved original create intent")
		}
	}
	compute, err := observer.Compute()
	if err != nil {
		return err
	}
	for _, spec := range p.approval.Hosts {
		id := j.Hosts[spec.Name]
		if id == "" {
			continue
		}
		host, err := compute.GetInstance(ociclient.RequestContext(bounded), core.GetInstanceRequest{InstanceId: new(id)})
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if host.Id == nil || *host.Id != id || host.CompartmentId == nil || *host.CompartmentId != p.approval.Compartment ||
			host.ImageId == nil || *host.ImageId != j.ImageID || host.LifecycleState != core.InstanceLifecycleStateTerminated {
			return errors.New("original disposable host is not verifiably terminated")
		}
	}
	for operation, id := range j.ConsoleHistories {
		parts := strings.Split(operation, "/")
		if len(parts) != 3 || parts[0] != "console" || j.Hosts[parts[1]] == "" || id == "" {
			return errors.New("completed cleanup console differs from original host journal")
		}
		_, err := compute.GetConsoleHistory(ociclient.RequestContext(bounded), core.GetConsoleHistoryRequest{InstanceConsoleHistoryId: new(id)})
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		return errors.New("original console history still exists")
	}
	objects, err := observer.ObjectStorage()
	if err != nil {
		return err
	}
	_, err = objects.HeadObject(ociclient.RequestContext(bounded), objectstorage.HeadObjectRequest{
		NamespaceName: new(p.approval.Namespace), BucketName: new(p.approval.Bucket), ObjectName: new(j.Object),
	})
	if !isNotFound(err) {
		if err != nil {
			return err
		}
		return errors.New("original qualification source object still exists")
	}
	if j.ImageID != "" {
		image, err := compute.GetImage(ociclient.RequestContext(bounded), core.GetImageRequest{ImageId: new(j.ImageID)})
		if err != nil && !isNotFound(err) {
			return err
		}
		if err == nil {
			if image.Id == nil || *image.Id != j.ImageID || image.CompartmentId == nil || *image.CompartmentId != p.approval.Compartment {
				return errors.New("completed cleanup image differs from original exact scope")
			}
			if image.LifecycleState != core.ImageLifecycleStateDeleted {
				if !validHash(j.ImageManifestSHA256) {
					return errors.New("remaining image lacks original immutable transfer reference")
				}
				transfer, err := c.observeImageTransfer(bounded, observer, j)
				if err != nil {
					return err
				}
				if transfer.manifestSHA256 != j.ImageManifestSHA256 || transfer.imageID != j.ImageID || transfer.approvalSHA256 != p.approvalSHA256 {
					return errors.New("remaining image lacks freshly authenticated original ownership transfer")
				}
				return guard(bounded)
			}
		}
	}
	if j.CapabilityID != "" {
		capability, err := compute.GetComputeImageCapabilitySchema(ociclient.RequestContext(bounded), core.GetComputeImageCapabilitySchemaRequest{ComputeImageCapabilitySchemaId: new(j.CapabilityID)})
		if err != nil && !isNotFound(err) {
			return err
		}
		if err == nil && (capability.Id == nil || *capability.Id != j.CapabilityID || capability.ImageId == nil || *capability.ImageId != j.ImageID ||
			capability.CompartmentId == nil || *capability.CompartmentId != p.approval.Compartment || capability.LifecycleState != core.ComputeImageCapabilitySchemaLifecycleStateDeleted) {
			return errors.New("original image capability is not verifiably deleted")
		}
	}
	return guard(bounded)
}
