package imagequalification

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

func (c *cloud) capability(ctx context.Context, j journal) (core.ComputeImageCapabilitySchema, error) {
	r, err := c.compute.GetComputeImageCapabilitySchema(ociclient.RequestContext(ctx), core.GetComputeImageCapabilitySchemaRequest{ComputeImageCapabilitySchemaId: new(j.CapabilityID)})
	if err != nil {
		return core.ComputeImageCapabilitySchema{}, err
	}
	s := r.ComputeImageCapabilitySchema
	if s.Id == nil || *s.Id != j.CapabilityID || s.ImageId == nil || *s.ImageId != j.ImageID || s.CompartmentId == nil || *s.CompartmentId != c.prepared.approval.Compartment || s.DisplayName == nil || *s.DisplayName != c.name("capability") || !c.owns(s.FreeformTags) || s.ComputeGlobalImageCapabilitySchemaVersionName == nil || *s.ComputeGlobalImageCapabilitySchemaVersionName != j.CapabilityVersion {
		return s, errors.New("native capability schema differs from exact owned image and durable create intent")
	}
	return s, nil
}

// The production helper chooses a fresh create token, so the finite disposable
// owner creates with a durable token before reusing its canonical validation.
func (c *cloud) configureNativeBoot(ctx context.Context, path string, j *journal) error {
	a := c.prepared.approval
	if a.Candidate.Architecture != "arm64" {
		return errors.New("native image import currently requires the canonical ARM64 A1 launch contract")
	}
	if j.CapabilityDeleted {
		return errors.New("deleted native boot capability cannot be reused")
	}
	if j.CapabilityID == "" {
		if j.Intents["capability"].IsZero() {
			ids, err := c.uploader.ListCapabilitySchemas(ctx, a.Compartment, j.ImageID)
			if err != nil {
				return err
			}
			if len(ids) != 0 {
				return errors.New("refusing to adopt an unjournaled native capability schema")
			}
			j.CapabilityVersion, err = c.uploader.GlobalCapabilitySchemaVersion(ctx)
			if err != nil {
				return err
			}
			if j.CapabilityVersion == "" {
				return errors.New("global native capability schema has no version")
			}
		}
		if j.CapabilityVersion == "" {
			return errors.New("native capability intent lacks its exact global version")
		}
		if err := c.check(ctx, false); err != nil {
			return err
		}
		if err := c.intent(path, j, "capability"); err != nil {
			return err
		}
		descriptors := map[string]core.ImageCapabilitySchemaDescriptor{}
		for key, value := range imageimport.Capabilities() {
			if value.Boolean {
				descriptors[key] = core.BooleanImageCapabilitySchemaDescriptor{Source: core.ImageCapabilitySchemaDescriptorSourceImage, DefaultValue: new(value.BoolDefault)}
			} else {
				descriptors[key] = core.EnumStringImageCapabilitySchemaDescriptor{Source: core.ImageCapabilitySchemaDescriptorSourceImage, Values: value.Values, DefaultValue: new(value.Default)}
			}
		}
		r, err := c.compute.CreateComputeImageCapabilitySchema(ociclient.RequestContext(ctx), core.CreateComputeImageCapabilitySchemaRequest{CreateComputeImageCapabilitySchemaDetails: core.CreateComputeImageCapabilitySchemaDetails{CompartmentId: new(a.Compartment), ImageId: new(j.ImageID), DisplayName: new(c.name("capability")), ComputeGlobalImageCapabilitySchemaVersionName: new(j.CapabilityVersion), SchemaData: descriptors, FreeformTags: c.tags()}, OpcRetryToken: new(c.token("capability"))})
		if err != nil {
			return err
		}
		if r.Id == nil || *r.Id == "" {
			return errors.New("created native capability schema has no ID")
		}
		j.CapabilityID = *r.Id
		if err := checkpoint(path, *j); err != nil {
			return err
		}
	}
	if _, err := c.capability(ctx, *j); err != nil {
		return err
	}
	ids, err := c.uploader.ListCapabilitySchemas(ctx, a.Compartment, j.ImageID)
	if err != nil {
		return err
	}
	if len(ids) != 1 || ids[0] != j.CapabilityID {
		return errors.New("native image must have exactly its journaled capability schema")
	}
	importer := imageimport.Importer{Client: c.uploader}
	if _, err := importer.EnsureCapabilities(ctx, a.Compartment, j.ImageID, c.name("capability")); err != nil {
		return err
	}
	_, err = importer.EnsureShapes(ctx, j.ImageID)
	return err
}

func (c *cloud) cleanupCapability(ctx context.Context, path string, j *journal) error {
	if j.CapabilityID == "" || j.CapabilityDeleted {
		return nil
	}
	if err := c.check(ctx, true); err != nil {
		return err
	}
	if _, err := c.capability(ctx, *j); err != nil {
		if !isNotFound(err) {
			return err
		}
	} else {
		if _, err := c.compute.DeleteComputeImageCapabilitySchema(ociclient.RequestContext(ctx), core.DeleteComputeImageCapabilitySchemaRequest{ComputeImageCapabilitySchemaId: new(j.CapabilityID)}); err != nil && !isNotFound(err) {
			return err
		}
		for {
			_, err := c.capability(ctx, *j)
			if isNotFound(err) {
				break
			}
			if err != nil {
				return err
			}
			if err := pauseConsole(ctx); err != nil {
				return err
			}
		}
	}
	j.CapabilityDeleted = true
	return checkpoint(path, *j)
}
