package oci

import (
	"context"
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// VolumeAttachmentLister is the optional Provider seam that lists the
// attachment records of one volume with OCI's VolumeId filter instead of
// paging through every attachment in the compartment.
type VolumeAttachmentLister interface {
	ListVolumeAttachmentsByVolume(ctx context.Context, compartmentID, availabilityDomain, volumeID string) ([]CloudAttachment, error)
}

func (provider *sdkProvider) ListVolumeAttachmentsByVolume(ctx context.Context, compartmentID, availabilityDomain, volumeID string) ([]CloudAttachment, error) {
	if compartmentID != provider.config.CompartmentID || availabilityDomain != provider.config.AvailabilityDomain {
		return nil, ErrForeignResource
	}
	if volumeID == "" {
		return nil, errors.New("OCI volume attachment lookup requires a volume ID")
	}
	var attachments []CloudAttachment
	var page *string
	for {
		response, err := provider.compute.ListVolumeAttachments(ctx, core.ListVolumeAttachmentsRequest{
			CompartmentId: new(compartmentID), AvailabilityDomain: new(availabilityDomain),
			VolumeId: new(volumeID), Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI volume attachments: %w", err)
		}
		for _, attachment := range response.Items {
			attachments = append(attachments, cloudAttachment(attachment, ""))
			if len(attachments) > maxProviderItems {
				return nil, errors.New("OCI attachment list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return attachments, nil
		}
		page = response.OpcNextPage
	}
}
