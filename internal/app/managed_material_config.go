package app

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

type acceptedMaterialConfig struct {
	repository           managedmaterial.RepositoryConfig
	recipientSigner      ed25519.PublicKey
	subnetCIDR           string
	nativeVerifierSHA256 string
}

// The startup gate has already verified the marker against the signed
// bootstrap manifest. Read its root-owned copy again before opening OCI.
func loadAcceptedMaterialConfig(cell string, region oci.RegionConfig) (acceptedMaterialConfig, error) {
	marker, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return acceptedMaterialConfig{}, fmt.Errorf("read accepted material domain: %w", err)
	}
	return acceptedMaterialConfigFromMarker(marker, cell, region)
}

func acceptedMaterialConfigFromMarker(marker bootstrapstart.AcceptedInstall, cell string,
	region oci.RegionConfig,
) (acceptedMaterialConfig, error) {
	domain := marker.ManagedMaterial
	if domain == nil || !strings.EqualFold(marker.Cell, cell) ||
		!strings.EqualFold(string(region.Region), cell) ||
		domain.MemberCompartmentOCID != region.CompartmentID ||
		domain.MemberSubnetOCID != region.SubnetID {
		return acceptedMaterialConfig{}, errors.New("regional fleet differs from the signed accepted material domain")
	}
	if err := domain.Validate(); err != nil {
		return acceptedMaterialConfig{}, err
	}
	signer, err := decodePublicKey(domain.RecipientSignerPublicKey)
	if err != nil {
		return acceptedMaterialConfig{}, err
	}
	config := acceptedMaterialConfig{repository: managedmaterial.RepositoryConfig{
		Region: region.Region, Cell: cell, Namespace: domain.Namespace,
		Bucket: domain.Bucket, KMSKeyID: domain.KMSKeyOCID,
	}, recipientSigner: signer, subnetCIDR: domain.MemberSubnetCIDR,
		nativeVerifierSHA256: domain.NativeVerifierSHA256}
	if err := config.repository.Validate(); err != nil {
		return acceptedMaterialConfig{}, err
	}
	return config, nil
}
