package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func TestAcceptedMaterialConfigPinsMemberCompartmentAndSubnet(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	domain := &bootstrap.ManagedMaterialDomain{
		Namespace: "terrascale", Bucket: "material",
		KMSKeyOCID:               "ocid1.key.oc1.sa-saopaulo-1.material",
		MemberCompartmentOCID:    "ocid1.compartment.oc1.sa-saopaulo-1.members",
		MemberSubnetOCID:         "ocid1.subnet.oc1.sa-saopaulo-1.members",
		MemberSubnetCIDR:         "10.251.0.0/25",
		RecipientSignerPublicKey: base64.StdEncoding.EncodeToString(public),
		NativeVerifierSHA256:     strings.Repeat("a", 64),
	}
	marker := bootstrapstart.AcceptedInstall{Cell: "GRU", ManagedMaterial: domain}
	region := oci.RegionConfig{Region: oci.RegionGRU,
		CompartmentID: domain.MemberCompartmentOCID, SubnetID: domain.MemberSubnetOCID}
	config, err := acceptedMaterialConfigFromMarker(marker, "gru", region)
	if err != nil || config.repository.Namespace != domain.Namespace || config.subnetCIDR != domain.MemberSubnetCIDR {
		t.Fatalf("accepted material pins rejected: %+v, %v", config, err)
	}
	region.SubnetID = "ocid1.subnet.oc1.sa-saopaulo-1.other"
	if _, err := acceptedMaterialConfigFromMarker(marker, "gru", region); err == nil {
		t.Fatal("different member subnet was accepted")
	}
	region.SubnetID = domain.MemberSubnetOCID
	region.CompartmentID = "ocid1.compartment.oc1.sa-saopaulo-1.other"
	if _, err := acceptedMaterialConfigFromMarker(marker, "gru", region); err == nil {
		t.Fatal("different member compartment was accepted")
	}
	marker.ManagedMaterial = nil
	if _, err := acceptedMaterialConfigFromMarker(marker, "gru", region); err == nil {
		t.Fatal("missing signed material domain was accepted")
	}
}
