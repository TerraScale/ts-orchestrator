package oci

const (
	testMember       = "gru-1-db-1"
	testMemberVolume = "gru-1-db-1-data"
)

func testMemberVolumeConfig() MemberVolumeConfig {
	return MemberVolumeConfig{Region: "GRU", CompartmentID: "ocid1.compartment.members", AvailabilityDomain: "AD-1", VPUsPerGB: 10}
}

// memberVolumeFixture builds MemberVolumes over the shared fake provider, or
// over provider when one is given. Created volumes become AVAILABLE at once.
