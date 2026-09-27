package oci

import "testing"

func TestRegionConfigRequiresExplicitCostAndPrivateNetworkBounds(t *testing.T) {
	base, intent := testRegionConfig()
	if err := base.Validate(intent); err != nil {
		t.Fatalf("bounded OCI region config was refused: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*RegionConfig)
	}{
		{"missing boot size", func(config *RegionConfig) { config.BootVolumeGB = 0 }},
		{"missing image compartment", func(config *RegionConfig) { config.ImageCompartmentID = "" }},
		{"premium boot tier", func(config *RegionConfig) { config.BootVolumeVPUsPerGB = 20 }},
		{"premium data tier", func(config *RegionConfig) { config.DataVolumeVPUsPerGB = 20 }},
		{"missing data ceiling", func(config *RegionConfig) { config.MaxDataVolumeGB = 0 }},
		{"missing NSG", func(config *RegionConfig) { config.NetworkSecurityGroupIDs = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if err := config.Validate(intent); err == nil {
				t.Fatal("unbounded OCI region config was admitted")
			}
		})
	}
}
