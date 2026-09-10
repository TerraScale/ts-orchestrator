package vmqualruntime

import "terrascale.tech/orchestrator/src/orchestrator/vmnet"

// QualificationNetworkConfig is the single pre-planning topology builder
// shared by material preparation and the runtime command.
func QualificationNetworkConfig(full, fourthRegion bool, tapUID, tapGID uint32) vmnet.Config {
	config := vmnet.Config{Prefix: "ts", Regions: []vmnet.RegionSpec{{Code: vmnet.GRU, Guests: []vmnet.GuestSpec{{ID: "gru-member-1"}}}}}
	if full {
		config = vmnet.DefaultConfig()
	}
	if fourthRegion {
		config.Regions = append(config.Regions, vmnet.RegionSpec{Code: "IAD", Guests: []vmnet.GuestSpec{{ID: "iad-member-1"}, {ID: "iad-member-2"}}})
	}
	config.TAPUID, config.TAPGID = tapUID, tapGID
	return config
}
