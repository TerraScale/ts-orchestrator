package hostagent

import "testing"

func TestEffectiveMemoryCapacityUsesMatchingCgroupTotal(t *testing.T) {
	const (
		hostTotal     = 64 << 20 // KiB: 64 GiB
		hostAvailable = 60 << 20 // KiB
		groupLimit    = 2 << 30  // bytes: 2 GiB
		groupCurrent  = 1 << 30  // bytes: 1 GiB
	)

	total, available, err := effectiveMemoryCapacity(hostTotal, hostAvailable, groupLimit, groupCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2<<20 || available != 1<<20 {
		t.Fatalf("effective memory = total %d KiB, available %d KiB, want 2097152 KiB and 1048576 KiB", total, available)
	}
	utilization := float64(total-available) / float64(total) * 100
	if utilization != 50 {
		t.Fatalf("memory utilization = %g%%, want 50%%", utilization)
	}
}

func TestEffectiveMemoryCapacityPreservesHostWithoutCgroupLimit(t *testing.T) {
	total, available, err := effectiveMemoryCapacity(64<<20, 32<<20, ^uint64(0), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if total != 64<<20 || available != 32<<20 {
		t.Fatalf("effective memory = total %d KiB, available %d KiB", total, available)
	}
}

func TestEffectiveMemoryCapacityFailsClosedForInvalidCgroupReadings(t *testing.T) {
	tests := []struct {
		name          string
		hostTotal     uint64
		hostAvailable uint64
		groupLimit    uint64
		groupCurrent  uint64
	}{
		{name: "over limit", hostTotal: 64 << 20, hostAvailable: 32 << 20, groupLimit: 2 << 30, groupCurrent: 3 << 30},
		{name: "host available exceeds total", hostTotal: 1, hostAvailable: 2, groupLimit: ^uint64(0)},
		{name: "sub KiB limit", hostTotal: 64 << 20, hostAvailable: 32 << 20, groupLimit: 1023},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := effectiveMemoryCapacity(test.hostTotal, test.hostAvailable, test.groupLimit, test.groupCurrent); err == nil {
				t.Fatal("invalid memory reading was accepted")
			}
		})
	}
}
