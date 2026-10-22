package swarmruntime

import "testing"

func TestPortConflict(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		holder                portHolder
		sameService, starting bool
		conflict              bool
	}{
		{"exited predecessor releases at prepare", holderExited, true, false, false},
		{"exited predecessor releases at start", holderExited, true, true, false},
		{"exited other service releases", holderExited, false, false, false},
		{"replacement prepares beside live predecessor", holderLive, true, false, false},
		{"replacement never starts beside live predecessor", holderLive, true, true, true},
		{"other service live refuses prepare", holderLive, false, false, true},
		{"other service prepared refuses prepare", holderPrepared, false, false, true},
		{"same service prepared allows prepare", holderPrepared, true, false, false},
		{"prepared holder binds nothing at start", holderPrepared, true, true, false},
	} {
		if got := portConflict(tc.holder, tc.sameService, tc.starting); got != tc.conflict {
			t.Errorf("%s: conflict = %t", tc.name, got)
		}
	}
}
