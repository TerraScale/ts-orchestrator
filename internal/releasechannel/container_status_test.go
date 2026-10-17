package releasechannel

import (
	"errors"
	"testing"
	"time"
)

func TestContainerStatusCannotEraseOperationOrSequence(t *testing.T) {
	previous := ContainerStatus{Schema: ContainerStatusSchema, OperationID: "original", Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "amd64", Image: "image", ReleaseSequence: 7, Fingerprint: "claim", State: StateRolling, UpdatedAt: time.Now().UTC()}
	for _, test := range []struct {
		name   string
		change func(*ContainerStatus)
		want   error
	}{
		{"older sequence", func(s *ContainerStatus) { s.ReleaseSequence-- }, ErrStale},
		{"same sequence other operation", func(s *ContainerStatus) { s.OperationID = "successor" }, ErrConflict},
		{"same sequence other release", func(s *ContainerStatus) { s.Fingerprint = "other" }, ErrConflict},
		{"complete current operation", func(s *ContainerStatus) { s.State = StateComplete }, nil},
		{"new sequence", func(s *ContainerStatus) { s.ReleaseSequence++; s.OperationID = "successor" }, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := previous
			test.change(&next)
			if err := containerStatusAdvance(previous, next); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	previous.State = StateComplete
	next := previous
	next.State = StateFailed
	if err := containerStatusAdvance(previous, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal result replaced: %v", err)
	}
}
