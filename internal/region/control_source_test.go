package region

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestControlStreamRequiresRetainedReplicatedIdentity(t *testing.T) {
	stream := func() *jetstream.StreamInfo {
		return &jetstream.StreamInfo{Created: time.Now().UTC(), Cluster: &jetstream.ClusterInfo{Leader: "original-leader"},
			Config: jetstream.StreamConfig{Name: "KV_" + controlRootsBucket, Subjects: []string{"$KV." + controlRootsBucket + ".>"},
				Storage: jetstream.FileStorage, Replicas: 3, Retention: jetstream.LimitsPolicy, MaxMsgsPerSubject: 4, DenyDelete: true, AllowRollup: true}}
	}
	if err := validateControlStream(stream(), controlRootsBucket); err != nil {
		t.Fatal(err)
	}
	if err := validateControlStream(nil, controlRootsBucket); err == nil {
		t.Fatal("missing stream identity was accepted")
	}
	for name, change := range map[string]func(*jetstream.StreamInfo){
		"no creation identity":     func(info *jetstream.StreamInfo) { info.Created = time.Time{} },
		"other subjects":           func(info *jetstream.StreamInfo) { info.Config.Subjects = []string{"$KV.OTHER.>"} },
		"volatile storage":         func(info *jetstream.StreamInfo) { info.Config.Storage = jetstream.MemoryStorage },
		"unreplicated":             func(info *jetstream.StreamInfo) { info.Config.Replicas = 1 },
		"expires retained history": func(info *jetstream.StreamInfo) { info.Config.MaxAge = time.Hour },
		"changed history":          func(info *jetstream.StreamInfo) { info.Config.MaxMsgsPerSubject = 1 },
		"allows message deletion":  func(info *jetstream.StreamInfo) { info.Config.DenyDelete = false },
		"mirrored source":          func(info *jetstream.StreamInfo) { info.Config.Mirror = &jetstream.StreamSource{Name: "other"} },
		"no current leader":        func(info *jetstream.StreamInfo) { info.Cluster = nil },
		"unaccounted deletion":     func(info *jetstream.StreamInfo) { info.State.NumDeleted = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			info := stream()
			change(info)
			if err := validateControlStream(info, controlRootsBucket); err == nil {
				t.Fatal("changed retained source contract was accepted")
			}
		})
	}
}
