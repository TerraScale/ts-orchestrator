package ocicost

import (
	"maps"
	"testing"
	"time"
)

var tagsTestNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func TestComponentRules(t *testing.T) {
	for _, test := range []struct {
		name     string
		cell     string
		resource Resource
		want     string
	}{
		{name: "valid component kept", cell: "gru", resource: Resource{Type: "Instance", Name: "random",
			Tags: map[string]string{ComponentTag: "apps"}}, want: "apps"},
		{name: "invalid component ignored", cell: "gru", resource: Resource{Type: "Instance", Name: "gru-1-ctl-1",
			Tags: map[string]string{ComponentTag: "gru"}}, want: "controller"},
		{name: "dr source", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-dr-sjc-1-backup",
			Tags: map[string]string{drSourceTag: "sjc"}}, want: "disaster-recovery"},
		{name: "member host", cell: "gru", resource: Resource{Type: "Instance", Name: "gru-1-db-1-retired-20261006",
			Tags: map[string]string{resourceTag: "terrabase-host"}}, want: "terrabase"},
		{name: "member data volume", cell: "gru", resource: Resource{Type: "Volume", Name: "gru-1-member-1-data",
			Tags: map[string]string{resourceTag: "member-data"}}, want: "terrabase"},
		{name: "database role", cell: "gru", resource: Resource{Type: "Instance", Name: "random",
			Tags: map[string]string{roleTag: "db"}}, want: "terrabase"},
		{name: "managed volume", cell: "gru", resource: Resource{Type: "Volume", Name: "random",
			Tags: map[string]string{resourceTag: "managed-volume"}}, want: "apps"},
		{name: "terrascale app", cell: "gru", resource: Resource{Type: "Instance", Name: "random",
			Tags: map[string]string{appTag: "forgejo"}}, want: "apps"},
		{name: "node pool mark", cell: "gru", resource: Resource{Type: "Instance", Name: "random",
			Tags: map[string]string{poolTag: "pool-a"}}, want: "node-pool"},
		{name: "controller boot volume", cell: "gru", resource: Resource{Type: "BootVolume", Name: "ts-gru-2 (Boot Volume)"}, want: "controller"},
		{name: "controller backup", cell: "gru", resource: Resource{Type: "BootVolumeBackup", Name: "gru-1-ctl-1-pre-anna-20261007"}, want: "controller"},
		{name: "database name", cell: "gru", resource: Resource{Type: "Volume", Name: "gru-1-db-1-data"}, want: "terrabase"},
		{name: "member backup name", cell: "gru", resource: Resource{Type: "VolumeBackup", Name: "ts-member-data-backup-abc"}, want: "terrabase"},
		{name: "pool name", cell: "gru", resource: Resource{Type: "Instance", Name: "gru-1-pool-3"}, want: "node-pool"},
		{name: "bucket backup", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-backup"}, want: "terrabase"},
		{name: "bucket head", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-head"}, want: "releases"},
		{name: "bucket material", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-material"}, want: "controller"},
		{name: "bucket ledger", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-ledger"}, want: "controller"},
		{name: "bucket outside cell", cell: "gru", resource: Resource{Type: "Bucket", Name: "ts-forgejo-backup"}, want: "storage"},
		{name: "bucket other", cell: "gru", resource: Resource{Type: "Bucket", Name: "gru-1-scratch"}, want: "storage"},
		{name: "image", cell: "gru", resource: Resource{Type: "Image", Name: "gru-1-arm64"}, want: "images"},
		{name: "load balancer", cell: "gru", resource: Resource{Type: "LoadBalancer", Name: "gru-1-api"}, want: "network"},
		{name: "unmarked instance", cell: "gru", resource: Resource{Type: "Instance", Name: "random"}, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Component(test.cell, test.resource); got != test.want {
				t.Fatalf("Component = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPlanTags(t *testing.T) {
	correct := map[string]string{RegionTag: "GRU", ComponentTag: "controller"}
	resources := []Resource{
		{ID: "young", Type: "Instance", Name: "gru-1-ctl-2", Created: tagsTestNow.Add(-time.Minute)},
		{ID: "done", Type: "Instance", Name: "gru-1-ctl-1", Created: tagsTestNow.Add(-2 * time.Hour), Tags: correct},
		{ID: "lower", Type: "Instance", Name: "gru-1-ctl-3", Created: tagsTestNow.Add(-2 * time.Hour),
			Tags: map[string]string{RegionTag: "gru", ComponentTag: "controller"}},
		{ID: "unknown-type", Type: "Network", Name: "gru-1-ctl-4"},
		{ID: "untagged", Type: "Instance", Name: "random"},
	}
	stamps, untagged := PlanTags("gru", resources, tagsTestNow)
	if len(stamps) != 1 || stamps[0].Resource.ID != "lower" {
		t.Fatalf("stamps = %+v, want only the lowercase region", stamps)
	}
	if want := map[string]string{RegionTag: "GRU", ComponentTag: "controller"}; !maps.Equal(stamps[0].Tags, want) {
		t.Fatalf("stamp tags = %v, want %v", stamps[0].Tags, want)
	}
	if len(untagged) != 1 || untagged[0].ID != "untagged" {
		t.Fatalf("untagged = %+v, want only the unmarked instance", untagged)
	}
}
