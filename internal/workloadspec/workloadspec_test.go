package workloadspec

import (
	"testing"
)

// The three sample workloads of TS-572: a stateless HTTP service, a stateful
// service with a volume and a quorum, and a third-party container.
var (
	statelessHTTP = MachineSpec{
		Files:     []File{{Path: "/etc/dashboard/config.toml", Content: "listen = \":8080\"\n"}},
		Lifecycle: Lifecycle{DrainSeconds: 30},
	}
	statefulStore = MachineSpec{
		Artifact:  ArtifactTarball,
		Command:   []string{"bin/store", "--data", "/var/lib/store"},
		Lifecycle: Lifecycle{PreStop: []string{"bin/store", "drain"}, DrainSeconds: 45},
	}
	container = MachineSpec{
		Artifact:  ArtifactImage,
		Image:     "ghcr.io/acme/hello-http",
		Command:   []string{"hello-http", "--listen", ":8080"},
		Lifecycle: Lifecycle{PostStart: []string{"/bin/sh", "-c", "test -s /etc/hello/index.html"}},
		Files:     []File{{Path: "/etc/hello/index.html", Content: "hello\n"}},
	}
)

func TestSampleWorkloadsAreValid(t *testing.T) {
	for name, spec := range map[string]MachineSpec{"stateless": statelessHTTP, "stateful": statefulStore, "container": container} {
		if err := spec.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (AppSpec{Placement: Placement{MaxPerFailureDomain: 1}}).Validate("dashboard"); err != nil {
		t.Fatal(err)
	}
	for _, stateful := range []AppSpec{
		{Stateful: &Stateful{Quorum: 2}, DependsOn: []string{"ts-auth"}},
		{Stateful: &Stateful{}, Update: Update{Strategy: Rolling, MaxUnavailable: 1}},
	} {
		if err := stateful.Validate("store"); err != nil {
			t.Fatal(err)
		}
	}
}
