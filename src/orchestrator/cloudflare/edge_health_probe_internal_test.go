package cloudflare

import "testing"

func TestResolveDownstreamAllocationStages(t *testing.T) {
	for _, test := range []struct {
		name      string
		candidate int
		previous  int
		versions  []WorkerDeploymentVersion
		wantC     string
		wantP     string
		wantOK    bool
	}{
		{name: "10", candidate: 10, previous: 90, versions: []WorkerDeploymentVersion{{VersionID: "bound-candidate", Percentage: 10}, {VersionID: "bound-previous", Percentage: 90}}, wantC: "bound-candidate", wantP: "bound-previous", wantOK: true},
		{name: "50", candidate: 50, previous: 50, versions: []WorkerDeploymentVersion{{VersionID: "bound-previous", Percentage: 50}, {VersionID: "bound-candidate", Percentage: 50}}, wantC: "bound-candidate", wantP: "bound-previous", wantOK: true},
		{name: "100", candidate: 100, versions: []WorkerDeploymentVersion{{VersionID: "bound-candidate", Percentage: 100}}, wantC: "bound-candidate", wantOK: true},
		{name: "stale allocation", candidate: 10, previous: 90, versions: []WorkerDeploymentVersion{{VersionID: "bound-candidate", Percentage: 20}, {VersionID: "bound-previous", Percentage: 80}}, wantOK: false},
		{name: "missing predecessor", candidate: 50, previous: 50, versions: []WorkerDeploymentVersion{{VersionID: "bound-candidate", Percentage: 50}}, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			versions := make([]WorkerVersion, 0, len(test.versions))
			for _, version := range test.versions {
				digest := "sha256:previous"
				if version.VersionID == "bound-candidate" {
					digest = "sha256:candidate"
				}
				versions = append(versions, WorkerVersion{ID: version.VersionID, Digest: digest})
			}
			candidate, previous, ok := resolveDownstreamAllocation(WorkerDeployment{Versions: test.versions}, versions, "sha256:candidate", test.candidate, test.previous)
			if ok != test.wantOK || candidate != test.wantC || previous != test.wantP {
				t.Fatalf("resolve = %q, %q, %v", candidate, previous, ok)
			}
		})
	}
}
