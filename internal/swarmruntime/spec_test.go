package swarmruntime

import (
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestContainerMountsAndReadyPath(t *testing.T) {
	bind := func(source, target string) api.Mount {
		return api.Mount{Type: api.MountTypeBind, Source: source, Target: target}
	}
	for _, tc := range []struct {
		name   string
		mounts []api.Mount
		labels map[string]string
		ok     bool
	}{
		{"none", nil, nil, true},
		{"data dir", []api.Mount{bind("/var/lib/ts-data/terrabase", "/data")}, map[string]string{LabelReadyPath: "/healthz"}, true},
		{"read only", []api.Mount{{Type: api.MountTypeBind, Source: "/var/lib/ts-data/a", Target: "/a", ReadOnly: true}, bind("/var/lib/ts-data/b", "/b")}, nil, true},
		{"root itself", []api.Mount{bind("/var/lib/ts-data", "/data")}, nil, false},
		{"outside root", []api.Mount{bind("/etc", "/data")}, nil, false},
		{"escape", []api.Mount{bind("/var/lib/ts-data/../../etc", "/data")}, nil, false},
		{"prefix lookalike", []api.Mount{bind("/var/lib/ts-database", "/data")}, nil, false},
		{"relative target", []api.Mount{bind("/var/lib/ts-data/a", "data")}, nil, false},
		{"slash target", []api.Mount{bind("/var/lib/ts-data/a", "/")}, nil, false},
		{"secret target", []api.Mount{bind("/var/lib/ts-data/a", "/run/ts-orch/secrets")}, nil, false},
		{"proc target", []api.Mount{bind("/var/lib/ts-data/a", "/proc/self")}, nil, false},
		{"nested sources", []api.Mount{bind("/var/lib/ts-data/a", "/a"), bind("/var/lib/ts-data/a/b", "/b")}, nil, false},
		{"nested targets", []api.Mount{bind("/var/lib/ts-data/a", "/a"), bind("/var/lib/ts-data/b", "/a/b")}, nil, false},
		{"volume", []api.Mount{{Type: api.MountTypeVolume, Source: "/var/lib/ts-data/a", Target: "/a"}}, nil, false},
		{"bind options", []api.Mount{{Type: api.MountTypeBind, Source: "/var/lib/ts-data/a", Target: "/a", BindOptions: &api.Mount_BindOptions{Propagation: api.MountPropagationShared}}}, nil, false},
		{"other label", nil, map[string]string{"x": "y"}, false},
		{"query path", nil, map[string]string{LabelReadyPath: "/healthz?x=1"}, false},
		{"relative path", nil, map[string]string{LabelReadyPath: "healthz"}, false},
		{"unclean path", nil, map[string]string{LabelReadyPath: "/a/../healthz"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Mounts: tc.mounts, Labels: tc.labels}
			if _, err := ContainerRuntime(spec); (err == nil) != tc.ok {
				t.Fatalf("ContainerRuntime() error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if got := ReadyPath(&api.ContainerSpec{}); got != DefaultReadyPath {
		t.Fatalf("default ready path = %q", got)
	}
	if got := ReadyPath(&api.ContainerSpec{Labels: map[string]string{LabelReadyPath: "/healthz"}}); got != "/healthz" {
		t.Fatalf("ready path = %q", got)
	}
}
