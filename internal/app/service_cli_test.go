package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// Committed specs must pass the same decode and validation as `service apply`.
func TestM1ServiceSpecsValidate(t *testing.T) {
	paths, err := filepath.Glob("../../deploy/m1/services/*.json")
	if err != nil || len(paths) != 4 {
		t.Fatalf("want 4 M1 service specs, got %d (%v)", len(paths), err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var spec swarmruntime.ServiceSpec
		if err := protocol.DecodeStrict(data, &spec, 64<<10); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if spec.Name != strings.TrimSuffix(filepath.Base(path), ".json") {
			t.Fatalf("%s: name %q differs from file name", path, spec.Name)
		}
		swarm, err := spec.SwarmSpec()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := swarm.Annotations.Labels[swarmruntime.LabelSecrets]; got != strings.Join(spec.Secrets, ",") {
			t.Fatalf("%s: secrets label %q", path, got)
		}
	}
}

func TestServiceSpecRejects(t *testing.T) {
	valid := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1}
	if _, err := valid.SwarmSpec(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*swarmruntime.ServiceSpec){
		"tag image":       func(s *swarmruntime.ServiceSpec) { s.Image = "docker.io/library/alpine:3" },
		"two replicas":    func(s *swarmruntime.ServiceSpec) { s.Replicas = 2 },
		"privileged port": func(s *swarmruntime.ServiceSpec) { s.Port = 80 },
		"bad secret":      func(s *swarmruntime.ServiceSpec) { s.Secrets = []string{"lower"} },
		"shadowed secret": func(s *swarmruntime.ServiceSpec) { s.Secrets, s.Env = []string{"A"}, map[string]string{"A": "x"} },
		"repeat hostname": func(s *swarmruntime.ServiceSpec) { s.Hostnames = []string{"a.example.com", "a.example.com"} },
		"bad hostname":    func(s *swarmruntime.ServiceSpec) { s.Hostnames = []string{"https://a.example.com"} },
		"relative ready":  func(s *swarmruntime.ServiceSpec) { s.ReadyPath = "readyz" },
	} {
		spec := valid
		mutate(&spec)
		if _, err := spec.SwarmSpec(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
