package app

import (
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Committed specs must pass the same decode and validation as `service apply`.
func TestM1ServiceSpecsValidate(t *testing.T) {
	paths, err := filepath.Glob("../../deploy/m1/services/*.json")
	if err != nil || len(paths) != 5 {
		t.Fatalf("want 5 M1 service specs, got %d (%v)", len(paths), err)
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
		if got := swarm.Annotations.Labels[swarmruntime.LabelSecrets]; got != strings.Join(slices.Sorted(maps.Keys(spec.Secrets)), ",") {
			t.Fatalf("%s: secrets label %q", path, got)
		}
	}
}

func TestServiceSpecRejects(t *testing.T) {
	ref := vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.aa.bb", Name: "gru-1-whoami-a"}
	valid := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1}
	if _, err := valid.SwarmSpec(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*swarmruntime.ServiceSpec){
		"tag image":       func(s *swarmruntime.ServiceSpec) { s.Image = "docker.io/library/alpine:3" },
		"two replicas":    func(s *swarmruntime.ServiceSpec) { s.Replicas = 2 },
		"privileged port": func(s *swarmruntime.ServiceSpec) { s.Port = 80 },
		"bad secret":      func(s *swarmruntime.ServiceSpec) { s.Secrets = map[string]vaultsecret.Ref{"lower": ref} },
		"shadowed secret": func(s *swarmruntime.ServiceSpec) {
			s.Secrets, s.Env = map[string]vaultsecret.Ref{"A_FILE": ref}, map[string]string{"A_FILE": "x"}
		},
		"plain key": func(s *swarmruntime.ServiceSpec) { s.Secrets = map[string]vaultsecret.Ref{"A": ref} },
		"no vault": func(s *swarmruntime.ServiceSpec) {
			s.Secrets = map[string]vaultsecret.Ref{"A_FILE": {Name: "gru-1-whoami-a"}}
		},
		"other service": func(s *swarmruntime.ServiceSpec) {
			s.Secrets = map[string]vaultsecret.Ref{"A_FILE": {Vault: ref.Vault, Name: "gru-1-terrabase-master-key"}}
		},
		"not shared": func(s *swarmruntime.ServiceSpec) {
			s.Secrets = map[string]vaultsecret.Ref{"A_FILE": {Vault: ref.Vault, Name: "gru-1-terrabase-peer-secret"}}
		},
		"two cells": func(s *swarmruntime.ServiceSpec) {
			s.Secrets = map[string]vaultsecret.Ref{"A_FILE": ref, "B_FILE": {Vault: ref.Vault, Name: "sjc-1-whoami-b"}}
		},
		"two vaults": func(s *swarmruntime.ServiceSpec) {
			s.Secrets = map[string]vaultsecret.Ref{"A_FILE": ref, "B_FILE": {Vault: ref.Vault + "x", Name: "gru-1-whoami-b"}}
		},
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

// Without a mesh (no client token) apply and rm change this host's services.
func TestServiceChangesWithoutMeshStayLocal(t *testing.T) {
	spec := filepath.Join("..", "..", "deploy", "m1", "services", "terrabase.json")
	for _, args := range [][]string{{"apply", "-f", spec}, {"rm", "terrabase"}} {
		err := runServiceCLI(t.Context(), args, io.Discard, t.TempDir())
		if err == nil || strings.Contains(err.Error(), "mesh is not running") {
			t.Fatalf("%v: want the single-host dial error, got %v", args, err)
		}
	}
}
