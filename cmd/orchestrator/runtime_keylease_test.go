package main

import (
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

func TestConfiguredKeyProvisionerUsesAdmittedRunFileLookup(t *testing.T) {
	t.Setenv(byokRoleEnvironment, "ambient-invalid-role")
	t.Setenv(byokTokenEnvironment, "")
	t.Setenv(byokKeyIDEnvironment, "ambient-invalid-key")
	t.Setenv(byokKeyRegionEnvironment, "")
	t.Setenv(byokKeyEndpointEnvironment, "https://ambient-invalid.example")
	values := map[string]string{
		byokRoleEnvironment:        "arn:aws:iam::123456789012:role/run-file",
		byokTokenEnvironment:       "/var/lib/terrascale/run-file.token",
		byokKeyIDEnvironment:       "arn:aws:kms:sa-east-1:123456789012:key/run-file",
		byokKeyRegionEnvironment:   "sa-east-1",
		byokKeyEndpointEnvironment: "https://kms.run-file.example",
	}
	lookup := func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	target := keylease.ProvisionTarget{Provider: "aws-kms", KeyID: values[byokKeyIDEnvironment], KeyRegion: values[byokKeyRegionEnvironment], KeyEndpoint: values[byokKeyEndpointEnvironment], NotAfter: time.Now().Add(time.Hour)}
	err := configuredKeyProvisioner(lookup)(t.Context(), "/unused/catalog", []keylease.ProvisionTarget{target})
	if errors.Is(err, keylease.ErrUnavailable) {
		t.Fatalf("run-file BYOK tuple was not admitted (ambient environment may have been used): %v", err)
	}
}

func TestConfiguredKeyProvisionerRejectsTargetTupleMismatch(t *testing.T) {
	lookup := func(name string) (string, bool) {
		values := map[string]string{
			byokRoleEnvironment:        "arn:aws:iam::123456789012:role/keylease",
			byokTokenEnvironment:       "/var/lib/terrascale/oidc.token",
			byokKeyIDEnvironment:       "arn:aws:kms:sa-east-1:123456789012:key/id",
			byokKeyRegionEnvironment:   "sa-east-1",
			byokKeyEndpointEnvironment: "https://kms.example.test",
		}
		value, ok := values[name]
		return value, ok
	}
	provision := configuredKeyProvisioner(lookup)
	base := keylease.ProvisionTarget{Provider: "aws-kms", KeyID: "arn:aws:kms:sa-east-1:123456789012:key/id", KeyRegion: "sa-east-1", KeyEndpoint: "https://kms.example.test", NotAfter: time.Now().Add(time.Hour)}
	changed := base
	changed.KeyEndpoint = "https://attacker.example"
	if err := provision(t.Context(), "/unused/catalog", []keylease.ProvisionTarget{base, changed}); !errors.Is(err, keylease.ErrUnavailable) {
		t.Fatalf("tuple mismatch error = %v, want ErrUnavailable", err)
	}
}

func TestConfiguredKeyProvisionerRejectsUnsupportedProvider(t *testing.T) {
	provision := configuredKeyProvisioner(func(string) (string, bool) { return "", false })
	if err := provision(t.Context(), "/unused/catalog", []keylease.ProvisionTarget{{Provider: "azure-key-vault"}}); !errors.Is(err, keylease.ErrUnavailable) {
		t.Fatalf("unsupported provider error = %v, want ErrUnavailable", err)
	}
}

func TestConfiguredKeyProvisionerRejectsMixedOCIAndCustomerProviders(t *testing.T) {
	provision := configuredKeyProvisioner(func(string) (string, bool) { return "", false })
	if err := provision(t.Context(), "/unused/catalog", []keylease.ProvisionTarget{{Provider: ""}, {Provider: "aws-kms"}}); !errors.Is(err, keylease.ErrUnavailable) {
		t.Fatalf("mixed provider error = %v, want ErrUnavailable", err)
	}
}

func TestStartConfiguredKeyLeaseRejectsPartialS3Configuration(t *testing.T) {
	lookup := func(name string) (string, bool) {
		values := map[string]string{
			keyLeaseSocketEnvironment:  "/run/terrascale/keylease.sock",
			keyLeaseCatalogEnvironment: "/var/lib/terrascale/catalog.json",
			keyLeaseEnvironment:        "production",
			keyLeaseUIDEnvironment:     "1001",
			keyLeaseGIDEnvironment:     "1001",
			byokS3TokenEnvironment:     "/var/lib/terrascale/s3.token",
		}
		value, ok := values[name]
		return value, ok
	}
	_, err := startConfiguredKeyLease(t.Context(), &control.OrchestratorOptions{Cell: "gru"}, lookup)
	if err == nil {
		t.Fatal("partial S3 workload identity configuration accepted")
	}
}

func TestStartConfiguredKeyLeaseRejectsKMSWithoutS3WorkloadTuple(t *testing.T) {
	lookup := func(name string) (string, bool) {
		values := map[string]string{
			keyLeaseSocketEnvironment:  "/run/terrascale/keylease.sock",
			keyLeaseCatalogEnvironment: "/var/lib/terrascale/catalog.json",
			keyLeaseEnvironment:        "production",
			keyLeaseUIDEnvironment:     "1001",
			keyLeaseGIDEnvironment:     "1001",
			byokProviderEnvironment:    "aws-kms",
			byokRoleEnvironment:        "arn:aws:iam::123456789012:role/keylease",
			byokTokenEnvironment:       "/var/lib/terrascale/oidc.token",
			byokKeyIDEnvironment:       "arn:aws:kms:sa-east-1:123456789012:key/id",
			byokKeyRegionEnvironment:   "sa-east-1",
			byokKeyEndpointEnvironment: "https://kms.example.test",
		}
		value, ok := values[name]
		return value, ok
	}
	if _, err := startConfiguredKeyLease(t.Context(), &control.OrchestratorOptions{Cell: "gru"}, lookup); err == nil {
		t.Fatal("KMS BYOK started without S3 workload identity tuple")
	}
}

func TestValidKeyAuthorityEndpoint(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "https://kms.example.test", want: true},
		{value: "http://kms.example.test", want: false},
		{value: "https://user:kms@example.test", want: false},
		{value: "https://kms.example.test/?tenant=other", want: false},
	} {
		if got := validKeyAuthorityEndpoint(test.value); got != test.want {
			t.Errorf("validKeyAuthorityEndpoint(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}
