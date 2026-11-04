package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// renderInputs writes reviewed render inputs for controller-a of a three
// controller cell whose placement member role leaves "terrabase" to the C#
// release path. It returns the base arguments and the candidate manifest.
func renderInputs(t *testing.T, now time.Time, keepSecret func(bootstrapmaterial.File) bool) ([]string, bootstrap.Manifest) {
	t.Helper()
	return renderInputsFor(t, now, keepSecret, false)
}

// renderInputsFor renders from legacy material, generated before the member
// CA existed, when legacy is set.
func renderInputsFor(t *testing.T, now time.Time, keepSecret func(bootstrapmaterial.File) bool, legacy bool) ([]string, bootstrap.Manifest) {
	t.Helper()
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	fixture.writeCandidate(t, fixture.manifest)
	manifest := fixture.manifest
	manifest.Slot, manifest.SeedSlot = "controller-a", "controller-a"
	manifest.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
	manifest.Secrets = nil
	record, err := bootstrapmaterial.Generate(filepath.Join(t.TempDir(), "material"), bootstrapmaterial.Config{
		Environment: manifest.Environment, Region: manifest.OCIRegion, Cell: "gru",
		DeploymentID: manifest.DeploymentID, ClusterID: manifest.ClusterID, SubnetCIDR: "10.0.0.0/24",
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.0.0.11"},
			{Name: "controller-b", PrivateIP: "10.0.0.12"}, {Name: "controller-c", PrivateIP: "10.0.0.13"}},
		ValidityHours: 48,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		record.Files = slices.DeleteFunc(record.Files, func(file bootstrapmaterial.File) bool {
			return strings.HasPrefix(file.Name, "terrabase-member-ca.")
		})
	}
	for _, file := range record.Files {
		if file.Purpose == "owner-only" || !keepSecret(file) {
			continue
		}
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot,
			SecretOCID:    "ocid1.vaultsecret.oc1.sa-saopaulo-1." + strings.ReplaceAll(file.Name, ".", "-"),
			VersionNumber: 1, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name})
	}
	grant := app.TrustedSignerConfig{Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
		Roles: []string{"terrabase"}, Environments: []string{manifest.Environment}}
	placementWire := []byte(`{"environment":"production","member_role":"terrabase-managed",` +
		`"resources":{"cpu":1,"memory_bytes":1073741824,"disk_bytes":53687091200}}`)
	write := func(name string, value any) string {
		path := filepath.Join(fixture.directory, name)
		wire, ok := value.([]byte)
		if !ok {
			if wire, err = protocol.EncodeJSON(value); err != nil {
				t.Fatal(err)
			}
		}
		writeFixture(t, path, wire, 0o600)
		return path
	}
	args := []string{}
	for _, input := range []struct {
		flag string
		path string
	}{
		{"--candidate", write("render-candidate.json", manifest)},
		{"--material-record", write("material.json", record)},
		{"--operator-grant", write("grant.json", grant)},
		{"--oci-region-intent", fixture.intentPath},
		{"--oci-region-config", fixture.regionConfigPath},
		{"--placement-config", write("render-placement.json", placementWire)},
	} {
		args = append(args, input.flag, input.path, input.flag+"-sha256", fixtureFileDigest(input.path))
	}
	return args, manifest
}

func keepEverySecret(bootstrapmaterial.File) bool { return true }

func checkedInTerraBaseProfile(t *testing.T) (string, app.WorkloadProfile) {
	t.Helper()
	path, err := filepath.Abs("../../../deploy/oci-region/terrabase-gru-1-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile app.WorkloadProfile
	if err := protocol.DecodeStrict(wire, &profile, 64<<10); err != nil {
		t.Fatal(err)
	}
	return path, profile
}

func checkedInTSAuthInputs(t *testing.T, environment string) (string, string, app.WorkloadProfile, workload.ServiceSpec) {
	t.Helper()
	profilePath, err := filepath.Abs("../../../deploy/oci-region/ts-auth-gru-1-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	profileWire, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	var profile app.WorkloadProfile
	if err := protocol.DecodeStrict(profileWire, &profile, 64<<10); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(t.TempDir(), "ts-auth-service.json")
	serviceWire, err := os.ReadFile(filepath.Join(filepath.Dir(profilePath), "ts-auth-gru-1-service.json"))
	if err != nil {
		t.Fatal(err)
	}
	var service workload.ServiceSpec
	if err := protocol.DecodeStrict(serviceWire, &service, 64<<10); err != nil {
		t.Fatal(err)
	}
	service.Environment = environment
	serviceWire, err = protocol.EncodeJSON(service)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, servicePath, serviceWire, 0o600)
	return profilePath, servicePath, profile, service
}

func TestRenderControllerConfigWritesTSAuthAndSignsInitialManifest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, manifest := renderInputs(t, now, keepEverySecret)
	terrabasePath, terrabaseProfile := checkedInTerraBaseProfile(t)
	authProfilePath, authServicePath, authProfile, authService := checkedInTSAuthInputs(t, manifest.Environment)
	output := filepath.Join(t.TempDir(), "controller.json")
	renderArgs := append(args,
		"--terrabase-profile", terrabasePath, "--terrabase-profile-sha256", fixtureFileDigest(terrabasePath),
		"--ts-auth-profile", authProfilePath, "--ts-auth-profile-sha256", fixtureFileDigest(authProfilePath),
		"--ts-auth-service", authServicePath, "--ts-auth-service-sha256", fixtureFileDigest(authServicePath),
		"--out", output)
	if err := renderControllerConfigAt(renderArgs, now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var cfg app.Config
	if err := protocol.DecodeStrict(wire, &cfg, bootstrap.MaxControllerConfigBytes); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Controller.Workloads, map[string]app.WorkloadProfile{
		"terrabase": terrabaseProfile, "ts-auth": authProfile,
	}) || cfg.Controller.Autoscale == nil ||
		!reflect.DeepEqual(cfg.Controller.Autoscale.Services, []workload.ServiceSpec{authService}) {
		t.Fatalf("rendered ts-auth config = %+v", cfg.Controller)
	}
	if !strings.Contains(string(wire), `"ts-auth"`) {
		t.Fatal("canonical config omitted ts-auth")
	}
}
