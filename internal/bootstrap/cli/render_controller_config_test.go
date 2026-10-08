package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machinesapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
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
	}) || cfg.Controller.Autoscale == nil || !cfg.Controller.Autoscale.Enabled ||
		!reflect.DeepEqual(cfg.Controller.Autoscale.Services, []workload.ServiceSpec{authService}) {
		t.Fatalf("rendered ts-auth config = %+v", cfg.Controller)
	}
	if !strings.Contains(string(wire), `"ts-auth"`) {
		t.Fatal("canonical config omitted ts-auth")
	}
}

func TestRenderControllerConfigRejectsIncompleteOrInvalidTSAuthInputs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, profilePath, servicePath string, profile app.WorkloadProfile, service workload.ServiceSpec) (string, string, string)
		want   string
	}{
		{name: "incomplete group", mutate: func(_ *testing.T, profilePath, servicePath string, _ app.WorkloadProfile, _ workload.ServiceSpec) (string, string, string) {
			return profilePath, "", "ts-auth requires"
		}, want: "ts-auth requires"},
		{name: "wrong profile digest", mutate: func(_ *testing.T, profilePath, servicePath string, _ app.WorkloadProfile, _ workload.ServiceSpec) (string, string, string) {
			return profilePath, servicePath, strings.Repeat("0", 64)
		}, want: "reviewed ts-auth profile"},
		{name: "secret profile", mutate: func(t *testing.T, _ string, servicePath string, profile app.WorkloadProfile, _ workload.ServiceSpec) (string, string, string) {
			profile.Env["TS_AUTH_MASTER_KEY"] = "secret"
			path := filepath.Join(t.TempDir(), "profile.json")
			wire, err := protocol.EncodeJSON(profile)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, wire, 0o600)
			return path, servicePath, fixtureFileDigest(path)
		}, want: "ts-auth"},
		{name: "wrong service role", mutate: func(t *testing.T, profilePath, _ string, _ app.WorkloadProfile, service workload.ServiceSpec) (string, string, string) {
			service.Role = "0000000000V4MRM46HP1SNGDYW"
			path := filepath.Join(t.TempDir(), "service.json")
			wire, err := protocol.EncodeJSON(service)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, wire, 0o600)
			return profilePath, path, fixtureFileDigest(path)
		}, want: "role ts-auth"},
		{name: "invalid service", mutate: func(t *testing.T, profilePath, _ string, _ app.WorkloadProfile, service workload.ServiceSpec) (string, string, string) {
			service.Kind = workload.KindStateful
			path := filepath.Join(t.TempDir(), "service.json")
			wire, err := protocol.EncodeJSON(service)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, wire, 0o600)
			return profilePath, path, fixtureFileDigest(path)
		}, want: "signed controller autoscale"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, manifest := renderInputs(t, now, keepEverySecret)
			profilePath, servicePath, profile, service := checkedInTSAuthInputs(t, manifest.Environment)
			profilePath, servicePath, _ = test.mutate(t, profilePath, servicePath, profile, service)
			serviceDigest := fixtureFileDigest(servicePath)
			output := filepath.Join(t.TempDir(), "controller.json")
			profileDigest := fixtureFileDigest(profilePath)
			if test.name == "wrong profile digest" {
				profileDigest = strings.Repeat("0", 64)
			}
			extra := []string{"--ts-auth-profile", profilePath, "--ts-auth-profile-sha256", profileDigest,
				"--ts-auth-service", servicePath, "--ts-auth-service-sha256", serviceDigest}
			if test.name == "incomplete group" {
				extra = []string{"--ts-auth-profile", profilePath}
			}
			err := renderControllerConfigAt(append(append(args, extra...), "--out", output), now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("render error = %v, want %q", err, test.want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatal("rejected ts-auth render wrote output")
			}
		})
	}
}

func TestRenderControllerConfigWritesTerraBaseCAAndProfile(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, _ := renderInputs(t, now, keepEverySecret)
	profilePath, profile := checkedInTerraBaseProfile(t)
	output := filepath.Join(t.TempDir(), "controller.json")
	if err := renderControllerConfigAt(append(args, "--terrabase-profile", profilePath,
		"--terrabase-profile-sha256", fixtureFileDigest(profilePath), "--out", output), now); err != nil {
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
	if cfg.Controller.TerraBaseCACertFile != filepath.Join(bootstrapstart.MaterialDirectory, "terrabase-member-ca.pem") ||
		cfg.Controller.TerraBaseCAKeyFile != filepath.Join(bootstrapstart.MaterialDirectory, "terrabase-member-ca.key") {
		t.Fatalf("member CA paths = %q %q", cfg.Controller.TerraBaseCACertFile, cfg.Controller.TerraBaseCAKeyFile)
	}
	if !reflect.DeepEqual(cfg.Controller.Workloads, map[string]app.WorkloadProfile{"terrabase": profile}) {
		t.Fatalf("rendered workloads = %+v", cfg.Controller.Workloads)
	}
}

func TestRenderControllerConfigWritesCanonicalTSAuthProfileAndService(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, _ := renderInputs(t, now, keepEverySecret)
	profile, err := filepath.Abs("../../../deploy/oci-region/ts-auth-gru-1-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	service, err := filepath.Abs("../../../deploy/oci-region/ts-auth-gru-1-service.json")
	if err != nil {
		t.Fatal(err)
	}
	serviceWire, err := os.ReadFile(service)
	if err != nil {
		t.Fatal(err)
	}
	serviceCopy := filepath.Join(t.TempDir(), "ts-auth-service.json")
	serviceWire = []byte(strings.Replace(string(serviceWire), `"canary"`, `"production"`, 1))
	if err := os.WriteFile(serviceCopy, serviceWire, 0o600); err != nil {
		t.Fatal(err)
	}
	service = serviceCopy
	output := filepath.Join(t.TempDir(), "controller.json")
	args = append(args,
		"--ts-auth-profile", profile, "--ts-auth-profile-sha256", fixtureFileDigest(profile),
		"--ts-auth-service", service, "--ts-auth-service-sha256", fixtureFileDigest(service), "--out", output)
	if err := renderControllerConfigAt(args, now); err != nil {
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
	canonical, err := protocol.EncodeJSON(cfg)
	if err != nil || !reflect.DeepEqual(canonical, wire) {
		t.Fatal("renderer output is not canonical app.Config JSON")
	}
	if cfg.Controller.Autoscale == nil || !cfg.Controller.Autoscale.Enabled || len(cfg.Controller.Autoscale.Services) != 1 ||
		cfg.Controller.Autoscale.Services[0].Role != "ts-auth" {
		t.Fatalf("ts-auth autoscale config = %+v", cfg.Controller.Autoscale)
	}
}

func TestRenderControllerConfigRejectsUnreviewedProfileAndMissingCA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profilePath, _ := checkedInTerraBaseProfile(t)
	unknown := filepath.Join(t.TempDir(), "profile.json")
	writeFixture(t, unknown, []byte(`{"resources":{"cpu":1,"memory_bytes":1,"disk_bytes":1},"replicas":2}`), 0o600)
	withoutCA := func(file bootstrapmaterial.File) bool { return file.Name != "terrabase-member-ca.key" }
	for _, test := range []struct {
		name  string
		keep  func(bootstrapmaterial.File) bool
		extra []string
		want  string
	}{
		{name: "profile digest mismatch", keep: keepEverySecret, want: "TerraBase profile",
			extra: []string{"--terrabase-profile", profilePath, "--terrabase-profile-sha256", strings.Repeat("0", 64)}},
		{name: "profile without digest", keep: keepEverySecret, want: "TerraBase profile",
			extra: []string{"--terrabase-profile", profilePath}},
		{name: "unknown profile member", keep: keepEverySecret, want: "decode reviewed TerraBase profile",
			extra: []string{"--terrabase-profile", unknown, "--terrabase-profile-sha256", fixtureFileDigest(unknown)}},
		{name: "missing member CA secret", keep: withoutCA, want: "TerraBase member CA secret terrabase-member-ca.key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, _ := renderInputs(t, now, test.keep)
			output := filepath.Join(t.TempDir(), "controller.json")
			err := renderControllerConfigAt(append(append(args, test.extra...), "--out", output), now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("render error = %v, want %q", err, test.want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatal("rejected render wrote output")
			}
		})
	}
}

// Signing refuses what controller start would refuse: a member CA outside
// the signed material and a placement role that overlaps a workload profile.
func TestSignedControllerConfigRejectsMisplacedCAAndOverlappingPlacementRole(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, manifest := renderInputs(t, now, keepEverySecret)
	profilePath, _ := checkedInTerraBaseProfile(t)
	output := filepath.Join(t.TempDir(), "controller.json")
	if err := renderControllerConfigAt(append(args, "--terrabase-profile", profilePath,
		"--terrabase-profile-sha256", fixtureFileDigest(profilePath), "--out", output), now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for index, flag := range []string{"--oci-region-intent", "--oci-region-config", "--placement-config"} {
		body, err := os.ReadFile(args[slices.Index(args, flag)+1])
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: digest(body), Bytes: body})
	}
	signed := func(change func(*app.Config), placementRole string) bootstrap.Manifest {
		var cfg app.Config
		if err := protocol.DecodeStrict(wire, &cfg, bootstrap.MaxControllerConfigBytes); err != nil {
			t.Fatal(err)
		}
		change(&cfg)
		modified := manifest
		modified.ControllerFiles = slices.Clone(manifest.ControllerFiles)
		if modified.ControllerConfig, err = protocol.EncodeJSON(cfg); err != nil {
			t.Fatal(err)
		}
		modified.ControllerConfigSHA256 = digest(modified.ControllerConfig)
		body := []byte(strings.Replace(string(modified.ControllerFiles[2].Bytes), "terrabase-managed", placementRole, 1))
		modified.ControllerFiles[2] = bootstrap.ControllerConfigFile{Name: "placement.json", SHA256: digest(body), Bytes: body}
		return modified
	}
	if _, err := app.ValidateSignedControllerConfig(signed(func(*app.Config) {}, "terrabase-managed"), ""); err != nil {
		t.Fatalf("rendered C# controller config rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*app.Config)
		role   string
		want   string
	}{
		{name: "CA key outside material", role: "terrabase-managed", want: "member CA",
			change: func(cfg *app.Config) { cfg.Controller.TerraBaseCAKeyFile = "/etc/terrascale-orchestrator/ca.key" }},
		{name: "CA unset though signed", role: "terrabase-managed", want: "member CA",
			change: func(cfg *app.Config) { cfg.Controller.TerraBaseCACertFile, cfg.Controller.TerraBaseCAKeyFile = "", "" }},
		{name: "placement role overlaps profile", role: "terrabase", want: "overlaps",
			change: func(*app.Config) {}},
		{name: "invalid profile", role: "terrabase-managed", want: "workloads",
			change: func(cfg *app.Config) { cfg.Controller.Workloads["terrabase"] = app.WorkloadProfile{} }},
		{name: "machines API before its signed listener", role: "terrabase-managed", want: "machines_api",
			change: func(cfg *app.Config) { cfg.Controller.MachinesAPI = &machinesapi.Config{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := app.ValidateSignedControllerConfig(signed(test.change, test.role), "")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("signed config error = %v, want %q", err, test.want)
			}
		})
	}
}

// A controller restarts on a config another binary signed: it checks the
// signed digest of the bytes, not a re-encoding, and a newer binary's members
// do not stop it. Signing still needs this binary's canonical config.
func TestInstalledControllerConfigFromAnotherBinaryStillStarts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, manifest := renderInputs(t, now, keepEverySecret)
	output := filepath.Join(t.TempDir(), "controller.json")
	if err := renderControllerConfigAt(append(args, "--out", output), now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(wire), fmt.Sprintf(`{"version":%d,`, app.ConfigVersion)) {
		t.Fatalf("rendered config does not name its version: %.40s", wire)
	}
	for index, flag := range []string{"--oci-region-intent", "--oci-region-config", "--placement-config"} {
		body, err := os.ReadFile(args[slices.Index(args, flag)+1])
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: digest(body), Bytes: body})
	}
	signed := func(config string) bootstrap.Manifest {
		modified := manifest
		modified.ControllerConfig, modified.ControllerConfigSHA256 = []byte(config), digest([]byte(config))
		return modified
	}
	rendered := string(wire)
	newer := strings.Replace(strings.Replace(rendered, fmt.Sprintf(`{"version":%d,`, app.ConfigVersion),
		fmt.Sprintf(`{"version":%d, "added_by_newer_binary":{"setting":true},`, app.ConfigVersion+1), 1),
		`"controller":{`, `"controller":{"added_setting":"on",`, 1)
	if _, err := app.ValidateInstalledControllerConfig(signed(newer), ""); err != nil {
		t.Fatalf("config signed by a newer binary: %v", err)
	}
	if _, err := app.ValidateSignedControllerConfig(signed(newer), ""); err == nil {
		t.Fatal("signing accepted members this binary does not know")
	}
	older := strings.Replace(rendered, fmt.Sprintf(`{"version":%d,`, app.ConfigVersion), "{ ", 1)
	if _, err := app.ValidateInstalledControllerConfig(signed(older), ""); err != nil {
		t.Fatalf("non-canonical config signed by an older binary: %v", err)
	}
	for name, manifest := range map[string]bootstrap.Manifest{
		"bytes differ from the signed digest": func() bootstrap.Manifest {
			tampered := signed(newer)
			tampered.ControllerConfig = []byte(strings.Replace(newer, `"setting":true`, `"setting":false`, 1))
			return tampered
		}(),
		"typo at this version": signed(strings.Replace(rendered, `"controller":{`, `"controller":{"candidate_idd":"x",`, 1)),
		"newer config breaks the role": signed(strings.Replace(newer, `"candidate_id":"`+manifest.Slot+`"`,
			`"candidate_id":"other-slot"`, 1)),
	} {
		if _, err := app.ValidateInstalledControllerConfig(manifest, ""); err == nil {
			t.Errorf("%s: installed config accepted", name)
		}
	}
}

// A material generation may pin the slot's new controller config (TS-668).
// The loaded config passes the installed checks in place of the manifest's:
// it must be the expected one, and its interregion files must be in the
// credential directory.
func TestLoadedControllerConfigFromAGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, manifest := renderInputs(t, now, keepEverySecret)
	output := filepath.Join(t.TempDir(), "controller.json")
	if err := renderControllerConfigAt(append(args, "--out", output), now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for index, flag := range []string{"--oci-region-intent", "--oci-region-config", "--placement-config"} {
		body, err := os.ReadFile(args[slices.Index(args, flag)+1])
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: digest(body), Bytes: body})
	}
	manifest.ControllerConfig, manifest.ControllerConfigSHA256 = wire, digest(wire)
	material := generationtest.New(t, now).SchemaTwo(t).WithoutIssuers(t).InterRegion(t, now, manifest.ControllerSlots)
	var generated struct {
		NATS natscell.Config `json:"nats"`
	}
	if err := protocol.DecodeTolerant(material.Files["controller-controller-a.json"], &generated,
		bootstrap.MaxControllerConfigBytes); err != nil {
		t.Fatal(err)
	}
	loaded := func(change func(*natscell.InterRegion)) []byte {
		var cfg app.Config
		if err := protocol.DecodeStrict(wire, &cfg, bootstrap.MaxControllerConfigBytes); err != nil {
			t.Fatal(err)
		}
		interregion := *generated.NATS.Embedded.InterRegion
		change(&interregion)
		cfg.NATS.Embedded.InterRegion = &interregion
		config, err := protocol.EncodeJSON(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	config := loaded(func(*natscell.InterRegion) {})
	if _, err := app.ValidateLoadedControllerConfig(manifest, config, digest(config), ""); err != nil {
		t.Fatalf("the generation's config: %v", err)
	}
	if _, err := app.ValidateLoadedControllerConfig(manifest, config, manifest.ControllerConfigSHA256, ""); err == nil {
		t.Error("accepted a config other than the expected one")
	}
	outside := loaded(func(ir *natscell.InterRegion) { ir.AccountJWTFile = "/etc/terrascale-orchestrator/interregion.jwt" })
	if _, err := app.ValidateLoadedControllerConfig(manifest, outside, digest(outside), ""); err == nil {
		t.Error("accepted an interregion file outside the credential directory")
	}
	other := []byte(strings.Replace(string(config), `"candidate_id":"controller-a"`, `"candidate_id":"controller-b"`, 1))
	if bytes.Equal(other, config) {
		t.Fatal("the config names no candidate")
	}
	if _, err := app.ValidateLoadedControllerConfig(manifest, other, digest(other), ""); err == nil {
		t.Error("accepted another slot's config")
	}
}

// Material generated before the member CA existed still renders, without
// the CA; a TerraBase profile needs the CA, at render and at signing.
func TestRenderControllerConfigKeepsLegacyMaterialWithoutTerraBase(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, manifest := renderInputsFor(t, now, keepEverySecret, true)
	output := filepath.Join(t.TempDir(), "controller.json")
	if err := renderControllerConfigAt(append(args, "--out", output), now); err != nil {
		t.Fatalf("legacy material did not render: %v", err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var cfg app.Config
	if err := protocol.DecodeStrict(wire, &cfg, bootstrap.MaxControllerConfigBytes); err != nil {
		t.Fatal(err)
	}
	if cfg.Controller.TerraBaseCACertFile != "" || cfg.Controller.TerraBaseCAKeyFile != "" || len(cfg.Controller.Workloads) != 0 {
		t.Fatalf("legacy render = %+v", cfg.Controller)
	}
	for index, flag := range []string{"--oci-region-intent", "--oci-region-config", "--placement-config"} {
		body, err := os.ReadFile(args[slices.Index(args, flag)+1])
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: digest(body), Bytes: body})
	}
	sign := func(cfg app.Config) bootstrap.Manifest {
		signed := manifest
		if signed.ControllerConfig, err = protocol.EncodeJSON(cfg); err != nil {
			t.Fatal(err)
		}
		signed.ControllerConfigSHA256 = digest(signed.ControllerConfig)
		return signed
	}
	if _, err := app.ValidateSignedControllerConfig(sign(cfg), ""); err != nil {
		t.Fatalf("legacy controller config rejected: %v", err)
	}
	_, profile := checkedInTerraBaseProfile(t)
	cfg.Controller.Workloads = map[string]app.WorkloadProfile{"terrabase": profile}
	if _, err := app.ValidateSignedControllerConfig(sign(cfg), ""); err == nil || !strings.Contains(err.Error(), "needs the signed member CA") {
		t.Fatalf("signed TerraBase profile without a member CA: %v", err)
	}
	profilePath, _ := checkedInTerraBaseProfile(t)
	args, _ = renderInputsFor(t, now, keepEverySecret, true)
	output = filepath.Join(t.TempDir(), "controller.json")
	err = renderControllerConfigAt(append(args, "--terrabase-profile", profilePath,
		"--terrabase-profile-sha256", fixtureFileDigest(profilePath), "--out", output), now)
	if err == nil || !strings.Contains(err.Error(), "needs the member CA") {
		t.Fatalf("TerraBase profile rendered without a member CA: %v", err)
	}
}

// The reviewed KV snapshot location becomes controller.kv_snapshot; a
// disabled or invalid location is refused.
func TestRenderControllerConfigWritesKVSnapshotLocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	args, _ := renderInputs(t, now, keepEverySecret)
	dir := t.TempDir()
	location := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := location("kv-snapshot.json", `{"enabled":true,"region":"sa-saopaulo-1","namespace":"grxnmoqvrcdv","bucket":"gru-1-head","prefix":"kv-snapshot/v1","interval_seconds":30}`)
	output := filepath.Join(dir, "controller.json")
	if err := renderControllerConfigAt(append(args, "--kv-snapshot", valid, "--kv-snapshot-sha256", fixtureFileDigest(valid),
		"--out", output), now); err != nil {
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
	if got := cfg.Controller.KVSnapshot; !got.Enabled || got.Bucket != "gru-1-head" || got.Prefix != "kv-snapshot/v1" ||
		got.Region != "sa-saopaulo-1" || got.IntervalSeconds != 30 {
		t.Fatalf("rendered kv_snapshot = %+v", got)
	}
	for name, body := range map[string]string{
		"disabled": `{"enabled":false}`,
		"unknown":  `{"enabled":true,"region":"sa-saopaulo-1","namespace":"n","bucket":"b","extra":1}`,
		"invalid":  `{"enabled":true,"region":"sa-saopaulo-1","namespace":"n","bucket":"b","interval_seconds":1}`,
	} {
		path := location(name+".json", body)
		err := renderControllerConfigAt(append(args, "--kv-snapshot", path, "--kv-snapshot-sha256", fixtureFileDigest(path),
			"--out", filepath.Join(dir, name+"-controller.json")), now)
		if err == nil {
			t.Errorf("%s KV snapshot location rendered", name)
		}
	}
}
