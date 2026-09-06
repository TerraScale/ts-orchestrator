package vmimage

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

func TestNoCloudCarriesSignedEngineConfigurationAndPrivateTLS(t *testing.T) {
	spec := validNoCloudSpec(t)
	manifest, err := hostmanifest.ParseHostManifest(spec.TSNode.DesiredHostManifest)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []vmengineconfig.Binding{{NodeID: spec.InstanceID, Region: "GRU", Address: spec.Address}, {NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"}}
	_, path := testengineconfig.DatabaseDeclaration(t, bindings, manifest.Components[1].Sha256, manifest.Components[1].Version)
	materials, err := vmengineconfig.Load(path, manifest.Components[1].Sha256, manifest.Components[1].Version, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	spec.TSNode.Engine = materials[spec.InstanceID]
	manifest, err = spec.TSNode.Engine.Apply(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = bootstrap.PlanControlLaunchManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec.TSNode.DesiredHostManifest, err = hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	grant, err := issuer.Grant(spec.InstanceID, manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec.TSNode.InitialGrant = &TSNodeInitialGrant{PublicKeyPEM: grant.PublicKeyPEM, SignedGrant: grant.SignedGrant}
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ArchitectureARM64)
	if err != nil {
		t.Fatal(err)
	}
	var config tsNodeConfigurationFile
	if err := json.Unmarshal(material.config, &config); err != nil {
		t.Fatal(err)
	}
	if config.EngineObservation == nil || *config.EngineObservation != spec.TSNode.Engine.Observation() {
		t.Fatal("engine observation configuration missing or substituted")
	}
	observerCount := 0
	for _, file := range seed.RootFiles {
		if _, ok := spec.TSNode.Engine.ObserverFiles()[file.Path]; ok {
			observerCount++
			if file.Owner != "" || file.Mode != 0600 {
				t.Fatal("observer credentials are not private root material")
			}
		}
	}
	if observerCount != 3 {
		t.Fatal("observer credentials missing")
	}
	controlFiles := spec.TSNode.Engine.ControlFiles()
	if len(controlFiles) != 9 {
		t.Fatal("control service material missing")
	}
	controlConfig, err := placementpublisher.ParseHostFile(controlFiles[placementpublisher.HostFilePath], "gru", spec.InstanceID)
	if err != nil || controlConfig.EngineEndpoint != "127.0.0.1:8421" {
		t.Fatalf("host control config=%v error=%v", controlConfig, err)
	}
	var runSettings map[string]string
	if err := json.Unmarshal([]byte(manifest.Components[0].Configuration), &runSettings); err != nil || runSettings["TS_ORCH_PLACEMENT_HOST_FILE"] != placementpublisher.HostFilePath {
		t.Fatal("signed production run omitted placement host file")
	}
	controlCount := 0
	for _, file := range seed.RootFiles {
		if !vmengineconfig.IsControlPath(file.Path) {
			continue
		}
		controlCount++
		if file.Owner != membershipServiceUser || file.Mode != 0400 || file.Validate() != nil || !bytes.Equal(file.Content, controlFiles[file.Path]) {
			t.Fatal("control material changed or owner access invalid")
		}
		if bytes.Contains(seed.UserData, file.Content) {
			t.Fatal("control credential leaked into cloud-init data")
		}
		wrong := file
		wrong.Owner = ""
		if wrong.Validate() == nil {
			t.Fatal("root-only control material accepted for nonroot service")
		}
	}
	if controlCount != 9 {
		t.Fatal("control service files not installed")
	}
	if !strings.Contains(controllerOwnershipBootstrap(seed.RootFiles), placementpublisher.HostFilePath) {
		t.Fatal("control service ownership missing")
	}
	databaseCount := 0
	for _, file := range seed.RootFiles {
		if !vmengineconfig.IsDatabasePath(file.Path) {
			continue
		}
		databaseCount++
		if file.Mode != 0400 || file.Owner != membershipServiceUser {
			t.Fatal("database material not isolated to orchestrator")
		}
		if bytes.Contains(seed.UserData, file.Content) {
			t.Fatal("database secret bytes exposed to cloud-init")
		}
	}
	if databaseCount != 7 {
		t.Fatalf("database files missing: %d", databaseCount)
	}
	var runConfig map[string]string
	if err := json.Unmarshal([]byte(manifest.Components[0].Configuration), &runConfig); err != nil {
		t.Fatal(err)
	}
	if runConfig[databaseadmission.HostFileEnvironment] != databaseadmission.HostFilePath || runConfig[databaseadmission.BrokerGrantsEnvironment] != databaseadmission.BrokerGrantsPath {
		t.Fatal("signed native boot omits database host or broker material")
	}
	count := 0
	for _, file := range seed.RootFiles {
		if !vmengineconfig.IsTLSPath(file.Path) {
			continue
		}
		count++
		if err := file.Validate(); err != nil {
			t.Fatal(err)
		}
		if file.Owner != vmengineconfig.ServiceUser || file.Mode != 0400 {
			t.Fatal("engine credentials lack dedicated owner")
		}
		if bytes.Contains(seed.UserData, file.Content) {
			t.Fatal("TLS bytes leaked into cloud-init data")
		}
		wrong := file
		wrong.Owner = membershipServiceUser
		if wrong.Validate() == nil {
			t.Fatal("orchestrator may own engine private material")
		}
	}
	if count != 3 {
		t.Fatal("engine TLS files missing")
	}
	script := engineOwnershipBootstrap(seed.RootFiles)
	if !strings.Contains(script, "chown terrascale-terrabase:terrascale-terrabase "+vmengineconfig.PrivateKeyPath) {
		t.Fatal("credential ownership not installed")
	}
	spec.Address = "10.77.0.12"
	if _, err := BuildNoCloudSeed(spec); err == nil {
		t.Fatal("wrong guest address accepted")
	}
	spec.Address = bindings[0].Address
	spec.TSNode.DesiredHostManifest = bytes.Replace(spec.TSNode.DesiredHostManifest, []byte("production"), []byte("local-development"), 1)
	if _, err := BuildNoCloudSeed(spec); err == nil {
		t.Fatal("engine mode tampering accepted")
	}
}
