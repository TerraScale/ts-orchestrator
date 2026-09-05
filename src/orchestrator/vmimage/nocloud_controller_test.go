package vmimage

import (
	"bytes"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
	"testing"
)

func TestNoCloudControllerFilesAndConfiguredGrant(t *testing.T) {
	spec := validNoCloudSpec(t)
	materials, err := vmcontrolseed.GenerateGRU("run1", []vmcontrolseed.Guest{{ID: spec.InstanceID, Address: spec.Address, CommandPrivateKey: spec.TSNode.MembershipIdentityPrivateKey}})
	if err != nil {
		t.Fatal(err)
	}
	m := materials[spec.InstanceID]
	defer m.Clear()
	spec.TSNode.Controller = &m
	if bytes.Equal(m.Files[vmcontrolseed.CAPath], spec.TSNode.NATSIdentity.TLSCA) || bytes.Equal(m.Files[vmcontrolseed.NKeyPath], spec.TSNode.NATSIdentity.NKeySeed) {
		t.Fatal("root transport credentials reused")
	}
	manifest, err := hostmanifest.ParseHostManifest(spec.TSNode.DesiredHostManifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Components[0].Arguments = "run --config @config"
	manifest.Components[0].Configuration = m.Settings
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
	count := 0
	for _, file := range seed.RootFiles {
		if !vmcontrolseed.IsFilePath(file.Path) {
			continue
		}
		count++
		if file.Owner != vmcontrolseed.ServiceUser || file.Mode != 0400 || file.Validate() != nil {
			t.Fatalf("unbound controller file %s", file.Path)
		}
		if !bytes.Equal(file.Content, m.Files[file.Path]) || bytes.Contains(seed.UserData, file.Content) {
			t.Fatalf("controller bytes misplaced %s", file.Path)
		}
		file.Mode = 0444
		if file.Validate() == nil {
			t.Fatal("public controller credentials accepted")
		}
		file.Mode = 0400
		file.Owner = ""
		if file.Validate() == nil {
			t.Fatal("root-owned controller credentials accepted")
		}
	}
	if count != len(m.Files) {
		t.Fatal("controller files missing")
	}
	script := controllerOwnershipBootstrap(seed.RootFiles)
	if !bytes.Contains([]byte(script), []byte("stat -c %U:%G:%a "+vmcontrolseed.ServerConfigPath)) {
		t.Fatal("broker config ownership not verified")
	}
	m.Settings += " "
	if _, err := BuildNoCloudSeed(spec); err == nil {
		t.Fatal("manifest/configuration mismatch accepted")
	}
}
