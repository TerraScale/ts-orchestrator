package vmimage

import (
	"bytes"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
	"testing"
)

func TestNoCloudControllerFilesAndConfiguredGrant(t *testing.T) {
	t.Run("default", func(t *testing.T) { testNoCloudControllerFilesAndConfiguredGrant(t, false) })
	t.Run("source-capture", func(t *testing.T) { testNoCloudControllerFilesAndConfiguredGrant(t, true) })
}

func testNoCloudControllerFilesAndConfiguredGrant(t *testing.T, capture bool) {
	spec := validNoCloudSpec(t)
	_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(spec.TSNode.MembershipIdentityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	guests := []vmcontrolseed.Guest{{ID: spec.InstanceID, Address: spec.Address, MembershipPublicKey: public}}
	var materials map[string]vmcontrolseed.Material
	if capture {
		materials, err = vmcontrolseed.GenerateGRUWithPreliminaryCapture("run1", guests, vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20})
	} else {
		materials, err = vmcontrolseed.GenerateGRU("run1", guests)
	}
	if err != nil {
		t.Fatal(err)
	}
	m := materials[spec.InstanceID]
	defer m.Clear()
	spec.TSNode.Controller = &m
	spec.TSNode.Config.AuthorityReader, err = m.AuthorityReader()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m.Files[vmcontrolseed.CAPath], spec.TSNode.NATSIdentity.TLSCA) || bytes.Equal(m.Files[vmcontrolseed.NKeyPath], spec.TSNode.NATSIdentity.NKeySeed) {
		t.Fatal("root transport credentials reused")
	}
	manifest, err := hostmanifest.ParseHostManifest(spec.TSNode.DesiredHostManifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Components[0].Arguments = vmcontrolseed.Arguments
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
		if !vmcontrolseed.IsFilePath(file.Path) && !vmcontrolseed.IsAuthorityFilePath(file.Path) {
			continue
		}
		count++
		wantOwner := vmcontrolseed.ServiceUser
		if vmcontrolseed.IsAuthorityFilePath(file.Path) {
			wantOwner = ""
		}
		if file.Owner != wantOwner || file.Mode != 0400 || file.Validate() != nil {
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
		if vmcontrolseed.IsAuthorityFilePath(file.Path) {
			file.Owner = vmcontrolseed.ServiceUser
		}
		if file.Validate() == nil {
			t.Fatal("root-owned controller credentials accepted")
		}
	}
	if count != len(m.Files) {
		t.Fatal("controller files missing")
	}
	script := controllerOwnershipBootstrap(seed.RootFiles)
	if !bytes.Contains([]byte(script), []byte("stat -c %U:%G:%a "+vmcontrolseed.ServerPrivateKeyPath)) {
		t.Fatal("broker credential ownership not verified")
	}
	m.Settings += " "
	if _, err := BuildNoCloudSeed(spec); err == nil {
		t.Fatal("manifest/configuration mismatch accepted")
	}
}
