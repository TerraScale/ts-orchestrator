package vmimage

import (
	"bytes"
	"encoding/json"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

func TestNoCloudInitialGrantMatchesReceiverAndFixedPrivateFiles(t *testing.T) {
	spec := validNoCloudSpec(t)
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	var public, grant []byte
	for _, file := range seed.RootFiles {
		switch file.Path {
		case BootstrapGrantPath:
			grant = file.Content
		case BootstrapPublicKeyPath:
			public = file.Content
		default:
			continue
		}
		if file.Mode != 0400 || file.Owner != "" || file.Validate() != nil {
			t.Fatal("bootstrap material lacks root-only fixed file admission")
		}
		file.Mode = 0644
		if file.Validate() == nil {
			t.Fatal("publicly accessible bootstrap material accepted")
		}
	}
	admitted, err := hostagent.VerifyBootstrapGrant(spec.InstanceID, public, grant)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(admitted.Manifest)
	if err != nil || !bytes.Equal(canonical, spec.TSNode.DesiredHostManifest) {
		t.Fatal("bootstrap grant did not admit exact launch manifest")
	}
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	var config tsNodeConfigurationFile
	if err := json.Unmarshal(material.config, &config); err != nil {
		t.Fatal(err)
	}
	if config.BootstrapGrantFile != BootstrapGrantPath || config.BootstrapPublicKeyFile != BootstrapPublicKeyPath {
		t.Fatal("ts-node config omitted canonical grant references")
	}
	if bytes.Contains(seed.UserData, grant) || bytes.Contains(seed.UserData, public) {
		t.Fatal("grant bytes entered cloud-init userdata")
	}
	spec.TSNode.InitialGrant.SignedGrant[0] ^= 1
	if bytes.Equal(grant, spec.TSNode.InitialGrant.SignedGrant) {
		t.Fatal("seed retains caller-owned grant bytes")
	}
}

func TestNoCloudRejectsMissingForeignAndChangedInitialGrant(t *testing.T) {
	for _, kind := range []string{"missing", "foreign-host", "changed-launch", "signature", "private-key"} {
		t.Run(kind, func(t *testing.T) {
			spec := validNoCloudSpec(t)
			switch kind {
			case "missing":
				spec.TSNode.InitialGrant = nil
			case "foreign-host":
				spec.TSNode.Config.NodeID = "other-host"
			case "changed-launch":
				manifest, err := hostmanifest.ParseHostManifest(spec.TSNode.DesiredHostManifest)
				if err != nil {
					t.Fatal(err)
				}
				manifest.Components[0].Version = "9.0.0"
				spec.TSNode.DesiredHostManifest, err = hostmanifest.CanonicalHostManifestJSON(manifest)
				if err != nil {
					t.Fatal(err)
				}
			case "signature":
				spec.TSNode.InitialGrant.SignedGrant[0] ^= 1
			case "private-key":
				spec.TSNode.InitialGrant.PublicKeyPEM = spec.TSNode.MembershipIdentityPrivateKey
			}
			if _, err := BuildNoCloudSeed(spec); err == nil {
				t.Fatal("unadmitted bootstrap grant accepted")
			}
		})
	}
}
