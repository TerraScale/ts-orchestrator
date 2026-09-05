package vmimage

import (
	"encoding/base64"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"testing"
)

func TestTSNodeBootstrapRetainsImmutableReleaseIdentity(t *testing.T) {
	spec := validNoCloudSpec(t)
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ArchitectureARM64)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostmanifest.ParseHostManifest(material.launchManifest)
	if err != nil || len(manifest.Components) != 1 {
		t.Fatalf("launch metadata: %v", err)
	}
	component := manifest.Components[0]
	if component.Name != hostmanifest.TsNodeComponentName || component.Version != spec.TSNode.Version || component.Sha256 != spec.TSNode.SHA256 || component.Configuration != "" || component.Arguments != "" {
		t.Fatal("bootstrap metadata changed release or self launch ownership")
	}
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	directory := "/opt/terrascale/ts-node/" + spec.TSNode.Version
	for _, fragment := range []string{
		"path: " + directory + "/ts-node.launch.json",
		"path: " + directory + "/ts-node.config\n    owner: root:root\n    permissions: '0444'\n    encoding: b64\n    content: ''\n",
		"path: " + directory + "/ts-node.sha256\n    owner: root:root\n    permissions: '0444'\n    encoding: b64\n    content: " + base64.StdEncoding.EncodeToString([]byte(spec.TSNode.SHA256)) + "\n",
		"/usr/bin/install -o root -g root -m 0444 " + tsNodeBootstrapSigPath + " " + directory + "/ts-node.sig",
	} {
		if !strings.Contains(string(seed.UserData), fragment) {
			t.Fatalf("missing release metadata %q", fragment)
		}
	}
}
