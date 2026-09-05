package provider

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestComputeLaunchBindsEachMemberToItsOwnInitialSeed(t *testing.T) {
	declared := testComputeDeclared(t)
	raw, err := base64.StdEncoding.DecodeString(declared.CloudInitByMember[2])
	if err != nil {
		t.Fatal(err)
	}
	declared.CloudInitByMember[2] = base64.StdEncoding.EncodeToString(append(raw, []byte("\n# gru-2\n")...))
	reconciler := &ComputeReconciler{}
	plan, err := reconciler.Reconcile(context.Background(), declared, testComputeObserved())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, action := range plan.Actions {
		launch, ok := action.(LaunchMemberAction)
		if !ok {
			continue
		}
		count++
		if launch.Spec.CloudInitBase64 != declared.CloudInitByMember[launch.Spec.Index] {
			t.Fatal("host received another slot's seed")
		}
	}
	if count != 2 {
		t.Fatalf("launch count %d", count)
	}
	delete(declared.CloudInitByMember, 2)
	if _, err := reconciler.Reconcile(context.Background(), declared, testComputeObserved()); err == nil {
		t.Fatal("missing slot silently used shared cloud-init")
	}
}
func TestInitialHostSeedRejectsSystemUnitAndPathReplacement(t *testing.T) {
	files := []BootstrapHostFile{{Path: "/etc/terrascale/ts-node.json", Content: []byte("{}"), Private: true}, {Path: "/var/lib/terrascale/ts-node/manifest.json", Content: []byte("{}"), Private: true}}
	render := func(files []BootstrapHostFile) error {
		_, err := TSNodeCloudInit("1.2.3", strings.Repeat("ab", 32), "https://releases.terrascale.tech/ts-node", "https://releases.terrascale.tech/ts-node.sig", strings.Repeat("ab", 32), files)
		return err
	}
	if err := render(files); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/systemd/system/terrascale-ts-node.service", "/etc/terrascale/../passwd", "/etc/terrascale/ts-node.pub"} {
		candidate := append(append([]BootstrapHostFile(nil), files...), BootstrapHostFile{Path: path, Content: []byte("replacement")})
		if err := render(candidate); err == nil {
			t.Fatalf("unsafe destination accepted %s", path)
		}
	}
}

func TestInitialHostSeedRejectsConfiglessLaunch(t *testing.T) {
	seed := testComputeDeclared(t).CloudInitByMember[1]
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{
		"#cloud-config\nruncmd: []\n",
		strings.Replace(string(raw), "/etc/terrascale/ts-node.json", "/etc/terrascale/other.json", 1),
		strings.Replace(string(raw), "/var/lib/terrascale/ts-node/manifest.json", "/etc/terrascale/other.json", 1),
	} {
		if err := validateBootstrapHostCloudInit(map[int]string{1: base64.StdEncoding.EncodeToString([]byte(document))}, 1); err == nil {
			t.Fatal("configless launch seed admitted")
		}
	}
}
