package ociregion

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func TestSeedLaunchForwardsManagedHostImageProofs(t *testing.T) {
	directory := t.TempDir()
	write := func(name, wire string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	manifest := write("manifest.json", `{"schemaVersion":1,"keyId":"root","signature":"signed","scope":{"domain":"terrascale.bootstrap.manifest","role":"controller","slot":"controller-a","cell":"GRU"},"payload":{"schemaVersion":1,"slot":"controller-a","seedSlot":"controller-a","cell":"GRU"}}`)
	anchor := write("anchor.json", `{}`)
	identity := write("identity.json", `{"deploymentId":"0000000000F9PR1WNVDTEXS31Z"}`)
	enrollment := write("enrollment.json", `{}`)
	ssh := write("ssh.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl operator@terrascale")
	receipt := write("image.json", `{"image":1}`)
	delegation := write("delegation.json", `{"delegation":1}`)
	reviewed := write("reviewed.json", fmt.Sprintf(`{"manifest_sha256":%q,"anchor_sha256":%q}`, fileSHA(manifest), fileSHA(anchor)))
	engine := &Engine{Context: t.Context()}
	value, err := engine.Invoke("seed_launch", []any{Object{"cell": "GRU", "hosts": []any{Object{"slot": "controller-a"}}}, Path(reviewed), Path(manifest), Path(identity), Path(anchor), Path(enrollment), Path(ssh), Path(receipt), Path(delegation)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := obj(obj(value)["metadata"])
	if metadata[bootstrapstart.ManagedHostImageReceiptMetadataKey] != `{"image":1}` ||
		metadata[bootstrapstart.ManagedHostImageDelegationMetadataKey] != `{"delegation":1}` {
		t.Fatal("seed launch omitted the exact managed image proof bytes")
	}
}
