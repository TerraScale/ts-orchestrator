//go:build linux

package host

import (
	"strings"
	"testing"
	"time"
)

func TestContainerMaterialInventoryBoundary(t *testing.T) {
	valid := func() ContainerMaterialFiles {
		return ContainerMaterialFiles{User: "65532:65532", ExpiresAt: time.Now().Add(time.Minute),
			Files: map[string][]byte{"key_file": []byte("secret")}, FileEnvironment: map[string]string{"KEY_FILE": "key_file"}}
	}
	if err := validateContainerMaterial(valid()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ContainerMaterialFiles){
		"alias":               func(files *ContainerMaterialFiles) { files.FileEnvironment["Key_FILE"] = "key_file" },
		"root":                func(files *ContainerMaterialFiles) { files.User = "0:65532" },
		"expired":             func(files *ContainerMaterialFiles) { files.ExpiresAt = time.Now().Add(-time.Second) },
		"credential deadline": func(files *ContainerMaterialFiles) { files.CredentialExpiresAt = time.Now().Add(time.Second) },
		"unbound file":        func(files *ContainerMaterialFiles) { files.Files["extra"] = []byte("value") },
	} {
		files := valid()
		change(&files)
		if err := validateContainerMaterial(files); err == nil {
			t.Errorf("%s material accepted", name)
		}
	}
	files := ContainerMaterialFiles{User: "65532:65532", ExpiresAt: time.Now().Add(time.Minute)}
	if err := validateContainerMaterial(files); err != nil || !files.CredentialExpiresAt.IsZero() {
		t.Fatal("explicit empty inventory fabricated credential expiry", err)
	}
}

func TestContainerInventoryContinuationRequiresOriginalExpiryAndDigest(t *testing.T) {
	query := containerMaterialQuery{}
	if !validContainerInventoryQuery(query) {
		t.Fatal("initial inventory request rejected")
	}
	query.Offset = 1
	if validContainerInventoryQuery(query) {
		t.Fatal("continuation accepted without inventory identity")
	}
	query.InventoryExpiresAt = time.Now().Add(time.Second)
	query.InventorySHA256 = strings.Repeat("a", 64)
	if !validContainerInventoryQuery(query) {
		t.Fatal("bounded continuation rejected")
	}
	query.InventoryExpiresAt = time.Now().Add(-time.Second)
	if validContainerInventoryQuery(query) {
		t.Fatal("expired inventory continuation accepted")
	}
	query.Offset = 0
	if validContainerInventoryQuery(query) {
		t.Fatal("new inventory accepted an inherited identity")
	}
}
