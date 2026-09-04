package vmimage

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecodeGuestChannelSeedPreservesCanonicalEncoding(t *testing.T) {
	t.Parallel()
	canonical := strictGuestSeedFixture(t)
	decoded, err := DecodeGuestChannelSeed(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, canonical) {
		t.Fatalf("canonical seed changed after strict decode\n got: %s\nwant: %s", reencoded, canonical)
	}
	if GuestChannelSeedDigest(reencoded) != GuestChannelSeedDigest(canonical) {
		t.Fatal("canonical seed digest changed after strict decode")
	}

	var indented bytes.Buffer
	if err := json.Indent(&indented, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGuestChannelSeed(indented.Bytes()); err != nil {
		t.Fatalf("semantically valid indented seed was rejected: %v", err)
	}
}

func TestDecodeGuestChannelSeedRejectsNonExactJSON(t *testing.T) {
	t.Parallel()
	valid := strictGuestSeedFixture(t)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "null document", data: []byte("null")},
		{name: "trailing document", data: append(append([]byte(nil), valid...), []byte(`{}`)...)},
		{name: "top-level case variant", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			renameSeedJSONField(t, root, "schemaVersion", "SchemaVersion")
		})},
		{name: "top-level duplicate", data: replaceSeedJSONOnce(t, valid, []byte(`{"schemaVersion":1,"image":`), []byte(`{"schemaVersion":1,"schemaVersion":1,"image":`))},
		{name: "top-level unknown", data: mutateSeedJSON(t, valid, func(root map[string]any) { root["unknown"] = true })},
		{name: "top-level null", data: mutateSeedJSON(t, valid, func(root map[string]any) { root["hostname"] = nil })},
		{name: "top-level missing", data: mutateSeedJSON(t, valid, func(root map[string]any) { delete(root, "hostname") })},

		{name: "image case variant", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			renameSeedJSONField(t, seedJSONObject(t, root["image"], "image"), "ubuntuRelease", "UbuntuRelease")
		})},
		{name: "image duplicate", data: replaceSeedJSONOnce(t, valid, []byte(`"image":{"schemaVersion":1,`), []byte(`"image":{"schemaVersion":1,"schemaVersion":1,`))},
		{name: "image unknown", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			seedJSONObject(t, root["image"], "image")["unknown"] = true
		})},
		{name: "image null", data: mutateSeedJSON(t, valid, func(root map[string]any) { root["image"] = nil })},
		{name: "image field null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			seedJSONObject(t, root["image"], "image")["kernel"] = nil
		})},
		{name: "image field missing", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			delete(seedJSONObject(t, root["image"], "image"), "version")
		})},

		{name: "image artifact case variant", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			renameSeedJSONField(t, strictKernelJSON(t, root), "name", "Name")
		})},
		{name: "image artifact duplicate", data: replaceSeedJSONOnce(t, valid, []byte(`"kernel":{"name":"vmlinuz",`), []byte(`"kernel":{"name":"vmlinuz","name":"vmlinuz",`))},
		{name: "image artifact unknown", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictKernelJSON(t, root)["unknown"] = true
		})},
		{name: "image artifact null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictKernelJSON(t, root)["mode"] = nil
		})},
		{name: "image artifact missing", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			delete(strictKernelJSON(t, root), "mode")
		})},

		{name: "transform case variant", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			renameSeedJSONField(t, strictTransformJSON(t, root), "type", "Type")
		})},
		{name: "transform duplicate", data: replaceSeedJSONOnce(t, valid, []byte(`"transform":{"type":"qcow2-root-partition",`), []byte(`"transform":{"type":"qcow2-root-partition","type":"qcow2-root-partition",`))},
		{name: "transform unknown", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictTransformJSON(t, root)["unknown"] = true
		})},
		{name: "transform null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictRootFSJSON(t, root)["transform"] = nil
		})},
		{name: "transform field null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictTransformJSON(t, root)["sectorSize"] = nil
		})},
		{name: "transform field missing", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			delete(strictTransformJSON(t, root), "sectorCount")
		})},

		{name: "guest artifact case variant", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			renameSeedJSONField(t, strictGuestArtifactJSON(t, root), "component", "Component")
		})},
		{name: "guest artifact duplicate", data: replaceSeedJSONOnce(t, valid, []byte(`"artifacts":[{"component":"ts-node",`), []byte(`"artifacts":[{"component":"ts-node","component":"ts-node",`))},
		{name: "guest artifact unknown", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictGuestArtifactJSON(t, root)["unknown"] = true
		})},
		{name: "guest artifact null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			strictGuestArtifactJSON(t, root)["mode"] = nil
		})},
		{name: "guest artifact missing", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			delete(strictGuestArtifactJSON(t, root), "mode")
		})},
		{name: "guest artifact array null", data: mutateSeedJSON(t, valid, func(root map[string]any) { root["artifacts"] = nil })},
		{name: "guest artifact item null", data: mutateSeedJSON(t, valid, func(root map[string]any) {
			seedJSONArray(t, root["artifacts"], "artifacts")[0] = nil
		})},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeGuestChannelSeed(test.data); err == nil {
				t.Fatalf("non-exact seed was accepted: %s", test.data)
			}
		})
	}
}

func strictGuestSeedFixture(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	manifest.RootFS.InputSHA256 = digest([]byte("source-qcow2"))
	manifest.RootFS.InputSize = int64(len("source-qcow2"))
	manifest.RootFS.Transform = &Transform{Type: TransformQCOW2RootPartition, SectorSize: 1, StartSector: 1, SectorCount: int64(len(rootfs))}
	seed, err := BuildGuestChannelSeed(GuestSeedSpec{
		Image: manifest, Hostname: "gru-member-1", InstanceID: "vm-001", Region: "gru", DataDiskPath: "/dev/vdb",
		Artifacts: []GuestArtifact{
			guestArtifact("terrabase", "3.0.0", "/fixtures/terrabase", []byte("tb")),
			guestArtifact("ts-node", "3.0.0", "/fixtures/ts-node", []byte("node")),
			guestArtifact("orchestrator", "3.0.0", "/fixtures/orchestrator", []byte("orch")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

func mutateSeedJSON(t *testing.T, data []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	mutate(root)
	result, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func replaceSeedJSONOnce(t *testing.T, data, old, replacement []byte) []byte {
	t.Helper()
	if bytes.Count(data, old) != 1 {
		t.Fatalf("seed fixture contains %d copies of %q, want one", bytes.Count(data, old), old)
	}
	return bytes.Replace(data, old, replacement, 1)
}

func renameSeedJSONField(t *testing.T, object map[string]any, old, replacement string) {
	t.Helper()
	value, ok := object[old]
	if !ok {
		t.Fatalf("seed fixture does not contain %q", old)
	}
	delete(object, old)
	object[replacement] = value
}

func strictKernelJSON(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	return seedJSONObject(t, seedJSONObject(t, root["image"], "image")["kernel"], "image.kernel")
}

func strictRootFSJSON(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	return seedJSONObject(t, seedJSONObject(t, root["image"], "image")["rootfs"], "image.rootfs")
}

func strictTransformJSON(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	return seedJSONObject(t, strictRootFSJSON(t, root)["transform"], "image.rootfs.transform")
}

func strictGuestArtifactJSON(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	artifacts := seedJSONArray(t, root["artifacts"], "artifacts")
	if len(artifacts) == 0 {
		t.Fatal("seed fixture contains no guest artifacts")
	}
	return seedJSONObject(t, artifacts[0], "artifacts[0]")
}

func seedJSONObject(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("seed fixture %s is %T, want object", path, value)
	}
	return object
}

func seedJSONArray(t *testing.T, value any, path string) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("seed fixture %s is %T, want array", path, value)
	}
	return array
}
