package vmimage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistedTrustBoundariesRejectAmbiguousJSON(t *testing.T) {
	t.Parallel()
	manifestData, err := os.ReadFile("ubuntu-24.04.3-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := DecodeManifest(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err = manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewBuildPlan(manifest, filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	planData, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	toolchainData, err := os.ReadFile("pins-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	toolchain, err := DecodeToolchainManifest(toolchainData)
	if err != nil {
		t.Fatal(err)
	}
	toolchainData, err = toolchain.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewPreparationReceipt(manifest, RootFSInspection{
		OSID: "ubuntu", OSVersionID: "24.04", OSVersion: "Ubuntu 24.04.3 LTS (Noble Numbat)",
		SanitizedMounts: []string{"/boot", "/boot/efi"}, FilesystemCheck: "e2fsck -fn",
	})
	if err != nil {
		t.Fatal(err)
	}
	receiptData, err := receipt.CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}

	boundaries := []struct {
		name   string
		data   []byte
		decode func([]byte) error
	}{
		{name: "manifest", data: manifestData, decode: func(data []byte) error { _, err := DecodeManifest(data); return err }},
		{name: "plan", data: planData, decode: func(data []byte) error { _, err := DecodeBuildPlan(data); return err }},
		{name: "toolchain", data: toolchainData, decode: func(data []byte) error { _, err := DecodeToolchainManifest(data); return err }},
		{name: "receipt", data: receiptData, decode: func(data []byte) error { _, err := DecodePreparationReceipt(data, manifest); return err }},
	}
	for _, boundary := range boundaries {
		boundary := boundary
		t.Run(boundary.name, func(t *testing.T) {
			t.Parallel()
			if err := boundary.decode(boundary.data); err != nil {
				t.Fatalf("canonical document rejected: %v", err)
			}
			mutations := map[string][]byte{
				"duplicate": duplicateFirstJSONField(t, boundary.data),
				"case":      bytes.Replace(boundary.data, []byte(`"architecture"`), []byte(`"Architecture"`), 1),
				"null":      bytes.Replace(boundary.data, []byte(`"architecture":"amd64"`), []byte(`"architecture":null`), 1),
				"unknown":   append([]byte(`{"unknown":true,`), boundary.data[1:]...),
				"missing":   removeJSONField(t, boundary.data, "architecture"),
				"trailing":  append(append([]byte(nil), boundary.data...), []byte(`{}`)...),
			}
			for name, data := range mutations {
				if bytes.Equal(data, boundary.data) {
					t.Fatalf("%s mutation did not alter document", name)
				}
				if err := boundary.decode(data); err == nil {
					t.Fatalf("%s JSON was accepted: %s", name, data)
				}
			}
		})
	}
}

func duplicateFirstJSONField(t *testing.T, data []byte) []byte {
	t.Helper()
	comma := bytes.IndexByte(data, ',')
	if len(data) < 2 || data[0] != '{' || comma < 2 {
		t.Fatal("fixture is not a non-empty JSON object")
	}
	result := make([]byte, 0, len(data)+comma)
	result = append(result, data[:comma+1]...)
	result = append(result, data[1:comma+1]...)
	result = append(result, data[comma+1:]...)
	return result
}

func removeJSONField(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, name)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
