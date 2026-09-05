package ocireconcile

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

func gzipHostFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestBootstrapGzipPreservesExactBoundedFiles(t *testing.T) {
	for _, raw := range [][]byte{[]byte("{}"), bytes.Repeat([]byte("a"), bootstrapHostFileLimit)} {
		encoding, content, err := encodeBootstrapHostFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBootstrapHostFile(encoding, content)
		if err != nil || !bytes.Equal(raw, decoded) {
			t.Fatalf("round trip: %v", err)
		}
		if len(raw) == bootstrapHostFileLimit && encoding != "gz+b64" {
			t.Fatal("large repetitive file was not compressed")
		}
	}
}

func TestBootstrapGzipRejectsBombsTruncationAndTrailingData(t *testing.T) {
	valid := gzipHostFixture(t, []byte(`{"ok":true}`))
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-8] ^= 1
	cases := map[string][]byte{
		"bomb":          gzipHostFixture(t, bytes.Repeat([]byte("a"), bootstrapHostFileLimit+1)),
		"truncated":     valid[:len(valid)-1],
		"checksum":      corrupt,
		"trailing":      append(append([]byte(nil), valid...), 0),
		"second-member": append(append([]byte(nil), valid...), valid...),
		"header":        []byte("not gzip"),
		"empty":         gzipHostFixture(t, nil),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBootstrapHostFile("gz+b64", base64.StdEncoding.EncodeToString(raw)); err == nil {
				t.Fatal("malformed gzip accepted")
			}
		})
	}
	for _, encoding := range []string{"gzip", "b64"} {
		if _, err := decodeBootstrapHostFile(encoding, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), bootstrapHostFileLimit+1))); err == nil {
			t.Fatal("oversized file accepted")
		}
	}
	if _, err := decodeBootstrapHostFile("gz+b64", "!!"); err == nil {
		t.Fatal("malformed base64 accepted")
	}
}

func TestBootstrapRendererEnforcesSerializedMetadataBound(t *testing.T) {
	render := func(content []byte) (string, error) {
		return TSNodeCloudInit("1.2.3", strings.Repeat("ab", 32), "https://releases.terrascale.tech/ts-node", "https://releases.terrascale.tech/ts-node.sig", strings.Repeat("ab", 32), []BootstrapHostFile{
			{Path: "/etc/terrascale/ts-node.json", Content: content, Private: true},
			{Path: "/var/lib/terrascale/ts-node/manifest.json", Content: content, Private: true},
		})
	}
	content := []byte(`{"payload":"` + strings.Repeat("a", bootstrapHostFileLimit-14) + `"}`)
	encoded, err := render(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > bootstrapMetadataLimit {
		t.Fatal("serialized metadata exceeds bound")
	}
	if err := validateBootstrapHostCloudInit(map[int]string{1: encoded}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := render(bytes.Repeat([]byte("a"), bootstrapHostFileLimit+1)); err == nil {
		t.Fatal("oversized raw content accepted")
	}
	random := make([]byte, 18000)
	_, _ = rand.New(rand.NewSource(1)).Read(random)
	incompressible := []byte(`{"payload":"` + base64.StdEncoding.EncodeToString(random) + `"}`)
	if len(incompressible) > bootstrapHostFileLimit {
		t.Fatal("fixture must fit decoded per-file bound")
	}
	if _, err := render(incompressible); err == nil || !strings.Contains(err.Error(), "OCI metadata bound") {
		t.Fatal("oversized actual serialized seed accepted")
	}
}
