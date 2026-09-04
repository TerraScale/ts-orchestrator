package vmimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestToolchainInstallerExtractsOnlyPinnedExecutables(t *testing.T) {
	t.Parallel()
	firecracker := []byte("firecracker executable")
	jailer := []byte("jailer executable")
	manifest, archive := testToolchain(t, firecracker, jailer, nil)
	installer := &ToolchainInstaller{
		Root: t.TempDir(),
		Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != manifest.Archive.URL {
				t.Fatalf("requested %q", request.URL)
			}
			return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(archive)), Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
		})},
	}
	first, err := installer.Install(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer.Install(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Dir != second.Dir {
		t.Fatal("idempotent toolchain install changed destination")
	}
	for path, want := range map[string][]byte{first.Firecracker: firecracker, first.Jailer: jailer} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s has unexpected bytes", filepath.Base(path))
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %v, err = %v", filepath.Base(path), info.Mode(), err)
		}
	}
	entries, err := os.ReadDir(first.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("installed %d files, want two executables and a manifest", len(entries))
	}
}

func TestCheckedInToolchainPinsAreValidAndArchitectureSpecific(t *testing.T) {
	t.Parallel()
	for _, architecture := range []Architecture{ArchitectureAMD64, ArchitectureARM64} {
		architecture := architecture
		t.Run(string(architecture), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile("pins-" + string(architecture) + ".json")
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := DecodeToolchainManifest(data)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Architecture != architecture || manifest.FirecrackerVersion != "1.15.1" {
				t.Fatalf("toolchain identity = %q v%s", manifest.Architecture, manifest.FirecrackerVersion)
			}
		})
	}
}

func TestToolchainRejectsArchiveTraversalBeforeExtraction(t *testing.T) {
	t.Parallel()
	manifest, archive := testToolchain(t, []byte("firecracker"), []byte("jailer"), &tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	archiveDigest := digest(archive)
	manifest.Archive.SHA256 = archiveDigest
	manifest.Archive.Size = int64(len(archive))
	installer := &ToolchainInstaller{
		Root: t.TempDir(),
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(archive)), Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
		})},
	}
	if _, err := installer.Install(context.Background(), manifest); err == nil {
		t.Fatal("archive traversal was accepted")
	}
	if _, err := os.Stat(filepath.Join(installer.Root, "escape")); !os.IsNotExist(err) {
		t.Fatalf("unsafe archive path was created: %v", err)
	}
}

func testToolchain(t *testing.T, firecracker, jailer []byte, extra *tar.Header) (ToolchainManifest, []byte) {
	t.Helper()
	const prefix = "release-v1.15.1-x86_64/"
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	if extra != nil {
		if err := writer.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
		if extra.Size > 0 {
			if _, err := writer.Write(make([]byte, extra.Size)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, data := range map[string][]byte{
		prefix + "firecracker-v1.15.1-x86_64": firecracker,
		prefix + "jailer-v1.15.1-x86_64":      jailer,
		prefix + "ignored":                    []byte("not extracted"),
	} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	data := archive.Bytes()
	manifest := ToolchainManifest{
		SchemaVersion:      ToolchainSchemaVersion,
		Architecture:       ArchitectureAMD64,
		FirecrackerVersion: "1.15.1",
		Archive: RemoteArtifact{
			URL: "https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz", SHA256: digest(data), Size: int64(len(data)),
		},
		Firecracker: ArchiveMember{ArchivePath: prefix + "firecracker-v1.15.1-x86_64", Name: "firecracker", SHA256: digest(firecracker), Size: int64(len(firecracker)), Mode: 0o755},
		Jailer:      ArchiveMember{ArchivePath: prefix + "jailer-v1.15.1-x86_64", Name: "jailer", SHA256: digest(jailer), Size: int64(len(jailer)), Mode: 0o755},
		SDKModule:   "github.com/firecracker-microvm/firecracker-go-sdk",
		SDKVersion:  "v1.0.0",
	}
	return manifest, append([]byte(nil), data...)
}
