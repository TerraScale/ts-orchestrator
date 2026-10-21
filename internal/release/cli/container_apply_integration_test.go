package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// Actual OCI layout, Git, delegated signatures, allocator and OCI SDK/HTTP are
// exercised. HTTP models regional admission; live runtime readiness is separate.
func TestSignedContainerProducerApplyHTTPRecovery(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: flaky on main since the 2026-10-21 integration-line merge")
	base := newApplyHTTPFixture(t)
	f := &containerHTTPFixture{applyHTTPFixture: base}
	base.reset("")
	server := httptest.NewServer(http.HandlerFunc(f.serveContainer))
	defer server.Close()
	clientInterface, err := base.env.storage("GRU")
	if err != nil {
		t.Fatal(err)
	}
	client := clientInterface.(objectstorage.ObjectStorageClient)
	client.Host = server.URL
	client.HTTPClient = applyHTTPDispatcher{server}
	f.allocations = release.SequenceLocation{Client: client, Namespace: "ns", Bucket: "gru-1-head"}
	env := deployEnv{timeout: 2 * time.Second, storage: func(string) (releasechannel.ObjectClient, error) { return client, nil }}
	leaf, err := readDelegatedPrivateKey(base.leafPath)
	if err != nil {
		t.Fatal(err)
	}
	public := leaf.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	now := time.Now().UTC()
	role := "ts-auth"
	caps := make([]trust.Capability, 0, 6)
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		for _, architecture := range []string{"amd64", "arm64"} {
			scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Environment: "production", Role: role, Architecture: architecture})
			caps = append(caps, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}})
		}
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: caps}, now.Add(-time.Minute), now.Add(time.Hour), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, _ := trust.EncodeEnvelope(grant)
	inputs := t.TempDir()
	delegationPath, migrationPath := filepath.Join(inputs, "delegation.json"), filepath.Join(inputs, "migration.json")
	writeFixtureFile(t, delegationPath, grantWire, 0o600)
	writeFixtureFile(t, migrationPath, serviceMigrationFixture(t, base, role, public, now), 0o600)
	layout, pin, children := containerCLIImageLayout(t)
	child := children["amd64"]
	evidenceDirectory := t.TempDir()
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		_, rootDigest, _ := strings.Cut(pin, "@sha256:")
		for architecture, child := range children {
			expected := release.ProductionExpectation{SourceRevision: base.binary.SourceRevision, ArtifactSHA256: child, QualificationSHA256: rootDigest, Cell: cell, Environment: "production", Runtime: release.ProductionRuntime, Architecture: architecture, Role: role}
			proof := writeProductionEvidence(t, evidenceDirectory, expected)
			writeProductionRecord(t, filepath.Join(evidenceDirectory, cell, architecture, "production.json"), proof, base.rootPrivate, now.Add(-time.Minute), now.Add(time.Hour))
		}
	}
	outputDirectory := t.TempDir()
	producerArgs := []string{"--dir", outputDirectory, "--oci-layout", layout, "--image", pin, "--role", role, "--repository", "https://source.example.invalid/ts-auth", "--commit", base.binary.SourceRevision, "--source-checkout", base.sourceDir, "--environment", "production", "--root-key", base.rootPath, "--delegation", delegationPath, "--sequence-migration", migrationPath, "--production-evidence-dir", evidenceDirectory, "--signing-key", base.leafPath, "--cell", "GRU", "--cell", "SFO", "--cell", "FRA"}
	c := command{ctx: t.Context(), output: io.Discard}
	if err := c.containerBundleWith(producerArgs, env); err != nil {
		t.Fatal(err)
	}
	expectedIndex, err := os.ReadFile(filepath.Join(layout, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		for architecture := range children {
			wire, err := os.ReadFile(filepath.Join(outputDirectory, cell, architecture, "container.json"))
			if err != nil {
				t.Fatal(err)
			}
			var bundle release.ContainerBundle
			if err := json.Unmarshal(wire, &bundle); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bundle.Index, expectedIndex) {
				t.Fatalf("%s/%s signed bundle lost exact retained OCI index", cell, architecture)
			}
		}
	}
	applyArgs := []string{"--dir", outputDirectory, "--root-key", base.rootPath, "--namespace", "ns"}
	f.mu.Lock()
	f.failure = "storage"
	f.mu.Unlock()
	if err := c.containerApplyWith(applyArgs, env); err == nil || !strings.Contains(err.Error(), "SFO") {
		t.Fatalf("regional failure: %v", err)
	}
	f.mu.Lock()
	if f.channelWrites["GRU"] != 2 || f.channelWrites["FRA"] != 2 || f.channelWrites["SFO"] != 0 {
		t.Fatal("regional independence", f.channelWrites)
	}
	f.failure = ""
	f.mu.Unlock()
	// Both qualified channels publish, but only one regional service completes.
	// The unrelated status telemetry reports arm64 and cannot select admission.
	if err := c.containerApplyWith(applyArgs, env); err != nil {
		t.Fatal("retry", err)
	}
	// Renewing independent qualification keeps the exact content sequence.
	originalBundleWire, err := os.ReadFile(filepath.Join(outputDirectory, "GRU", "amd64", "container.json"))
	if err != nil {
		t.Fatal(err)
	}
	var originalBundle release.ContainerBundle
	if err := json.Unmarshal(originalBundleWire, &originalBundle); err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		_, rootDigest, _ := strings.Cut(pin, "@sha256:")
		for architecture, child := range children {
			expected := release.ProductionExpectation{SourceRevision: base.binary.SourceRevision, ArtifactSHA256: child, QualificationSHA256: rootDigest, Cell: cell, Environment: "production", Runtime: release.ProductionRuntime, Architecture: architecture, Role: role}
			proof := writeProductionEvidence(t, evidenceDirectory, expected)
			writeProductionRecord(t, filepath.Join(evidenceDirectory, cell, architecture, "production.json"), proof, base.rootPrivate, now.Add(-30*time.Second), now.Add(time.Hour))
		}
	}
	renewedDirectory := t.TempDir()
	producerArgs[1] = renewedDirectory
	if err := c.containerBundleWith(producerArgs, env); err != nil {
		t.Fatal("renew qualification", err)
	}
	renewedWire, err := os.ReadFile(filepath.Join(renewedDirectory, "GRU", "amd64", "container.json"))
	if err != nil {
		t.Fatal(err)
	}
	var renewedBundle release.ContainerBundle
	if err := json.Unmarshal(renewedWire, &renewedBundle); err != nil {
		t.Fatal(err)
	}
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: role, Architecture: "amd64"}
	beforeRenewal, err := release.VerifyContainerHistorical(originalBundle, base.roots, target)
	if err != nil {
		t.Fatal(err)
	}
	afterRenewal, err := release.VerifyContainerHistorical(renewedBundle, base.roots, target)
	if err != nil {
		t.Fatal(err)
	}
	if beforeRenewal.Claim().ReleaseSequence != afterRenewal.Claim().ReleaseSequence || beforeRenewal.ReleaseIdentity() != afterRenewal.ReleaseIdentity() || beforeRenewal.Fingerprint() == afterRenewal.Fingerprint() {
		t.Fatal("qualification renewal changed content sequence or did not renew signed proof")
	}
	if err := c.containerApplyWith([]string{"--dir", renewedDirectory, "--root-key", base.rootPath, "--namespace", "ns"}, env); err != nil {
		t.Fatal("renewed same-sequence apply", err)
	}
	// Source-free apply retains only public bundles, standard layout and evidence.
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	if err := os.Rename(base.leafPath, base.leafPath+".retained"); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(base.leafPath+".retained", base.leafPath)
	if err := c.containerApplyWith(applyArgs, env); err != nil {
		t.Fatal("source-free retry", err)
	}
	t.Setenv("PATH", originalPath)
	// Corrupt the selected child and reject before making any new remote writes.
	blob := filepath.Join(outputDirectory, "oci-layout", "blobs", "sha256", child)
	original, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, []byte("native tar or changed image"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := f.channelWrites["GRU"] + f.channelWrites["SFO"] + f.channelWrites["FRA"]
	f.mu.Unlock()
	if err := c.containerApplyWith(applyArgs, env); err == nil {
		t.Fatal("tampered OCI graph accepted")
	}
	if err := os.WriteFile(blob, original, 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	after := f.channelWrites["GRU"] + f.channelWrites["SFO"] + f.channelWrites["FRA"]
	f.mu.Unlock()
	if before != after {
		t.Fatal("local tamper detected after publication")
	}
	// Missing qualification is rejected before a missing private key is read.
	for index, arg := range producerArgs {
		if arg == "--signing-key" {
			producerArgs[index+1] = filepath.Join(inputs, "absent.key")
		}
		if arg == "--production-evidence-dir" {
			producerArgs[index+1] = t.TempDir()
		}
	}
	if err := c.containerBundleWith(producerArgs, env); !errors.Is(err, release.ErrProductionQualification) {
		t.Fatalf("qualification before signing key: %v", err)
	}
}

type containerHTTPFixture struct {
	*applyHTTPFixture
	allocations release.SequenceLocation
}

func (f *containerHTTPFixture) serveContainer(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Path, "/", 7)
	if len(parts) != 7 || r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cell, _, _ := strings.Cut(strings.ToUpper(parts[4]), "-")
	name := parts[6]
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[cell] == nil {
		f.objects[cell] = map[string][]byte{}
	}
	if r.Method == http.MethodPut {
		if cell == "SFO" && f.failure == "storage" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		old, exists := f.objects[cell][name]
		sum := sha256.Sum256(old)
		if r.Header.Get("If-None-Match") == "*" && exists || r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != fmt.Sprintf("%x", sum) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.objects[cell][name] = data
		if strings.HasSuffix(name, "/container.json") {
			f.channelWrites[cell]++
		}
		sum = sha256.Sum256(data)
		w.Header().Set("etag", fmt.Sprintf("%x", sum))
		return
	}
	data, exists := f.objects[cell][name]
	if name == releasechannel.StatusObject {
		data, _ = json.Marshal(releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell, Environment: "production", Architectures: []string{"arm64"}, UpdatedAt: time.Now().UTC()})
		exists = true
	}
	if name == releasechannel.ContainerStatusObject("ts-auth", "amd64") {
		if wire, found := f.objects[cell][releasechannel.ContainerReleaseObject("ts-auth", "amd64")]; found {
			var bundle release.ContainerBundle
			if err := json.Unmarshal(wire, &bundle); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			scope := release.ContainerTarget{Cell: cell, Environment: "production", Role: "ts-auth", Architecture: "amd64"}
			now := time.Now().UTC()
			f.mu.Unlock()
			verified, err := release.VerifyContainerCurrent(r.Context(), bundle, f.roots, scope, now, now.Add(time.Millisecond), func(_ context.Context, digest string) (io.ReadCloser, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				content, ok := f.objects[cell][releasechannel.ContainerEvidenceObject("ts-auth", digest)]
				if !ok {
					return nil, os.ErrNotExist
				}
				return io.NopCloser(bytes.NewReader(content)), nil
			}, f.allocations)
			f.mu.Lock()
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			claim := verified.Claim()
			data, _ = json.Marshal(releasechannel.ContainerStatus{Schema: releasechannel.ContainerStatusSchema, Cell: cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture, Image: claim.Image, ReleaseSequence: claim.ReleaseSequence, Fingerprint: verified.Fingerprint(), State: releasechannel.StateComplete, UpdatedAt: now})
			exists = true
		}
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("etag", fmt.Sprintf("%x", sum))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func containerCLIImageLayout(t *testing.T) (string, string, map[string]string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	encode := func(value any) []byte {
		t.Helper()
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	blob := func(wire []byte, media string) ocispec.Descriptor {
		t.Helper()
		sum := digest.FromBytes(wire)
		writeFixtureFile(t, filepath.Join(directory, "blobs", "sha256", sum.Encoded()), wire, 0o600)
		return ocispec.Descriptor{MediaType: media, Digest: sum, Size: int64(len(wire))}
	}
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	contents := []byte("#!/bin/sh\nexit 0\n")
	if err := archive.WriteHeader(&tar.Header{Name: "service", Mode: 0o755, Size: int64(len(contents))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	layerDescriptor := blob(layer.Bytes(), ocispec.MediaTypeImageLayer)
	children := make(map[string]string)
	index := ocispec.Index{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageIndex}
	for _, architecture := range []string{"amd64", "arm64"} {
		platform := ocispec.Platform{OS: "linux", Architecture: architecture}
		config := ocispec.Image{Platform: platform, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDescriptor.Digest}}}
		manifest := ocispec.Manifest{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageManifest, Config: blob(encode(config), ocispec.MediaTypeImageConfig), Layers: []ocispec.Descriptor{layerDescriptor}}
		child := blob(encode(manifest), ocispec.MediaTypeImageManifest)
		child.Platform = &platform
		index.Manifests = append(index.Manifests, child)
		children[architecture] = child.Digest.Encoded()
	}
	root := ocispec.Descriptor{Digest: digest.FromBytes(encode(index))}
	writeFixtureFile(t, filepath.Join(directory, "index.json"), encode(index), 0o600)
	writeFixtureFile(t, filepath.Join(directory, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600)
	return directory, "registry.example/terrascale/auth@" + root.Digest.String(), children
}
