package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// testHostImage signs a release image receipt for imageID with a release
// leaf under the root's image delegation, valid from issuedAt for lifetime.
func testHostImage(t *testing.T, keys testSpecTrust, imageID string, issuedAt time.Time, lifetime time.Duration) cellspec.HostImage {
	t.Helper()
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	public, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	revision := "0123456789abcdef0123456789abcdef01234567"
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
		SubjectPublicKey: public, Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: revision,
			Cell: "GRU", Environment: keys.identity.Environment, Role: "oci-image", Slots: []string{imageID},
			Actions: []string{"sign"}}},
	}, issuedAt.Add(-time.Minute), issuedAt.Add(lifetime), keys.root)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("cd", 32)
	receipt, err := release.SignImageReceipt(release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: revision, GoVersion: release.DefaultGoVersion,
		Architecture: "arm64", BinaryBytes: 100, BinarySHA256: digest, QualificationSHA256: digest,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: digest,
		KernelRelease: "6.1.0-test+1", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: digest, OCIImageOCID: imageID, OCIRegion: "GRU",
	}, keys.identity.Environment, delegation, keys.roots, leafPrivate, issuedAt, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(receipt)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return cellspec.HostImage{ImageID: imageID, Receipt: receiptWire, Delegation: delegationWire}
}

// The leader admits a host image only when a root signs the amendment and
// the image's receipt is currently valid; revoking one is ordinary. Images
// a replaced root qualified stay allowed through a root rotation.
func TestSpecRegistryAdmitsOnlyCurrentlyQualifiedHostImages(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"})
	registry, err := newSpecRegistry(Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{SpecTrust: keys.config()}}, "member")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	fence := rolloutTestFence{epoch: 3}
	apply := func(path string) (specReply, error) {
		return registry.apply(t.Context(), mustRead(t, path), "", fence.epoch, fence, nil)
	}
	now := time.Now().UTC().Truncate(time.Second)
	earlier := testHostImage(t, keys, "ocid1.image.oc1.sa-saopaulo-1.earlier", now, time.Hour)
	expired := testHostImage(t, keys, "ocid1.image.oc1.sa-saopaulo-1.expired", now.Add(-2*time.Hour), time.Hour)

	first := cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: 1, RequiresBinary: 9,
		HostImages: []cellspec.HostImage{earlier}, LaunchImage: earlier.ImageID}
	if _, err := apply(keys.sign(t, dir, first)); err == nil || !strings.Contains(err.Error(), "a root must sign it") {
		t.Fatalf("leaf-signed host image: %v", err)
	}
	if reply, err := apply(keys.signRoot(t, dir, first)); err != nil || reply.Status != "applied" {
		t.Fatalf("apply qualified host image: %+v, %v", reply, err)
	}
	if snapshot := registry.hostImageSnapshot(); len(snapshot.images) != 1 || snapshot.launch != earlier.ImageID ||
		!slices.Equal(registry.hostImages(), []string{earlier.ImageID}) || !slices.Equal(slices.Sorted(maps.Keys(snapshot.roots)), slices.Sorted(maps.Keys(keys.roots))) {
		t.Fatalf("hostImageSnapshot = %+v", snapshot)
	}

	second := first
	second.Generation = 2
	second.HostImages = []cellspec.HostImage{earlier, expired}
	payload, err := cellspec.Encode(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.diff(t.Context(), payload); err == nil || !strings.Contains(err.Error(), "not qualified") {
		t.Fatalf("diff of an expired added image: %v", err)
	}
	// The expired receipt was validly signed; only the current check refuses it.
	if _, err := apply(keys.signRoot(t, dir, second)); err == nil || !strings.Contains(err.Error(), "not qualified") {
		t.Fatalf("apply of an expired added image: %v", err)
	}
	if images := registry.hostImages(); !slices.Equal(images, []string{earlier.ImageID}) {
		t.Fatalf("hostImages after refusal = %v", images)
	}

	// Rotate the root that qualified the image away. The next generation,
	// signed by the new root, keeps the image without a new receipt.
	next := newRootKey(t)
	rotation, err := trust.EncodeRootChain(trust.RootChain{Rotations: []trust.SignedRotation{
		signTestRotation(t, trust.ChainIdentity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"},
			registry.roots.verified, rootKeys(next), keys.root, next)}})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := trust.DecodeRootChain(rotation)
	if err != nil {
		t.Fatal(err)
	}
	before := registry.hostImageSnapshot().version
	if err := registry.roots.adopt(chain); err != nil {
		t.Fatal(err)
	}
	// A launch chosen before the rotation cannot run after it.
	rotatedVersion := registry.hostImageSnapshot().version
	if rotatedVersion == before {
		t.Fatalf("snapshot version %q survived a root rotation", rotatedVersion)
	}
	rotated := keys
	rotated.root = next
	if rotated.roots, err = trust.ParseKeyring(next.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	kept := first
	kept.Generation = 2
	keptWire := mustRead(t, rotated.signRoot(t, dir, kept))
	if reply, err := registry.apply(t.Context(), keptWire, "", fence.epoch, fence, nil); err != nil || reply.Status != "applied" {
		t.Fatalf("keep a host image through a root rotation: %+v, %v", reply, err)
	}
	if registry.hostImageSnapshot().version == rotatedVersion {
		t.Fatal("snapshot version survived a new spec generation")
	}
	if _, err := registry.verify(keptWire, nil); err != nil {
		t.Fatalf("reload a host image through a root rotation: %v", err)
	}

	// Revoking an image is ordinary: the release leaf may sign it.
	revoked := kept
	revoked.Generation = 3
	revoked.HostImages, revoked.LaunchImage = nil, ""
	revoked.RequiresBinary = 1
	leaf := newTestSpecTrustWithRoot(t, dir, keys.identity, next)
	if reply, err := apply(leaf.sign(t, dir, revoked)); err != nil || reply.Status != "applied" || len(registry.hostImages()) != 0 {
		t.Fatalf("revoke host image: %+v, %v", reply, err)
	}
}

// allow-image needs the receipt and delegation, revoke-image neither; both
// refuse before contacting the cell, as does a receipt file that is not a
// canonical envelope, which a spec could not hold byte for byte.
func TestServiceHostImageArguments(t *testing.T) {
	dir := t.TempDir()
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"})
	image := testHostImage(t, keys, "ocid1.image.oc1.sa-saopaulo-1.earlier", time.Now(), time.Hour)
	receipt, reformatted := filepath.Join(dir, "receipt.json"), filepath.Join(dir, "reformatted.json")
	if err := os.WriteFile(receipt, image.Receipt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reformatted, append(bytes.Clone(image.Receipt), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"allow without receipt":    {"allow", image.ImageID, "", ""},
		"allow without image ID":   {"allow", "", receipt, receipt},
		"allow without delegation": {"allow", image.ImageID, receipt, ""},
		"revoke with a receipt":    {"revoke", image.ImageID, receipt, receipt},
		"reformatted receipt":      {"allow", image.ImageID, reformatted, receipt},
	} {
		err := operatorServiceHostImage(t.Context(), Config{}, nil, args[0] == "allow", false,
			args[1], args[2], args[3], "", io.Discard)
		if err == nil || !strings.Contains(err.Error(), "requires --image-id") && !strings.Contains(err.Error(), "not canonical") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if data, err := readCanonicalEnvelope(receipt); err != nil || !bytes.Equal(data, image.Receipt) {
		t.Fatalf("readCanonicalEnvelope = %q, %v", data, err)
	}
}

// A launch holds the spec registry's fence from its final image check
// through the provider launch: adopting a spec or a root rotation waits.
func TestSpecRegistryAdoptionWaitsForLaunches(t *testing.T) {
	dir := t.TempDir()
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"})
	registry, err := newSpecRegistry(Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{SpecTrust: keys.config()}}, "member")
	if err != nil {
		t.Fatal(err)
	}
	if registry.roots.fence != &registry.launches {
		t.Fatal("root rotations do not take the launch fence")
	}
	release := registry.holdLaunch()
	adopted := make(chan struct{})
	go func() {
		registry.adopt(cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: 1, RequiresBinary: 1}, 1)
		close(adopted)
	}()
	select {
	case <-adopted:
		t.Fatal("a spec was adopted during a launch")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-adopted:
	case <-time.After(5 * time.Second):
		t.Fatal("the spec was not adopted after the launch")
	}
	if registry.hostImageSnapshot().version == "0/" || !strings.HasPrefix(registry.hostImageSnapshot().version, "1/") {
		t.Fatalf("snapshot version after adoption = %q", registry.hostImageSnapshot().version)
	}
}
