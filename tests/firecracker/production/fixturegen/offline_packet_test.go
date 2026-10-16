package fixturegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// OfflinePacketInput binds the local test-authority receipt to actual frozen
// build artifacts. OCI identifiers are simulator identities, not live assets.
type OfflinePacketInput struct {
	SourceRoot      string `json:"sourceRoot"`
	Binary          string `json:"binary"`
	BinarySHA256    string `json:"binarySha256"`
	SourceRevision  string `json:"sourceRevision"`
	BaseImage       string `json:"baseImage"`
	BaseSHA256      string `json:"baseSha256"`
	Image           string `json:"image"`
	ImageSHA256     string `json:"imageSha256"`
	Kernel          string `json:"kernel"`
	KernelSHA256    string `json:"kernelSha256"`
	ServiceUID      uint32 `json:"serviceUid"`
	ServiceGID      uint32 `json:"serviceGid"`
	Packet          string `json:"packet"`
	RootCertificate string `json:"rootCertificate"`
}

func pinnedFile(t *testing.T, name, expected string) int64 {
	t.Helper()
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("input %q is not regular: %v", name, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		t.Fatalf("input %q differs from frozen SHA-256", name)
	}
	return info.Size()
}

func validateProductionBuildInfo(info *debug.BuildInfo, sourceRevision string) error {
	if info == nil {
		return errors.New("production executable has no Go build information")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if info.GoVersion != release.DefaultGoVersion || settings["vcs.revision"] != sourceRevision ||
		settings["vcs.modified"] != "false" || settings["GOOS"] != "linux" ||
		settings["GOARCH"] != "amd64" || settings["CGO_ENABLED"] != "0" {
		return errors.New("production executable build provenance differs from frozen receipt input")
	}
	return nil
}

func TestOfflineIssuerRejectsChangedBuildIdentity(t *testing.T) {
	info, err := buildinfo.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	info.GoVersion = release.DefaultGoVersion
	info.Settings = []debug.BuildSetting{{Key: "vcs.revision", Value: "a"},
		{Key: "vcs.modified", Value: "false"}, {Key: "GOOS", Value: "linux"},
		{Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"}}
	if err := validateProductionBuildInfo(info, "a"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ key, value string }{
		{"vcs.revision", "b"}, {"vcs.modified", "true"}, {"CGO_ENABLED", "1"},
	} {
		mutated := *info
		mutated.Settings = append([]debug.BuildSetting(nil), info.Settings...)
		for index := range mutated.Settings {
			if mutated.Settings[index].Key == change.key {
				mutated.Settings[index].Value = change.value
			}
		}
		if err := validateProductionBuildInfo(&mutated, "a"); err == nil {
			t.Fatalf("accepted changed build setting %s=%s", change.key, change.value)
		}
	}
}

// TestEmitOfflineProductionPacket is an opt-in local packet issuer. No packet
// or signer is created by the normal test suite.
func TestEmitOfflineProductionPacket(t *testing.T) {
	// TS_PRODUCTION_PACKET_INPUT names the frozen offline packet input JSON.
	inputPath := tier.Qualification(t, "TS_PRODUCTION_PACKET_INPUT")[0]
	wire, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input OfflinePacketInput
	if err := json.Unmarshal(wire, &input, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	binarySize := pinnedFile(t, input.Binary, input.BinarySHA256)
	baseSize := pinnedFile(t, input.BaseImage, input.BaseSHA256)
	imageSize := pinnedFile(t, input.Image, input.ImageSHA256)
	pinnedFile(t, input.Kernel, input.KernelSHA256)
	if binarySize == 0 || baseSize == 0 || imageSize == 0 || input.ServiceUID == 0 || input.ServiceGID == 0 {
		t.Fatal("offline image, binary, or service ownership is absent")
	}
	info, err := buildinfo.ReadFile(input.Binary)
	if err != nil || info == nil {
		t.Fatalf("read production executable build information: %v", err)
	}
	if err := validateProductionBuildInfo(info, input.SourceRevision); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(input.Binary)
	if err != nil {
		t.Fatal(err)
	}
	// A matching artifact SHA-256 is required before the receipt is signed.
	if int64(len(binary)) != binarySize {
		t.Fatal("binary changed between pinning and receipt construction")
	}
	now := time.Now().UTC().Truncate(time.Second)
	qualificationDigest := sha256.Sum256([]byte("offline qualification fixture"))
	receipt := release.ImageReceipt{Schema: release.ImageSchema,
		SourceRevision: input.SourceRevision, GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: binarySize, BinarySHA256: input.BinarySHA256,
		QualificationSHA256: hex.EncodeToString(qualificationDigest[:]),
		BaseImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.offline-base-fixture",
		BaseImageRegion:     "GRU", BaseImageSHA256: input.BaseSHA256,
		KernelRelease: "6.1.186", KernelSHA256: input.KernelSHA256,
		ImageFormat: "qcow2", ImageBytes: imageSize, ImageSHA256: input.ImageSHA256,
		OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.offline-production-restart",
		OCIRegion:    "GRU"}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	inputs := productionGuestTestInputs(t, now, binary)
	inputs.ServiceUID, inputs.ServiceGID = input.ServiceUID, input.ServiceGID
	recipe := signedHistoryRecipeWithMaterialsAndReceipt(t, now, binary, inputs.Credentials, &receipt)
	capture, err := NewCapturingObjectStorage(now)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := CurrentCompletedSourcePins(input.SourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	anchor := recipe.Anchor.Anchor()
	manifest := Manifest{SchemaVersion: ManifestVersion, DeploymentID: anchor.DeploymentID,
		Cell: string(anchor.Cell), Environment: anchor.Environment, FixtureNow: now,
		Binary: BinaryInput{Path: "input/orchestrator", GuestPath: "/usr/local/bin/terrascale-orchestrator",
			Architecture: "amd64"}, SourcePins: pins}
	for _, slot := range anchor.ControllerSlots {
		manifest.Controllers = append(manifest.Controllers, Controller{Slot: slot,
			InstanceOCID: recipe.Observed[slot].InstanceOCID,
			GuestRoot:    "controllers/" + slot + "/guest-root"})
	}
	compute, err := BuildComputeInventory(recipe, inputs)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Routes = compute.Routes
	packet, _, err := EmitCompletedRestartPacket(t.Context(), input.Packet, input.SourceRoot,
		manifest, func(ctx context.Context, completed CompletedHistories) (map[string][]byte, error) {
			material, err := BuildVerifiedGuestMaterial(ctx, recipe, completed, inputs)
			if err != nil {
				return nil, err
			}
			for name, body := range compute.Bodies {
				material[name] = bytes.Clone(body)
			}
			return material, nil
		}, recipe.Anchor, capture, recipe.Prepare, recipe.RootPrivateKey, recipe.Roots, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(recipe.RootPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(input.RootCertificate), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(input.RootCertificate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(root); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("offline packet %s; root %s; image %s", input.Packet, input.RootCertificate,
		packet.Manifest().Binary.SHA256)
}
