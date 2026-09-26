package fixturegen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyPacketImageReceipt verifies the production release delegation and
// signed image receipt against the packet's exact executable bytes, fixed
// guest destination, architecture, and independently pinned image OCID.
func VerifyPacketImageReceipt(packet VerifiedPacket, imageWire, delegationWire []byte,
	roots trust.Keyring, imageOCID string, runNow time.Time,
) (release.VerifiedImage, error) {
	binary, err := packet.Executable()
	if err != nil {
		return release.VerifiedImage{}, fmt.Errorf("read packet executable: %w", err)
	}
	if binary.GuestPath != "/usr/local/bin/terrascale-orchestrator" || binary.Mode != 0o755 ||
		imageOCID == "" || runNow.IsZero() {
		return release.VerifiedImage{}, errors.New("image verification lacks fixed binary destination, image identity, or clock")
	}
	image, err := release.VerifyImageCurrent(imageWire, delegationWire, roots,
		release.ImageExpectation{Environment: "production", LogicalRegion: "GRU",
			OCIImageOCID: imageOCID, Architecture: binary.Architecture}, runNow)
	if err != nil {
		return release.VerifiedImage{}, fmt.Errorf("verify current image receipt: %w", err)
	}
	receipt := image.Receipt()
	digest := sha256.Sum256(binary.Body)
	if receipt.BinaryBytes != int64(len(binary.Body)) || receipt.BinaryBytes != packet.manifest.Binary.Size ||
		receipt.BinarySHA256 != hex.EncodeToString(digest[:]) || receipt.BinarySHA256 != binary.SHA256 {
		return release.VerifiedImage{}, errors.New("signed image receipt does not bind exact packet executable")
	}
	return image, nil
}

// VerifyPacketEmbeddedImage reads the two fixed host-side release proof files
// from the validated packet and rechecks their signed file digests before
// trusting them. The runtime driver must use this proof and install the bytes
// returned by Executable at its fixed guest path.
func VerifyPacketEmbeddedImage(packet VerifiedPacket, roots trust.Keyring, imageOCID string,
	runNow time.Time,
) (release.VerifiedImage, error) {
	if packet.root == "" {
		return release.VerifiedImage{}, errors.New("packet was not verified")
	}
	read := func(name string) ([]byte, error) {
		var entry *FileEntry
		for index := range packet.manifest.Files {
			if packet.manifest.Files[index].Path == name {
				entry = &packet.manifest.Files[index]
				break
			}
		}
		if entry == nil {
			return nil, fmt.Errorf("packet lacks signed release proof %q", name)
		}
		full := filepath.Join(packet.root, filepath.FromSlash(name))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("packet release proof is nonregular: %q", name)
		}
		body, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(body)
		if int64(len(body)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return nil, fmt.Errorf("packet release proof changed: %q", name)
		}
		return body, nil
	}
	imageWire, err := read("simulator/release-image-receipt.json")
	if err != nil {
		return release.VerifiedImage{}, err
	}
	delegationWire, err := read("simulator/release-delegation.json")
	if err != nil {
		return release.VerifiedImage{}, err
	}
	return VerifyPacketImageReceipt(packet, imageWire, delegationWire, roots, imageOCID, runNow)
}
