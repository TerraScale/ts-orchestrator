package vmimage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	PreparationReceiptSchemaVersion = 1
	maxPreparationReceiptBytes      = 16 << 10
)

// RootFSInspection is bounded evidence returned by the typed filesystem
// preparation boundary. It contains no command transcript or host path.
type RootFSInspection struct {
	OSID            string
	OSVersionID     string
	OSVersion       string
	SanitizedMounts []string
	FilesystemCheck string
}

// PreparationReceipt binds filesystem inspection to a pinned manifest and
// final rootfs digest. Runtime PID 1 readiness is intentionally absent: only a
// booted guest can provide that evidence.
type PreparationReceipt struct {
	SchemaVersion   int          `json:"schemaVersion"`
	ManifestDigest  string       `json:"manifestDigest"`
	Architecture    Architecture `json:"architecture"`
	UbuntuRelease   string       `json:"ubuntuRelease"`
	OSID            string       `json:"osId"`
	OSVersionID     string       `json:"osVersionId"`
	OSVersion       string       `json:"osVersion"`
	RootFSSHA256    string       `json:"rootfsSha256"`
	SanitizedMounts []string     `json:"sanitizedMounts"`
	FilesystemCheck string       `json:"filesystemCheck"`
}

func NewPreparationReceipt(manifest GuestImageManifest, inspection RootFSInspection) (PreparationReceipt, error) {
	canonical, err := NewPinnedManifest(manifest)
	if err != nil {
		return PreparationReceipt{}, err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return PreparationReceipt{}, err
	}
	receipt := PreparationReceipt{
		SchemaVersion: PreparationReceiptSchemaVersion, ManifestDigest: digest,
		Architecture: canonical.Architecture, UbuntuRelease: canonical.UbuntuRelease,
		OSID: inspection.OSID, OSVersionID: inspection.OSVersionID, OSVersion: inspection.OSVersion,
		RootFSSHA256: canonical.RootFS.SHA256, SanitizedMounts: append([]string(nil), inspection.SanitizedMounts...),
		FilesystemCheck: inspection.FilesystemCheck,
	}
	if err := receipt.Validate(canonical); err != nil {
		return PreparationReceipt{}, err
	}
	return receipt, nil
}

func (receipt PreparationReceipt) Validate(manifest GuestImageManifest) error {
	canonical, err := NewPinnedManifest(manifest)
	if err != nil {
		return err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return err
	}
	if receipt.SchemaVersion != PreparationReceiptSchemaVersion || receipt.ManifestDigest != digest ||
		receipt.Architecture != canonical.Architecture || receipt.UbuntuRelease != canonical.UbuntuRelease ||
		receipt.RootFSSHA256 != canonical.RootFS.SHA256 {
		return errors.New("vmimage: preparation receipt does not match manifest")
	}
	identity := []byte("ID=" + receipt.OSID + "\nVERSION_ID=\"" + receipt.OSVersionID + "\"\nVERSION=\"" + receipt.OSVersion + "\"\n")
	if _, err := verifyUbuntuIdentity(identity, canonical.UbuntuRelease); err != nil {
		return err
	}
	if len(receipt.SanitizedMounts) != 2 || receipt.SanitizedMounts[0] != "/boot" || receipt.SanitizedMounts[1] != "/boot/efi" {
		return errors.New("vmimage: preparation receipt has incomplete sanitized mounts")
	}
	if receipt.FilesystemCheck != "e2fsck -fn" {
		return errors.New("vmimage: preparation receipt has an unsupported filesystem check")
	}
	for _, value := range []string{receipt.OSID, receipt.OSVersionID, receipt.OSVersion} {
		if value == "" || len(value) > 256 || strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
			return errors.New("vmimage: preparation receipt contains unsafe identity text")
		}
	}
	return nil
}

func (receipt PreparationReceipt) CanonicalJSON(manifest GuestImageManifest) ([]byte, error) {
	if err := receipt.Validate(manifest); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func DecodePreparationReceipt(data []byte, manifest GuestImageManifest) (PreparationReceipt, error) {
	if len(data) == 0 || len(data) > maxPreparationReceiptBytes {
		return PreparationReceipt{}, errors.New("vmimage: preparation receipt size is outside the permitted range")
	}
	if err := validateSeedJSONObjectDocument(data, preparationReceiptJSONSchema(), "preparation receipt"); err != nil {
		return PreparationReceipt{}, fmt.Errorf("vmimage: decode preparation receipt: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt PreparationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return PreparationReceipt{}, fmt.Errorf("vmimage: decode preparation receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return PreparationReceipt{}, errors.New("vmimage: preparation receipt contains trailing data")
	}
	if err := receipt.Validate(manifest); err != nil {
		return PreparationReceipt{}, err
	}
	return receipt, nil
}
