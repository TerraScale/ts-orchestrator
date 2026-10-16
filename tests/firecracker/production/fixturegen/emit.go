package fixturegen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// EmitPacket writes an immutable, signed packet to a new directory. Inputs
// are named relative files; no material is taken from a live guest or cloud.
// The binary digest and every file entry are derived from the supplied bytes.
func EmitPacket(destination, sourceRoot string, manifest Manifest, material map[string][]byte,
	rootPrivateKey ed25519.PrivateKey, roots trust.Keyring, expiresAt time.Time,
) (VerifiedPacket, error) {
	if len(material) == 0 || len(material) > 2048 || manifest.FixtureNow.IsZero() ||
		!expiresAt.After(manifest.FixtureNow) || len(rootPrivateKey) != ed25519.PrivateKeySize {
		return VerifiedPacket{}, errors.New("invalid packet emission inputs")
	}
	if err := VerifySourcePins(sourceRoot, manifest.SourcePins); err != nil {
		return VerifiedPacket{}, fmt.Errorf("packet source binding: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil || !errors.Is(err, os.ErrNotExist) {
		return VerifiedPacket{}, errors.New("packet destination must not exist")
	}
	controllers := make(map[string]string, len(manifest.Controllers))
	for _, controller := range manifest.Controllers {
		controllers[controller.Slot] = controller.InstanceOCID
	}
	manifest.Files = nil
	for name, body := range material {
		if !canonicalPath(name) {
			return VerifiedPacket{}, fmt.Errorf("invalid packet material path %q", name)
		}
		role, mode := expectedOwnership(name, controllers)
		if role == "" {
			return VerifiedPacket{}, fmt.Errorf("packet material path is outside allowed roots: %q", name)
		}
		if (strings.HasPrefix(name, "controllers/") || name == "input/orchestrator") && containsRootPrivateKey(body, rootPrivateKey) {
			return VerifiedPacket{}, fmt.Errorf("offline root signing key appears in guest material %q", name)
		}
		digest := sha256.Sum256(body)
		manifest.Files = append(manifest.Files, FileEntry{Path: name, SHA256: hex.EncodeToString(digest[:]),
			Size: int64(len(body)), Mode: mode, OwnerRole: role})
	}
	slices.SortFunc(manifest.Files, func(a, b FileEntry) int { return strings.Compare(a.Path, b.Path) })
	binary, ok := material["input/orchestrator"]
	if !ok {
		return VerifiedPacket{}, errors.New("packet lacks exact orchestrator binary")
	}
	binaryDigest := sha256.Sum256(binary)
	manifest.Binary.Path = "input/orchestrator"
	manifest.Binary.SHA256 = hex.EncodeToString(binaryDigest[:])
	manifest.Binary.Size = int64(len(binary))
	if err := manifest.Validate(); err != nil {
		return VerifiedPacket{}, err
	}
	wire, err := trust.EncodePayload(manifest)
	if err != nil {
		return VerifiedPacket{}, err
	}
	envelope, err := trust.Sign(wire, manifest.scope(), manifest.FixtureNow.Add(-time.Minute), expiresAt, rootPrivateKey)
	if err != nil {
		return VerifiedPacket{}, err
	}
	signature, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return VerifiedPacket{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return VerifiedPacket{}, err
	}
	staging, err := os.MkdirTemp(parent, ".production-packet-")
	if err != nil {
		return VerifiedPacket{}, err
	}
	defer os.RemoveAll(staging)
	for _, entry := range manifest.Files {
		name := filepath.Join(staging, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return VerifiedPacket{}, err
		}
		if err := os.WriteFile(name, material[entry.Path], os.FileMode(entry.Mode)); err != nil {
			return VerifiedPacket{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), wire, 0o600); err != nil {
		return VerifiedPacket{}, err
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.sig"), signature, 0o600); err != nil {
		return VerifiedPacket{}, err
	}
	if _, err := ValidatePacket(staging, roots, time.Now().UTC()); err != nil {
		return VerifiedPacket{}, fmt.Errorf("emitted packet failed self-verification: %w", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		return VerifiedPacket{}, err
	}
	return ValidatePacket(destination, roots, time.Now().UTC())
}

func containsRootPrivateKey(body []byte, rootPrivateKey ed25519.PrivateKey) bool {
	seed := rootPrivateKey.Seed()
	if bytes.Contains(body, rootPrivateKey) || bytes.Contains(body, seed) ||
		bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(rootPrivateKey))) ||
		bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(seed))) ||
		bytes.Contains(body, []byte(hex.EncodeToString(rootPrivateKey))) ||
		bytes.Contains(body, []byte(hex.EncodeToString(seed))) {
		return true
	}
	der, err := x509.MarshalPKCS8PrivateKey(rootPrivateKey)
	if err != nil {
		return true
	}
	if bytes.Contains(body, der) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(der))) {
		return true
	}
	for rest := body; len(rest) > 0; {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = tail
		if block.Type != "PRIVATE KEY" {
			continue
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if key, ok := parsed.(ed25519.PrivateKey); err == nil && ok && bytes.Equal(key, rootPrivateKey) {
			return true
		}
	}
	return false
}
