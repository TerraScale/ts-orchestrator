// Package bootstrapstart composes local, pre-NATS controller admission checks.
package bootstrapstart

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const (
	MarkerDirectory = "/var/lib/terrascale-orchestrator-bootstrap"
	markerName      = "accepted-install.json"
	maxMarkerBytes  = 16 << 10
)

var (
	ErrInvalidMarker = errors.New("accepted bootstrap install marker is invalid")
	markerDigestRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	markerNameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// AcceptedInstall records the exact checked inputs of one completed install.
// Filesystem ownership is its integrity boundary; this record is not a new
// signing authority and does not grant current cloud or Vault permissions.
type AcceptedInstall struct {
	SchemaVersion      int                              `json:"schemaVersion"`
	AnchorSHA256       string                           `json:"anchorSha256"`
	ManifestSHA256     string                           `json:"manifestSha256"`
	ReceiptSHA256      string                           `json:"receiptSha256"`
	ImageReceiptSHA256 string                           `json:"imageReceiptSha256"`
	DeploymentID       string                           `json:"deploymentId"`
	Cell               string                           `json:"cell"`
	Slot               string                           `json:"slot"`
	SeedSlot           string                           `json:"seedSlot"`
	ImageOCID          string                           `json:"imageOcid"`
	InstanceOCID       string                           `json:"instanceOcid"`
	PrimaryVNICOCID    string                           `json:"primaryVnicOcid"`
	PrimaryPrivateIP   string                           `json:"primaryPrivateIp"`
	HeadAttempt        uint64                           `json:"headAttempt"`
	HeadGeneration     uint64                           `json:"headGeneration"`
	ResultSHA256       string                           `json:"resultSha256"`
	BinarySHA256       string                           `json:"binarySha256"`
	MaterialSHA256     map[string]string                `json:"materialSha256"`
	ManagedMaterial    *bootstrap.ManagedMaterialDomain `json:"managedMaterial,omitempty"`
	AcceptedAt         time.Time                        `json:"acceptedAt"`
}

func (marker AcceptedInstall) validate() error {
	if marker.SchemaVersion != 1 || marker.HeadAttempt == 0 || marker.HeadGeneration == 0 ||
		!markerDigestRE.MatchString(marker.AnchorSHA256) || !markerDigestRE.MatchString(marker.ManifestSHA256) ||
		!markerDigestRE.MatchString(marker.ReceiptSHA256) || !markerDigestRE.MatchString(marker.ImageReceiptSHA256) ||
		!markerDigestRE.MatchString(marker.ResultSHA256) || !markerDigestRE.MatchString(marker.BinarySHA256) ||
		marker.DeploymentID == "" || marker.Cell == "" || !descriptorSlotRE.MatchString(marker.Slot) ||
		!descriptorSlotRE.MatchString(marker.SeedSlot) ||
		!strings.HasPrefix(marker.ImageOCID, "ocid1.image.") || !strings.HasPrefix(marker.InstanceOCID, "ocid1.instance.") ||
		!strings.HasPrefix(marker.PrimaryVNICOCID, "ocid1.vnic.") || !validPrivateIPv4(marker.PrimaryPrivateIP) ||
		len(marker.MaterialSHA256) == 0 || len(marker.MaterialSHA256) > 64 ||
		marker.AcceptedAt.IsZero() || marker.AcceptedAt.Location() != time.UTC {
		return ErrInvalidMarker
	}
	for name, digest := range marker.MaterialSHA256 {
		if !markerNameRE.MatchString(name) || !markerDigestRE.MatchString(digest) {
			return ErrInvalidMarker
		}
	}
	if marker.ManagedMaterial != nil && marker.ManagedMaterial.Validate() != nil {
		return ErrInvalidMarker
	}
	return nil
}

func validPrivateIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.IsGlobalUnicast() && address.String() == value
}

// MarkerStore opens the fixed root-owned marker directory without following
// symlinks. The marker contains only public proofs and digests, so its 0644
// mode lets the unprivileged controller verify root-owned integrity directly.
// Production uses NewMarkerStore; tests inject their own owner ID.
type MarkerStore struct {
	directory            string
	ownerUID             uint32
	allowUnsafeAncestors bool
}

func NewMarkerStore() MarkerStore {
	return MarkerStore{directory: MarkerDirectory, ownerUID: 0}
}

// Read returns a canonical, root-owned accepted-install marker. A missing or
// invalid marker always fails closed; first-install admission decides whether
// the missing case is eligible for current-proof bootstrap.
func (store MarkerStore) Read() (AcceptedInstall, error) {
	dir, err := store.openDirectory()
	if err != nil {
		return AcceptedInstall{}, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, markerName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("open accepted-install marker: %w", err)
	}
	file := os.NewFile(uintptr(fd), markerName)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != store.ownerUID || stat.Gid != 0 && store.ownerUID == 0 ||
		stat.Mode&0o777 != 0o644 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxMarkerBytes {
		return AcceptedInstall{}, ErrInvalidMarker
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMarkerBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxMarkerBytes {
		return AcceptedInstall{}, ErrInvalidMarker
	}
	var marker AcceptedInstall
	if err := protocol.DecodeStrict(data, &marker, maxMarkerBytes); err != nil || marker.validate() != nil {
		return AcceptedInstall{}, ErrInvalidMarker
	}
	canonical, err := protocol.EncodeJSON(marker)
	if err != nil || !bytes.Equal(data, canonical) {
		return AcceptedInstall{}, ErrInvalidMarker
	}
	return marker, nil
}

// WriteNew atomically installs a new marker after the caller has completed all
// current-proof and material checks. It never replaces an accepted marker.
func (store MarkerStore) WriteNew(marker AcceptedInstall) error {
	if err := marker.validate(); err != nil {
		return err
	}
	data, err := protocol.EncodeJSON(marker)
	if err != nil || len(data) > maxMarkerBytes {
		return ErrInvalidMarker
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".accepted-install." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("create temporary accepted-install marker: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(dir, temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if err := unix.Fchmod(fd, 0o644); err != nil {
		_ = file.Close()
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != store.ownerUID ||
		stat.Gid != 0 && store.ownerUID == 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		_ = file.Close()
		return ErrInvalidMarker
	}
	if written, err := file.Write(data); err != nil || written != len(data) {
		_ = file.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, temporary, dir, markerName, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("install accepted-install marker without replacement: %w", err)
	}
	removeTemporary = false
	if err := unix.Fsync(dir); err != nil {
		return fmt.Errorf("sync accepted-install marker directory: %w", err)
	}
	return nil
}

func (store MarkerStore) openDirectory() (int, error) {
	if !filepath.IsAbs(store.directory) || filepath.Clean(store.directory) != store.directory {
		return -1, ErrInvalidMarker
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(store.directory, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return -1, ErrInvalidMarker
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("open accepted-install directory component: %w", openErr)
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil ||
			!store.allowUnsafeAncestors && (stat.Uid != 0 || stat.Mode&0o022 != 0) {
			unix.Close(fd)
			return -1, ErrInvalidMarker
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != store.ownerUID ||
		stat.Gid != 0 && store.ownerUID == 0 || stat.Mode&0o777 != 0o755 {
		unix.Close(fd)
		return -1, ErrInvalidMarker
	}
	return fd, nil
}
