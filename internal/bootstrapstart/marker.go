// Package bootstrapstart composes local, pre-NATS controller admission checks.
package bootstrapstart

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"golang.org/x/sys/unix"
)

const (
	MarkerDirectory      = "/var/lib/terrascale-orchestrator-bootstrap"
	markerName           = "accepted-install.json"
	initialFormationName = "initial-formation.json"
	maxMarkerBytes       = 16 << 10
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
