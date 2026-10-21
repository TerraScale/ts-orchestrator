package bootstrapstart

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"golang.org/x/sys/unix"
)

// LoadAcceptedOCIConfig reads only installed root-owned sidecars whose exact
// bytes the accepted installation pins. IPC callers cannot choose paths.
func LoadAcceptedOCIConfig() (AcceptedIdentity, oci.RegionIntent, oci.RegionConfig, error) {
	accepted, err := NewMarkerStore().ReadIdentity()
	if err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	if err := CheckIdentityRekeyPrestart(accepted); err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	if _, err := LoadTrustInputs(accepted); err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	intentWire, err := readAcceptedOCISidecar(accepted, "oci-region-intent.json")
	if err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	configWire, err := readAcceptedOCISidecar(accepted, "oci-region.json")
	if err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	intent, err := oci.ParseRegionIntent(intentWire)
	if err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	config, err := oci.ParseRegionConfig(configWire)
	if err != nil {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	if err := config.Validate(intent); err != nil || string(config.Region) != accepted.Cell {
		return AcceptedIdentity{}, oci.RegionIntent{}, oci.RegionConfig{}, errors.New("accepted OCI sidecars differ from local installation")
	}
	return accepted, intent, config, nil
}

func readAcceptedOCISidecar(accepted AcceptedIdentity, name string) ([]byte, error) {
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range []string{"etc", "terrascale-orchestrator"} {
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return nil, err
		}
		dir = next
		var stat unix.Stat_t
		if err := unix.Fstat(dir, &stat); err != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(dir)
			return nil, errors.New("accepted OCI directory is not exclusively root-writable")
		}
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o444 || stat.Size < 1 || stat.Size > bootstrap.MaxControllerSidecarBytes {
		return nil, errors.New("accepted OCI sidecar is not bounded immutable root-owned material")
	}
	wire, err := io.ReadAll(io.LimitReader(file, bootstrap.MaxControllerSidecarBytes+1))
	if err != nil || int64(len(wire)) != stat.Size {
		return nil, errors.New("accepted OCI sidecar read is incomplete")
	}
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != accepted.ConfigSHA256[name] {
		return nil, errors.New("accepted OCI sidecar digest differs from installed identity")
	}
	return wire, nil
}
