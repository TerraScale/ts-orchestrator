package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const controllerSeedManifestFilename = "controller-seed-manifest.json"

func runInstallControllerConfig(ctx context.Context, args []string) error {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("install-controller-config requires root and accepts no arguments")
	}
	if _, err := bootstrapstart.NewMarkerStore().Read(); err == nil {
		// Restart admission checks the historical ledger and loaded config.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect accepted controller install: %w", err)
	}
	if err := controllerClockCheck(controllerBrokerClockProbe())(); err != nil {
		return fmt.Errorf("controller install NTP clock health: %w", err)
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return err
	}
	now := time.Now().Round(0).UTC()
	anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, baked.Roots,
		baked.Identity.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return fmt.Errorf("verify current baked anchor: %w", err)
	}
	observer, _, _, err := bootstrapstart.NewCurrentOCIAdmissionClients(anchor, baked.Roots)
	if err != nil {
		return err
	}
	imds := bootstrapstart.NewIMDSClient()
	descriptor, err := imds.FetchDescriptor(ctx)
	if err != nil {
		return err
	}
	wire, metadataErr := imds.FetchControllerManifest(ctx)
	if metadataErr != nil {
		if len(anchor.Anchor().ControllerSlots) == 0 || descriptor.Slot != anchor.Anchor().ControllerSlots[0] {
			return fmt.Errorf("managed peer has no signed manifest metadata: %w", metadataErr)
		}
		wire, err = readInstalledControllerFile(controllerConfigDirectory,
			controllerSeedManifestFilename, 0, 0, 0o644, bootstrapstart.MaxControllerManifestMetadataBytes)
		if err != nil {
			return fmt.Errorf("read reviewed seed manifest: %w", err)
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return err
		}
		seedManifest, err := bootstrap.ManifestPayload(envelope.Payload)
		if err != nil || seedManifest.SeedSlot != descriptor.Slot {
			return errors.New("reviewed seed manifest does not authorize the first controller")
		}
	}
	manifest, observed, err := bootstrapstart.VerifyControllerConfigInstall(ctx, baked, wire, imds, observer, now)
	if err != nil {
		return err
	}
	if _, err := ValidateSignedControllerConfig(manifest, observed.PrimaryPrivateIP); err != nil {
		return err
	}
	_, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	return installSignedControllerFiles(controllerConfigDirectory, wire, manifest, gid)
}

// installSignedControllerFiles installs the manifest and sidecars before the
// config that enables bootstrap. Existing files must match byte for byte, so a
// crash or retry cannot quietly replace a partially installed role.
func installSignedControllerFiles(directory string, wire []byte, manifest bootstrap.Manifest, serviceGID uint32) error {
	dir, err := openControllerConfigDirectory(directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := installExactControllerFile(dir, controllerManifestFilename, wire, 0, 0, 0o644); err != nil {
		return err
	}
	for _, file := range manifest.ControllerFiles {
		uid, gid, mode := uint32(0), uint32(0), uint32(0o644)
		if file.Name == "oci-region-intent.json" {
			uid, gid, mode = 0, serviceGID, 0o440
		}
		if err := installExactControllerFile(dir, file.Name, file.Bytes, uid, gid, mode); err != nil {
			return err
		}
	}
	return installExactControllerFile(dir, controllerConfigFilename, manifest.ControllerConfig, 0, 0, 0o644)
}

func openControllerConfigDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("controller config directory must be absolute and clean")
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(dir)
			return -1, errors.New("invalid controller config directory")
		}
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return -1, err
		}
		dir = next
		var ancestor unix.Stat_t
		if err := unix.Fstat(dir, &ancestor); err != nil || ancestor.Uid != 0 || ancestor.Gid != 0 ||
			ancestor.Mode&0o777 != 0o755 {
			unix.Close(dir)
			return -1, errors.New("controller config path ancestor ownership or mode is invalid")
		}
	}
	return dir, nil
}

func readInstalledControllerFile(directory, name string, uid, gid, mode uint32, maximum int) ([]byte, error) {
	dir, err := openControllerConfigDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	return readExactControllerFile(dir, name, uid, gid, mode, maximum)
}

func readExactControllerFile(dir int, name string, uid, gid, mode uint32, maximum int) ([]byte, error) {
	if name == "" || name != filepath.Base(name) || maximum <= 0 {
		return nil, errors.New("invalid controller config file name or bound")
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != mode ||
		stat.Size <= 0 || stat.Size > int64(maximum) {
		return nil, errors.New("controller config file ownership, mode, or size is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		return nil, errors.New("controller config file exceeds bound")
	}
	return data, nil
}

func installExactControllerFile(dir int, name string, wire []byte, uid, gid, mode uint32) error {
	if len(wire) == 0 || name == "" || name != filepath.Base(name) {
		return errors.New("invalid signed controller file")
	}
	existing, err := readExactControllerFile(dir, name, uid, gid, mode, len(wire))
	if err == nil {
		if bytes.Equal(existing, wire) {
			return nil
		}
		return fmt.Errorf("existing controller file %s differs from signed bytes", name)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing controller file %s: %w", name, err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		file.Close()
		return err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		file.Close()
		return err
	}
	if count, err := file.Write(wire); err != nil || count != len(wire) {
		file.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("install signed controller file %s: %w", name, err)
	}
	return unix.Fsync(dir)
}
