package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// Deployment-specific public material arrives in OCI launch metadata. The
// image carries only the trust roots that authenticate it, so one qualified
// image serves every deployment and bootstrap attempt.
const (
	IdentityMetadataKey    = "terrascale-bootstrap-identity-v1"
	AnchorMetadataKey      = "terrascale-bootstrap-anchor-v1"
	HostEnrollmentFilename = "host-enrollment-public.json"
	identityFilename       = "identity.json"
	anchorFilename         = "anchor.json"
)

var ErrLaunchMaterial = errors.New("launch bootstrap material is invalid")

// LaunchMaterial is the exact public deployment material a controller
// receives at launch and forwards to the instances it launches.
type LaunchMaterial struct {
	Identity       []byte
	Anchor         []byte
	HostEnrollment []byte
}

// ControllerMetadata returns the launch metadata entries a controller needs.
func (material LaunchMaterial) ControllerMetadata() map[string]string {
	return map[string]string{
		IdentityMetadataKey:            string(material.Identity),
		AnchorMetadataKey:              string(material.Anchor),
		hostboot.EnrollmentMetadataKey: string(material.HostEnrollment),
	}
}

// HostMetadata returns the launch metadata entry a managed host needs.
func (material LaunchMaterial) HostMetadata() map[string]string {
	return map[string]string{hostboot.EnrollmentMetadataKey: string(material.HostEnrollment)}
}

// launchMaterialNames are the installed file names, in LaunchMaterial field order.
var launchMaterialNames = [...]string{identityFilename, anchorFilename, HostEnrollmentFilename}

func (material LaunchMaterial) wires() [len(launchMaterialNames)][]byte {
	return [...][]byte{material.Identity, material.Anchor, material.HostEnrollment}
}

// LoadLaunchMaterial reads the installed material this controller forwards.
func LoadLaunchMaterial() (LaunchMaterial, error) {
	return bakedStore{directory: BakedDirectory}.loadLaunchMaterial()
}

// InstallLaunchMaterial verifies launch metadata against the image's trust
// roots and installs it beside them. Installed files are write-once: a retry
// accepts only identical bytes, so a launch cannot be redirected later.
func InstallLaunchMaterial(ctx context.Context, imds IMDSClient, now time.Time) error {
	return bakedStore{directory: BakedDirectory}.installLaunchMaterial(ctx, imds.FetchLaunchMaterial, now)
}

func (store bakedStore) loadLaunchMaterial() (LaunchMaterial, error) {
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return LaunchMaterial{}, fmt.Errorf("open baked bootstrap directory: %w", err)
	}
	defer unix.Close(dir)
	limits := [len(launchMaterialNames)]int64{maxIdentity, bootstrap.MaxBootstrapAnchorBytes,
		hostenroll.MaxPublicBundleBytes}
	var wires [len(launchMaterialNames)][]byte
	for index, name := range launchMaterialNames {
		if wires[index], err = store.readFile(dir, name, limits[index]); err != nil {
			return LaunchMaterial{}, fmt.Errorf("read installed %s: %w", name, err)
		}
	}
	return LaunchMaterial{Identity: wires[0], Anchor: wires[1], HostEnrollment: wires[2]}, nil
}

func (store bakedStore) installLaunchMaterial(ctx context.Context,
	fetch func(context.Context) (LaunchMaterial, error), now time.Time,
) error {
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return fmt.Errorf("open baked bootstrap directory: %w", err)
	}
	defer unix.Close(dir)
	installed := 0
	for _, name := range launchMaterialNames {
		var stat unix.Stat_t
		switch err := unix.Fstatat(dir, name, &stat, unix.AT_SYMLINK_NOFOLLOW); {
		case err == nil:
			installed++
		case !errors.Is(err, unix.ENOENT):
			return fmt.Errorf("inspect installed %s: %w", name, err)
		}
	}
	if installed == len(launchMaterialNames) {
		return nil
	}
	material, err := fetch(ctx)
	if err != nil {
		return err
	}
	if err := store.verifyLaunchMaterial(material, now); err != nil {
		return err
	}
	for index, wire := range material.wires() {
		if err := store.writeOnce(dir, launchMaterialNames[index], wire); err != nil {
			return err
		}
	}
	return unix.Fsync(dir)
}

func (store bakedStore) verifyLaunchMaterial(material LaunchMaterial, now time.Time) error {
	identity, err := parseBakedIdentity(material.Identity)
	if err != nil {
		return fmt.Errorf("%w: identity: %v", ErrLaunchMaterial, err)
	}
	roots, err := store.loadRoots()
	if err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(material.Anchor)
	if err != nil {
		return fmt.Errorf("%w: decode anchor: %v", ErrLaunchMaterial, err)
	}
	if _, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, identity.AnchorExpectation(), now,
		bootstrap.BootstrapAnchorTrustPolicy()); err != nil {
		return fmt.Errorf("%w: verify anchor against image trust roots: %v", ErrLaunchMaterial, err)
	}
	bundle, err := hostenroll.ParsePublicBundle(material.HostEnrollment)
	if err == nil {
		err = bundle.MatchesImageLayout()
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLaunchMaterial, err)
	}
	if bundle.Cell != strings.ToLower(string(identity.Cell)) || bundle.Region != string(identity.Cell) ||
		bundle.Environment != identity.Environment {
		return fmt.Errorf("%w: host enrollment bundle belongs to another cell or environment", ErrLaunchMaterial)
	}
	return nil
}

// writeOnce publishes exact bytes with rename-without-replace, so a crash
// never leaves a partial file under the final name.
func (store bakedStore) writeOnce(dir int, name string, wire []byte) error {
	if existing, err := store.readFile(dir, name, int64(len(wire))); err == nil {
		if !bytes.Equal(existing, wire) {
			return fmt.Errorf("%w: installed %s differs from launch metadata", ErrLaunchMaterial, name)
		}
		return nil
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect installed %s: %w", name, err)
	}
	temporary := "." + name + ".tmp"
	if err := unix.Unlinkat(dir, temporary, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return fmt.Errorf("create %s: %w", temporary, err)
	}
	written, err := unix.Write(fd, wire)
	if err == nil && written != len(wire) {
		err = errors.New("short write")
	}
	if err == nil {
		err = unix.Fchown(fd, int(store.ownerUID), int(store.ownerGID))
	}
	if err == nil {
		err = unix.Fchmod(fd, 0o444)
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	if closeErr := unix.Close(fd); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		_ = unix.Unlinkat(dir, temporary, 0)
		return fmt.Errorf("install %s: %w", name, err)
	}
	return nil
}
