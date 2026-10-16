//go:build linux

package host

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// ContainerMember preserves the existing material, TLS, Vault and held mount
// checks without constructing a native runner or launching any process.
type ContainerMember struct {
	Workload                                                                    Workload
	MountPath, MaterialPath, ControlDirectory, ControlSocket, PublicationSocket string
	Publication                                                                 nativerootoci.Target
	mount                                                                       managedMount
}

func (member *ContainerMember) Close() {
	if member != nil {
		member.mount.close()
	}
}

func ListenContainerPublication(path string, identity WorkloadIdentity) (*net.UnixListener, os.FileInfo, error) {
	if err := verifyManagedDirectory(filepath.Dir(path), identity, 0o750); err != nil {
		return nil, nil, err
	}
	return listenManagedNativeRoot(path, identity)
}

func RemoveContainerPublicationSocket(path string, file os.FileInfo) error {
	return removeManagedNativeRootSocket(&managedNativeRoot{path: path, file: file})
}

// ValidateContainerDesired is also used by the manager's concrete grant producer.
func ValidateContainerDesired(desired Desired, registration Registration) error {
	if desired.Role != "terrabase" || desired.Withdrawn || desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil || registration.ManagedPlacement == nil {
		return errors.New("container member requires a current managed desired and placement")
	}
	return validateDesired(desired, registration.Cell, registration)
}

// PrepareContainerMember installs only the exact pinned backup material and
// derives the same fixed member arguments as the retained host implementation.
func PrepareContainerMember(ctx context.Context, root string, identity WorkloadIdentity, desired Desired, registration Registration, executable, fingerprint string) (*ContainerMember, error) {
	if ctx == nil || ctx.Err() != nil || executable == "" || identity.UID == 0 || identity.GID == 0 {
		return nil, errors.New("container member preparation is incomplete")
	}
	if err := ValidateContainerDesired(desired, registration); err != nil {
		return nil, err
	}
	resolver, err := NewOCIS3CredentialResolver(oci.Region(strings.ToUpper(registration.Cell)))
	if err != nil {
		return nil, err
	}
	config := AgentConfig{ManagedRuntimeRoot: root, WorkloadIdentity: identity, ManagedS3Credentials: resolver, ManagedBackupDataKeys: resolver}
	workload, mount, socket, err := prepareManagedRuntime(ctx, config, desired, executable, fingerprint)
	if err != nil {
		return nil, err
	}
	paths, err := runtimePaths(root, *desired.ManagedMember)
	if err != nil {
		mount.close()
		return nil, err
	}
	wire, err := verifyManagedMaterial(filepath.Join(paths.material, "signed-v2-s3-config.json"), desired.ManagedMember.Runtime.LiveS3ConfigSHA256, identity, 16<<10)
	if err != nil {
		mount.close()
		return nil, err
	}
	target, selected, err := nativeRootTarget(*desired.ManagedMember, wire)
	if err != nil || !selected {
		mount.close()
		return nil, errors.New("container member requires the signed native OCI publication target")
	}
	return &ContainerMember{Workload: workload, MountPath: paths.mount, MaterialPath: paths.material, ControlDirectory: filepath.Dir(socket), ControlSocket: socket, PublicationSocket: paths.nativeRoot, Publication: target, mount: mount}, nil
}

// ContainerMemberPaths derives the exact paths from the signed member identity.
// It performs no filesystem access or process launch.
func ContainerMemberPaths(root string, launch ManagedMemberLaunch) (mount, control, publication string, err error) {
	paths, err := runtimePaths(root, launch)
	if err != nil {
		return "", "", "", err
	}
	return paths.mount, paths.socket, paths.nativeRoot, nil
}
