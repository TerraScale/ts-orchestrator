//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"golang.org/x/sys/unix"
)

const nativeMaintenanceCertificateDirectory = swarmStateDirectory + "/node/certificates"
const maxNativeMaintenanceIdentityFileBytes = 64 << 10

// NativeMaintenanceIdentity retains root's exact native identity, not permission
// to maintain a node. Its key never leaves this package.
type NativeMaintenanceIdentity struct {
	original                          context.Context
	node                              *Node
	local                             *ControllerHostBinding
	control                           *manager.ControlReader
	key                               crypto.Signer
	chain                             [][]byte
	files                             [3]nativeMaintenanceFilePin
	directories                       []nativeMaintenancePathPin
	nodeID, clusterID, source, anchor string
	deadline                          time.Time
}

func (p *NativeMaintenanceIdentity) ExpiresAt() time.Time { return p.deadline }

// ReadNativeMaintenanceIdentity accepts only the live root-owned manager and
// its actual accepted ownhost binding. Original Call/R3 custody belongs to the
// separate private APP before-source; this proof exposes no transport or signer.
func (n *Node) ReadNativeMaintenanceIdentity(ctx context.Context, local *ControllerHostBinding) (*NativeMaintenanceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || !nativeMaintenanceNodeMatches(n, local) {
		return nil, errors.New("native maintenance requires the root-owned accepted local manager")
	}
	current, err := local.reader.ReadRuntimeAuthority(ctx, local.accepted, time.Now().UTC())
	if err != nil || current.Identity() != local.identity {
		return nil, errors.New("native maintenance local authority unavailable")
	}
	deadline := current.ExpiresAt()
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	readCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if _, err := local.currentRegistration(readCtx); err != nil {
		return nil, err
	}
	files, directories, err := readNativeMaintenanceIdentityFiles()
	if err != nil {
		return nil, err
	}
	defer clear(files[0].wire)
	key, chain, err := parseNodeSigningKey(n.ID(), files[0].wire, files[1].wire, files[2].wire)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil || !slices.Contains(leaf.Subject.OrganizationalUnit, "swarm-manager") {
		return nil, errors.New("native maintenance identity is not a manager certificate")
	}
	if leaf.NotAfter.Before(deadline) {
		deadline = leaf.NotAfter
	}
	readCtx, certificateCancel := context.WithDeadline(readCtx, deadline)
	defer certificateCancel()
	if err := readCtx.Err(); err != nil {
		return nil, err
	}
	control, err := n.ReadOnlyControlClient(readCtx)
	if err != nil {
		return nil, err
	}
	cluster, err := control.ClusterIdentity(readCtx)
	if err != nil || cluster == nil || cluster.ID == "" || !bytes.Equal(cluster.RootCACert, files[2].wire) ||
		!slices.Equal(leaf.Subject.Organization, []string{cluster.ID}) {
		return nil, errors.New("native maintenance identity differs from the live native cluster")
	}
	proof := &NativeMaintenanceIdentity{original: ctx, node: n, local: local, control: control, key: key, chain: chain,
		directories: directories, nodeID: n.ID(), clusterID: cluster.ID, source: current.ManagerSourceSHA256(), anchor: current.Anchor().Digest(), deadline: deadline}
	for i := range files {
		proof.files[i] = files[i].pin
	}
	if proof.source == "" || proof.anchor == "" {
		return nil, errors.New("native maintenance accepted source unavailable")
	}
	if err := proof.Revalidate(readCtx); err != nil {
		return nil, err
	}
	return proof, nil
}

func nativeMaintenanceNodeMatches(n *Node, local *ControllerHostBinding) bool {
	if os.Geteuid() != 0 || n == nil || n.upstream == nil || n.done == nil || n.role != "manager" ||
		n.stateDir != swarmStateDirectory+"/node" || local == nil || local.reader == nil || local.hostID == "" {
		return false
	}
	select {
	case <-n.done:
		return false
	default:
	}
	id := local.identity
	return n.admission.InstanceID == id.InstanceID && n.admission.HostID == id.Slot && n.admission.Region == id.OCIRegion && n.admission.Role == "manager"
}

// Revalidate never adopts a replaced inode, rotated certificate, renewed source
// or successor manager. The caller must also guard its original Call/R3 source.
func (p *NativeMaintenanceIdentity) Revalidate(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.original == nil || p.original.Err() != nil ||
		p.control == nil || p.key == nil || !nativeMaintenanceNodeMatches(p.node, p.local) || p.node.ID() != p.nodeID || !time.Now().Before(p.deadline) {
		return errors.New("original native maintenance identity ended")
	}
	ctx, cancel := context.WithDeadline(ctx, p.deadline)
	stop := context.AfterFunc(p.original, cancel)
	defer cancel()
	defer stop()
	if _, err := p.local.currentRegistration(ctx); err != nil {
		return err
	}
	current, err := p.local.reader.ReadRuntimeAuthority(ctx, p.local.accepted, time.Now().UTC())
	if err != nil || current.Identity() != p.local.identity || current.ExpiresAt().Before(p.deadline) ||
		current.ManagerSourceSHA256() != p.source || current.Anchor().Digest() != p.anchor {
		return errors.New("original native maintenance accepted source changed")
	}
	files, directories, err := readNativeMaintenanceIdentityFiles()
	if err != nil {
		return err
	}
	defer clear(files[0].wire)
	if !slices.Equal(directories, p.directories) {
		return errors.New("original native maintenance directory custody changed")
	}
	for i := range files {
		if files[i].pin != p.files[i] {
			return errors.New("original native maintenance key or certificate changed")
		}
	}
	if _, _, err := parseNodeSigningKey(p.nodeID, files[0].wire, files[1].wire, files[2].wire); err != nil {
		return err
	}
	got, err := p.control.GetNode(ctx, &api.GetNodeRequest{NodeID: p.node.ID()})
	if err != nil || got == nil || got.Node == nil {
		return errors.New("original native maintenance member unavailable")
	}
	native, id := got.Node, p.local.identity
	if native.ID != p.node.ID() || native.Role != api.NodeRoleManager || native.Spec.DesiredRole != api.NodeRoleManager ||
		native.Spec.Membership != api.NodeMembershipAccepted || native.Status.State != api.NodeStatus_READY ||
		native.Spec.Annotations.Name != id.Slot || native.Spec.Annotations.Labels[LabelInstanceID] != id.InstanceID ||
		native.Spec.Annotations.Labels[LabelRegion] != id.OCIRegion || native.Spec.Annotations.Labels[LabelHostRole] != "manager" ||
		native.Spec.Annotations.Labels[LabelExecutionScope] != "platform" || native.Certificate.CN != native.ID ||
		native.Certificate.Role != api.NodeRoleManager || !bytes.Equal(native.Certificate.Certificate, files[1].wire) {
		return errors.New("original native maintenance member changed")
	}
	cluster, err := p.control.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID != p.clusterID || !bytes.Equal(cluster.RootCACert, files[2].wire) {
		return errors.New("original native maintenance cluster changed")
	}
	if _, err := p.local.currentRegistration(ctx); err != nil {
		return err
	}
	confirmedFiles, confirmedDirectories, err := readNativeMaintenanceIdentityFiles()
	if err != nil {
		return err
	}
	clear(confirmedFiles[0].wire)
	if !slices.Equal(confirmedDirectories, p.directories) {
		return errors.New("original native maintenance path changed during verification")
	}
	for i := range confirmedFiles {
		if confirmedFiles[i].pin != p.files[i] {
			return errors.New("original native maintenance identity changed during verification")
		}
	}
	confirmed, err := p.local.reader.ReadRuntimeAuthority(ctx, p.local.accepted, time.Now().UTC())
	if err != nil || confirmed.Identity() != current.Identity() || confirmed.ExpiresAt().Before(p.deadline) ||
		confirmed.ManagerSourceSHA256() != p.source || confirmed.Anchor().Digest() != p.anchor ||
		!nativeMaintenanceNodeMatches(p.node, p.local) || !time.Now().Before(p.deadline) || p.original.Err() != nil {
		return errors.New("original native maintenance source changed during identity verification")
	}
	return ctx.Err()
}

type nativeMaintenancePathPin struct {
	device, inode  uint64
	mode, uid, gid uint32
}

type nativeMaintenanceFilePin struct {
	path              nativeMaintenancePathPin
	links             uint64
	size              int64
	modified, changed unix.Timespec
	digest            [32]byte
}

type nativeMaintenanceFile struct {
	wire []byte
	pin  nativeMaintenanceFilePin
}

func nativeMaintenancePath(stat unix.Stat_t) nativeMaintenancePathPin {
	return nativeMaintenancePathPin{device: uint64(stat.Dev), inode: stat.Ino, mode: stat.Mode, uid: stat.Uid, gid: stat.Gid}
}

func readNativeMaintenanceIdentityFiles() ([3]nativeMaintenanceFile, []nativeMaintenancePathPin, error) {
	var files [3]nativeMaintenanceFile
	if os.Geteuid() != 0 {
		return files, nil, errors.New("native maintenance key custody requires root")
	}
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return files, nil, err
	}
	defer func() { _ = unix.Close(directory) }()
	var directories []nativeMaintenancePathPin
	path := ""
	for component := range strings.SplitSeq(strings.TrimPrefix(nativeMaintenanceCertificateDirectory, "/"), "/") {
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return files, nil, errors.New("native maintenance ancestry is not root-owned")
		}
		directories = append(directories, nativeMaintenancePath(stat))
		next, err := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return files, nil, err
		}
		_ = unix.Close(directory)
		directory = next
		path += "/" + component
		if path == swarmStateDirectory || path == swarmStateDirectory+"/node" || path == nativeMaintenanceCertificateDirectory {
			if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0o7777 != 0o700 {
				return files, nil, errors.New("native maintenance private directory custody changed")
			}
		}
	}
	var stat unix.Stat_t
	if unix.Fstat(directory, &stat) != nil {
		return files, nil, errors.New("native maintenance certificate directory unavailable")
	}
	directories = append(directories, nativeMaintenancePath(stat))
	for i, name := range []string{"swarm-node.key", "swarm-node.crt", "swarm-root-ca.crt"} {
		mode := uint32(0o644)
		if i == 0 {
			mode = 0o600
		}
		files[i], err = readNativeMaintenanceIdentityFile(directory, name, mode)
		if err != nil {
			clear(files[0].wire)
			return files, nil, err
		}
	}
	return files, directories, nil
}

func readNativeMaintenanceIdentityFile(directory int, name string, mode uint32) (nativeMaintenanceFile, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nativeMaintenanceFile{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after, path unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 ||
		before.Nlink != 1 || before.Mode&0o7777 != mode || before.Size <= 0 || before.Size > maxNativeMaintenanceIdentityFileBytes {
		return nativeMaintenanceFile{}, errors.New("native maintenance identity file custody rejected")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxNativeMaintenanceIdentityFileBytes+1))
	pin := func(stat unix.Stat_t) nativeMaintenanceFilePin {
		return nativeMaintenanceFilePin{path: nativeMaintenancePath(stat), links: uint64(stat.Nlink), size: stat.Size,
			modified: stat.Mtim, changed: stat.Ctim, digest: sha256.Sum256(wire)}
	}
	if err != nil || int64(len(wire)) != before.Size || unix.Fstat(fd, &after) != nil ||
		unix.Fstatat(directory, name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || pin(before) != pin(after) || pin(before) != pin(path) {
		clear(wire)
		return nativeMaintenanceFile{}, errors.New("native maintenance identity file changed while reading")
	}
	return nativeMaintenanceFile{wire: wire, pin: pin(before)}, nil
}
