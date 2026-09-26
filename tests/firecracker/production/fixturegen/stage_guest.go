package fixturegen

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const serviceAccountName = "terrascale-orchestrator"

// StageGuest installs one controller into an already mounted, disposable
// image. The caller must never pass the original base image mount. All packet
// and source authority is checked before the first write.
func StageGuest(ctx context.Context, packet VerifiedPacket, roots trust.Keyring,
	imageOCID, sourceRoot, guestRoot, slot string, now time.Time,
) error {
	if os.Geteuid() != 0 || now.IsZero() {
		return errors.New("guest staging requires root and a trusted current clock")
	}
	if err := VerifyCompletedSourcePins(sourceRoot, packet.Manifest().SourcePins); err != nil {
		return fmt.Errorf("staging source pins: %w", err)
	}
	if _, err := VerifyPacketEmbeddedImage(packet, roots, imageOCID, now); err != nil {
		return fmt.Errorf("staging image binding: %w", err)
	}
	if err := packet.ValidateProductionGuests(now); err != nil {
		return fmt.Errorf("staging production packet: %w", err)
	}
	directories, err := packet.GuestDirectories(slot)
	if err != nil {
		return err
	}
	files, err := packet.GuestFiles(slot)
	if err != nil {
		return err
	}
	executable, err := packet.Executable()
	if err != nil {
		return err
	}
	root, err := filepath.Abs(guestRoot)
	if err != nil {
		return err
	}
	if err := verifyMountedGuestRoot(root); err != nil {
		return err
	}
	if len(directories) != 2 || directories[0].UID != directories[1].UID ||
		directories[0].GID != directories[1].GID {
		return errors.New("signed service directory ownership is incomplete")
	}
	if err := verifyGuestAccount(root, directories[0].UID, directories[0].GID); err != nil {
		return err
	}
	sysusersSource, err := os.ReadFile(filepath.Join(sourceRoot, "deploy/image/terrascale-orchestrator.sysusers"))
	if err != nil {
		return err
	}
	sysusersGuest, err := readGuestRegular(root, "/etc/sysusers.d/terrascale-orchestrator.conf")
	if err != nil || !bytes.Equal(sysusersGuest, sysusersSource) {
		return fmt.Errorf("guest image has unpinned service-account policy: %w", err)
	}
	if err := verifyRootOwnedGuestFile(root, "/etc/sysusers.d/terrascale-orchestrator.conf", 0o644); err != nil {
		return err
	}
	for _, unit := range []string{"terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-controller.service"} {
		source, err := os.ReadFile(filepath.Join(sourceRoot, "deploy/systemd", unit))
		if err != nil {
			return err
		}
		installed, err := readGuestRegular(root, "/etc/systemd/system/"+unit)
		if err != nil || !bytes.Equal(installed, source) {
			return fmt.Errorf("guest image has unpinned shipped unit %q: %w", unit, err)
		}
		if err := verifyRootOwnedGuestFile(root, "/etc/systemd/system/"+unit, 0o644); err != nil {
			return err
		}
		if unit == "terrascale-orchestrator-bootstrap.service" &&
			(!bytes.Contains(source, []byte("\nUser=root\n")) ||
				!bytes.Contains(source, []byte("\nRequires=systemd-timesyncd.service systemd-time-wait-sync.service\n"))) {
			return errors.New("shipped bootstrap unit lacks root and NTP gate")
		}
		if unit == "terrascale-orchestrator-controller.service" &&
			!bytes.Contains(source, []byte("\nUser=terrascale-orchestrator\n")) {
			return errors.New("shipped controller unit lacks dedicated service account")
		}
	}
	for _, unit := range []string{"systemd-timesyncd.service", "systemd-time-wait-sync.service"} {
		if _, err := readGuestRegular(root, "/usr/lib/systemd/system/"+unit); err != nil {
			return fmt.Errorf("guest image lacks NTP unit %q: %w", unit, err)
		}
	}
	ntpGate, err := readGuestRegular(root,
		"/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf")
	if err != nil || !bytes.Equal(ntpGate, []byte("[Service]\nTimeoutStartSec=300s\n")) {
		return fmt.Errorf("guest image lacks shipped time-wait-sync timeout: %w", err)
	}
	if err := verifyRootOwnedGuestFile(root,
		"/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf", 0o644); err != nil {
		return err
	}
	for _, directory := range directories {
		if err := ensureGuestDirectory(root, directory.GuestPath, os.FileMode(directory.Mode),
			directory.UID, directory.GID); err != nil {
			return err
		}
	}
	if err := installGuestFile(root, executable.GuestPath, executable.Body,
		os.FileMode(executable.Mode), 0, 0); err != nil {
		return err
	}
	for _, file := range files {
		var uid, gid uint32
		if file.File.OwnerRole == "service:"+slot {
			uid, gid = directories[0].UID, directories[0].GID
		} else if file.File.OwnerRole != "root:"+slot {
			return fmt.Errorf("guest file %q has unexpected owner role", file.GuestPath)
		}
		if err := installGuestFile(root, file.GuestPath, file.Body,
			os.FileMode(file.File.Mode), uid, gid); err != nil {
			return err
		}
	}
	if err := refreshGuestCA(ctx, root, packet, slot); err != nil {
		return err
	}
	if err := preflightGuestCredentials(ctx, root, files, directories[0].UID, directories[0].GID); err != nil {
		return err
	}
	return nil
}

func verifyMountedGuestRoot(root string) error {
	if root == "/" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("guest root must be an exact non-root mount point")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("guest root must be a mounted real directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return errors.New("guest root has a symlink ancestor")
	}
	parent, err := os.Stat(filepath.Dir(root))
	if err != nil {
		return err
	}
	rootStat, rootOK := info.Sys().(*syscall.Stat_t)
	parentStat, parentOK := parent.Sys().(*syscall.Stat_t)
	if !rootOK || !parentOK || rootStat.Dev == parentStat.Dev {
		return errors.New("guest root is not a distinct filesystem mount point")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(root, &filesystem); err != nil {
		return err
	}
	if filesystem.Type != unix.EXT4_SUPER_MAGIC {
		return errors.New("guest root mount is not an ext4 image")
	}
	return nil
}

func verifyGuestAccount(root string, wantUID, wantGID uint32) error {
	passwd, err := readGuestRegular(root, "/etc/passwd")
	if err != nil {
		return err
	}
	group, err := readGuestRegular(root, "/etc/group")
	if err != nil {
		return err
	}
	var uid, primaryGID, gid uint64
	var users, groups int
	for line := range strings.SplitSeq(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] != serviceAccountName {
			continue
		}
		if len(fields) != 7 {
			return errors.New("guest service passwd entry is malformed")
		}
		users++
		uid, err = strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return err
		}
		primaryGID, err = strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			return err
		}
	}
	for line := range strings.SplitSeq(string(group), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] != serviceAccountName {
			continue
		}
		if len(fields) != 4 {
			return errors.New("guest service group entry is malformed")
		}
		groups++
		gid, err = strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return err
		}
	}
	if users != 1 || groups != 1 || uid == 0 || gid == 0 ||
		uid != uint64(wantUID) || primaryGID != uint64(wantGID) || gid != uint64(wantGID) {
		return errors.New("guest service account UID/GID differs from signed directory plan")
	}
	return nil
}

func guestPath(root, absolute string, createParents bool) (string, error) {
	if !filepath.IsAbs(absolute) || filepath.Clean(absolute) != absolute || absolute == "/" {
		return "", fmt.Errorf("invalid guest path %q", absolute)
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	current := root
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && createParents {
			if err := os.Mkdir(current, 0o755); err != nil {
				return "", err
			}
			if err := os.Chown(current, 0, 0); err != nil {
				return "", err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("guest path %q has missing or unsafe ancestor", absolute)
		}
	}
	return filepath.Join(current, parts[len(parts)-1]), nil
}

func readGuestRegular(root, absolute string) ([]byte, error) {
	path, err := guestPath(root, absolute, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("guest path %q is not regular: %w", absolute, err)
	}
	if info.Size() < 0 || info.Size() > 8<<20 {
		return nil, fmt.Errorf("guest path %q exceeds bounded read", absolute)
	}
	return os.ReadFile(path)
}

func verifyRootOwnedGuestFile(root, absolute string, mode os.FileMode) error {
	path, err := guestPath(root, absolute, false)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return fmt.Errorf("guest image file %q has unexpected type or mode", absolute)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("guest image file %q is not root-owned", absolute)
	}
	return nil
}

func ensureGuestDirectory(root, absolute string, mode os.FileMode, uid, gid uint32) error {
	path, err := guestPath(root, absolute, true)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guest directory %q is unsafe", absolute)
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func installGuestFile(root, absolute string, body []byte, mode os.FileMode, uid, gid uint32) error {
	path, err := guestPath(root, absolute, true)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("guest destination %q is not regular", absolute)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ts-stage-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chown(int(uid), int(gid)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func refreshGuestCA(ctx context.Context, root string, packet VerifiedPacket, slot string) error {
	caFiles, err := packet.GuestFiles(slot)
	if err != nil {
		return err
	}
	var expected *x509.Certificate
	for _, file := range caFiles {
		if file.GuestPath == fixtureCAGuestPath {
			block, _ := pem.Decode(file.Body)
			if block == nil {
				return errors.New("signed OCI CA cannot be decoded")
			}
			expected, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
		}
	}
	if expected == nil {
		return errors.New("signed OCI CA is absent")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/usr/sbin/update-ca-certificates", "--fresh")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("update guest CA bundle: %w: %s", err, output)
	}
	bundle, err := readGuestRegular(root, "/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return err
	}
	for len(bundle) > 0 {
		block, rest := pem.Decode(bundle)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, expected.Raw) {
			return nil
		}
		bundle = rest
	}
	return errors.New("guest system CA bundle lacks signed OCI simulator CA")
}

func preflightGuestCredentials(ctx context.Context, root string, files []GuestFile, uid, gid uint32) error {
	var config []byte
	for _, file := range files {
		if file.GuestPath == controllerConfigGuestPath {
			config = file.Body
		}
	}
	var cfg app.Config
	if len(config) == 0 || protocol.DecodeStrict(config, &cfg, 1<<20) != nil {
		return errors.New("signed controller config cannot be decoded for service preflight")
	}
	request, err := protocol.EncodeJSON(bootstrapstart.CredentialChildRequest{
		Config: cfg.NATS, UID: uid, GID: gid,
		ResponseKeyFile:     cfg.Controller.ResponseKeyFile,
		BrokerTicketKeyFile: cfg.Controller.BrokerTicketKeyFile,
	})
	if err != nil {
		return err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/usr/local/bin/terrascale-orchestrator", "bootstrap-credential-check")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stdin = bytes.NewReader(request)
	command.SysProcAttr = &syscall.SysProcAttr{Chroot: root,
		Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("shipped binary rejected service-account credentials: %w: %s", err, output)
	}
	return nil
}
