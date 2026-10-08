package firecracker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type ManagedLab struct {
	Step             func(string, func() error) error
	commandHooks     *processHooks
	pendingCommands  []managedPendingCommand
	NativeProvenance NativeProvenance

	Ctx                                                                                            context.Context
	Manifest                                                                                       ManagedManifest
	Command                                                                                        CommandFunc
	Root, Logs, Commands, Images, Mounts, Stage, Fixture, FixtureCA, SocketDir, Bridge, RustFSName string
	S3CredentialPaths                                                                              [2]string
	S3KeyHashes                                                                                    [2]string
	RustFSStarted                                                                                  bool
	Taps, Tokens, SourcePaths, SourceHashes                                                        map[string]string
	CreatedLinks                                                                                   []string
	Mounted                                                                                        map[string]bool
	VMs                                                                                            map[string]*ManagedVM
	Events                                                                                         []Object
	CleanupErrors                                                                                  []string
	Failure                                                                                        string
	StartedAt                                                                                      time.Time
	CommandNumber                                                                                  int
	Stdout                                                                                         io.Writer
}

type managedPendingCommand struct {
	label, path string
	process     *Process
}

func NewManagedLab(ctx context.Context, m ManagedManifest, root, sourceRoot string, credentials [2]string, out io.Writer) (*ManagedLab, error) {
	suffix := token(3)
	l := &ManagedLab{Ctx: ctx, Manifest: m, Root: root, Logs: filepath.Join(root, "logs"), Commands: filepath.Join(root, "commands"), Images: filepath.Join(root, "images"), Mounts: filepath.Join(root, "mounts"), Stage: filepath.Join(root, "stage"), Fixture: filepath.Join(root, "rustfs"), S3CredentialPaths: credentials, RustFSName: "tsmm-rustfs-" + token(8), Bridge: "tsm" + suffix + "b", Taps: map[string]string{"a": "tsm" + suffix + "1", "b": "tsm" + suffix + "2"}, Tokens: map[string]string{"a": token(32), "b": token(32)}, Mounted: map[string]bool{}, VMs: map[string]*ManagedVM{}, StartedAt: time.Now(), SourcePaths: map[string]string{}, SourceHashes: map[string]string{}, Stdout: out}
	l.FixtureCA = filepath.Join(l.Fixture, "ca.crt")
	var e error
	l.NativeProvenance, e = CaptureNativeProvenance()
	if e != nil {
		return nil, e
	}
	for _, name := range []string{"go.mod", "go.sum", "tests/firecracker/managedmember/qualify_test.go", "tests/firecracker/managedmember/README.md", "internal/testutil/script/script.go", "internal/host/managed_member_firecracker_test.go"} {
		l.SourcePaths[name] = filepath.Join(sourceRoot, name)
	}
	if e := filepath.WalkDir(filepath.Join(sourceRoot, "internal/qualification/firecracker"), func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") {
			name, e := filepath.Rel(sourceRoot, p)
			if e != nil {
				return e
			}
			l.SourcePaths[name] = p
		}
		return nil
	}); e != nil {
		return nil, e
	}
	for name, path := range l.SourcePaths {
		h, e := DirectDigest(path)
		if e != nil {
			return nil, e
		}
		l.SourceHashes[name] = h
	}
	return l, nil
}
func (l *ManagedLab) Note(kind string, fields Object) {
	entry := Object{"at": time.Now().UTC().Format(time.RFC3339Nano), "kind": kind}
	for k, v := range fields {
		entry[k] = v
	}
	l.Events = append(l.Events, entry)
}
func (l *ManagedLab) RunCommand(label string, args []string, sudo bool, timeout time.Duration, allowed []int, env []string) (string, error) {
	l.CommandNumber++
	path := filepath.Join(l.Commands, fmt.Sprintf("%03d-%s.log", l.CommandNumber, label))
	argv := slices.Clone(args)
	if sudo {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	o := CommandOptions{Timeout: timeout, AllowFailure: true, Env: env}
	var r CommandResult
	var e error
	if l.Command != nil {
		r, e = l.Command(l.Ctx, argv, o)
		if writeErr := os.WriteFile(path, []byte(head(r.Stdout+r.Stderr, 32<<20)), 0o600); e == nil {
			e = writeErr
		}
		if len(r.Stdout+r.Stderr) > 32<<20 {
			e = errors.Join(e, errors.New("command log exceeded 33554432 bytes"))
		}
	} else {
		r, _, e = runBoundedCommand(l.Ctx, argv, o, path, 32<<20, l.commandHooks)
	}
	if pending, ok := errors.AsType[*PendingCommandError](e); ok {
		l.pendingCommands = append(l.pendingCommands, managedPendingCommand{label: label, path: path, process: pending.Process})
	}
	if e != nil {
		return "", fmt.Errorf("%s: %w; see %s", label, e, path)
	}
	if !slices.Contains(allowed, r.Code) {
		return "", fmt.Errorf("%s: exit %d; see %s: %s", label, r.Code, path, tail(r.Stdout, 1500))
	}
	l.Note("command", Object{"label": label, "argv": args, "sudo": sudo})
	return r.Stdout, nil
}
func (l *ManagedLab) cmd(label string, args []string, sudo bool, timeout time.Duration) (string, error) {
	return l.RunCommand(label, args, sudo, timeout, []int{0}, nil)
}
func (l *ManagedLab) PrepareDirs() error {
	if _, e := os.Lstat(l.Root); e == nil || !os.IsNotExist(e) {
		return errors.New("run directory must not exist before qualification")
	}
	if e := os.Mkdir(l.Root, 0o700); e != nil {
		return e
	}
	for _, d := range []string{l.Logs, l.Commands, l.Images, l.Mounts, l.Stage, l.Fixture} {
		if e := os.Mkdir(d, 0o700); e != nil {
			return e
		}
	}
	if e := os.WriteFile(filepath.Join(l.Root, "manifest.json"), l.Manifest.Raw, 0o600); e != nil {
		return e
	}
	l.Note("start", Object{"profile": ManagedMemberProfile, "manifest_sha256": l.Manifest.SHA256, "source_commits": l.Manifest.Commits, "source_hashes": l.SourceHashes, "native_provenance": l.NativeProvenance})
	return nil
}
func (l *ManagedLab) RecheckInputs() error {
	records := []ManagedInput{}
	for _, r := range l.Manifest.Inputs {
		records = append(records, r)
	}
	for _, m := range l.Manifest.Members {
		for _, r := range m.Inputs {
			records = append(records, r)
		}
	}
	for _, r := range records {
		h, e := DirectDigest(r.Path)
		if e != nil {
			return e
		}
		if h != r.SHA256 {
			return fmt.Errorf("immutable input changed: %s", r.Path)
		}
	}
	l.Note("inputs_rechecked", Object{"count": len(records)})
	return nil
}
func (l *ManagedLab) CopyImages() error {
	for _, member := range []string{"a", "b"} {
		rootfs, volume := filepath.Join(l.Images, member+"-rootfs.ext4"), filepath.Join(l.Images, member+"-volume.ext4")
		for _, copy := range []struct {
			name   string
			input  ManagedInput
			target string
		}{{"rootfs", l.Manifest.Inputs["rootfs"], rootfs}, {"volume", l.Manifest.Members[member].Inputs["volume_ext4"], volume}} {
			if _, e := l.cmd("copy-"+member+"-"+copy.name, []string{"cp", "--reflink=auto", "--sparse=always", copy.input.Path, copy.target}, false, 240*time.Second); e != nil {
				return e
			}
			if e := os.Chmod(copy.target, 0o600); e != nil {
				return e
			}
			h, e := DirectDigest(copy.target)
			if e != nil {
				return e
			}
			if h != copy.input.SHA256 {
				return fmt.Errorf("private %s %s differs from pinned input", member, copy.name)
			}
			l.Note("private_image_verified", Object{"member": member, "image": copy.name, "sha256": h})
		}
		s, e := os.Stat(rootfs)
		if e != nil {
			return e
		}
		if e = os.Truncate(rootfs, max(s.Size(), 8<<30)); e != nil {
			return e
		}
		if _, e = l.RunCommand("e2fsck-"+member+"-rootfs", []string{"e2fsck", "-f", "-y", rootfs}, false, 240*time.Second, []int{0, 1}, nil); e != nil {
			return e
		}
		for _, cmd := range []struct {
			label   string
			args    []string
			timeout time.Duration
		}{{"resize-" + member + "-rootfs", []string{"resize2fs", rootfs}, 240 * time.Second}, {"e2fsck-" + member + "-volume", []string{"e2fsck", "-fn", volume}, 120 * time.Second}} {
			if _, e = l.cmd(cmd.label, cmd.args, false, cmd.timeout); e != nil {
				return e
			}
		}
		uuid, e := l.cmd("uuid-"+member+"-volume", []string{"blkid", "-s", "UUID", "-o", "value", volume}, false, 30*time.Second)
		if e != nil {
			return e
		}
		kind, e := l.cmd("type-"+member+"-volume", []string{"blkid", "-s", "TYPE", "-o", "value", volume}, false, 30*time.Second)
		if e != nil {
			return e
		}
		if strings.TrimSpace(uuid) != ManagedVolumeUUIDs[member] || strings.TrimSpace(kind) != "ext4" {
			return fmt.Errorf("%s: attached private volume UUID/type mismatch", member)
		}
	}
	return nil
}
func isMount(path string) (bool, error) {
	var s, parent syscall.Stat_t
	if e := syscall.Stat(path, &s); e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return false, nil
		}
		return false, e
	}
	if e := syscall.Stat(filepath.Dir(path), &parent); e != nil {
		return false, e
	}
	return s.Dev != parent.Dev || s.Ino == parent.Ino, nil
}
func (l *ManagedLab) MountRoot(member string, readOnly bool) (string, error) {
	target := filepath.Join(l.Mounts, member)
	if e := os.Mkdir(target, 0o700); e != nil {
		return "", fmt.Errorf("%s: root mount path already exists: %w", member, e)
	}
	option := "loop"
	if readOnly {
		option = "loop,ro,noload"
	}
	l.Mounted[member] = true
	_, e := l.cmd("mount-"+member, []string{"mount", "-o", option, filepath.Join(l.Images, member+"-rootfs.ext4"), target}, true, 120*time.Second)
	mounted, probeErr := isMount(target)
	if mounted {
		l.Mounted[member] = true
	}
	if e != nil {
		if !mounted && probeErr == nil && len(l.pendingCommands) == 0 {
			delete(l.Mounted, member)
			_ = os.Remove(target)
		}
		return "", e
	}
	if probeErr != nil {
		return "", probeErr
	}
	if !mounted {
		return "", fmt.Errorf("%s: mount returned without mounting", member)
	}
	return target, nil
}
func (l *ManagedLab) UnmountRoot(member string) error {
	if len(l.pendingCommands) > 0 {
		return fmt.Errorf("%s: image retained while commands may still be live", member)
	}
	target := filepath.Join(l.Mounts, member)
	mounted, e := isMount(target)
	if e != nil {
		return e
	}
	if !mounted {
		delete(l.Mounted, member)
		return removeMissing(target)
	}
	if !l.Mounted[member] {
		return fmt.Errorf("%s: refusing to unmount unowned image", member)
	}
	if _, e = l.cmd("umount-"+member, []string{"umount", target}, true, 120*time.Second); e != nil {
		return e
	}
	mounted, e = isMount(target)
	if e != nil {
		return e
	}
	if mounted {
		return fmt.Errorf("%s: owned image remains mounted", member)
	}
	delete(l.Mounted, member)
	return os.Remove(target)
}
func (l *ManagedLab) StageText(name, text string, mode os.FileMode) (string, error) {
	p := filepath.Join(l.Stage, name)
	if e := os.WriteFile(p, []byte(text), mode); e != nil {
		return "", e
	}
	return p, os.Chmod(p, mode)
}
func (l *ManagedLab) Install(mount, source, destination, mode, group string) error {
	target, e := GuestPath(mount, destination)
	if e != nil {
		return e
	}
	_, e = l.cmd("install-"+filepath.Base(destination), []string{"install", "-D", "-o", "root", "-g", group, "-m", mode, source, target}, true, 60*time.Second)
	return e
}
func (l *ManagedLab) InstallDir(mount, destination, mode, group string) error {
	target, e := GuestPath(mount, destination)
	if e != nil {
		return e
	}
	_, e = l.cmd("install-dir-"+filepath.Base(destination), []string{"install", "-d", "-o", "root", "-g", group, "-m", mode, target}, true, 30*time.Second)
	return e
}
func (l *ManagedLab) StagedSHA256(mount, destination string) (string, error) {
	target, e := GuestPath(mount, destination)
	if e != nil {
		return "", e
	}
	output, e := l.cmd("hash-"+filepath.Base(destination), []string{"sha256sum", target}, true, 60*time.Second)
	if e != nil {
		return "", e
	}
	fields := strings.Fields(output)
	if len(fields) != 2 || fields[1] != target || !shaPattern.MatchString(fields[0]) {
		return "", fmt.Errorf("staged guest hash output is malformed for %s", destination)
	}
	return fields[0], nil
}
func (l *ManagedLab) StageManagedMaterial(mount, member string, inputs map[string]ManagedInput) error {
	directories := ManagedDirectories(member)
	for _, d := range directories {
		if e := l.InstallDir(mount, d[0].(string), "0755", "65534"); e != nil {
			return e
		}
	}
	for _, material := range ManagedMaterials {
		dest := ManagedMemberDirs[member] + "/material/" + material[1]
		input := inputs[material[0]]
		if e := l.Install(mount, input.Path, dest, "0440", "65534"); e != nil {
			return e
		}
		h, e := l.StagedSHA256(mount, dest)
		if e != nil {
			return e
		}
		if h != input.SHA256 {
			return fmt.Errorf("%s: staged %s changed", member, material[0])
		}
	}
	type expected struct {
		path      string
		mode      uint64
		directory bool
	}
	expectedPaths := []expected{}
	for _, d := range directories {
		p, e := GuestPath(mount, d[0].(string))
		if e != nil {
			return e
		}
		expectedPaths = append(expectedPaths, expected{p, uint64(d[1].(int)), true})
	}
	for _, material := range ManagedMaterials {
		p, e := GuestPath(mount, ManagedMemberDirs[member]+"/material/"+material[1])
		if e != nil {
			return e
		}
		expectedPaths = append(expectedPaths, expected{p, 0o440, false})
	}
	for i := len(directories) - 1; i >= 0; i-- {
		d := directories[i]
		if e := l.InstallDir(mount, d[0].(string), fmt.Sprintf("%04o", d[1]), "65534"); e != nil {
			return e
		}
	}
	argv := []string{"stat", "-c", "%u:%g:%f", "--"}
	for _, p := range expectedPaths {
		argv = append(argv, p.path)
	}
	output, e := l.cmd("verify-"+member+"-managed-layout", argv, true, 30*time.Second)
	if e != nil {
		return e
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != len(expectedPaths) {
		return fmt.Errorf("%s: managed layout stat count mismatch", member)
	}
	for i, expected := range expectedPaths {
		fields := strings.Split(lines[i], ":")
		if len(fields) != 3 {
			return fmt.Errorf("%s: malformed managed layout stat", member)
		}
		observed, e := strconv.ParseUint(fields[2], 16, 64)
		if e != nil {
			return e
		}
		kind := uint64(syscall.S_IFREG)
		if expected.directory {
			kind = syscall.S_IFDIR
		}
		if fields[0] != "0" || fields[1] != "65534" || observed&0o7777 != expected.mode || observed&syscall.S_IFMT != kind {
			return fmt.Errorf("%s: unsafe final managed layout at %s", member, expected.path)
		}
	}
	return nil
}
func (l *ManagedLab) EnableUnit(mount, name string) error {
	wants, e := GuestPath(mount, "/etc/systemd/system/multi-user.target.wants")
	if e != nil {
		return e
	}
	if _, e = l.cmd("wants-dir", []string{"install", "-d", "-o", "root", "-g", "root", "-m", "0755", wants}, true, 120*time.Second); e != nil {
		return e
	}
	link := filepath.Join(wants, name)
	if _, e = os.Lstat(link); e == nil || !os.IsNotExist(e) {
		return fmt.Errorf("guest unit link already exists: %s", link)
	}
	_, e = l.cmd("enable-"+name, []string{"ln", "-s", "../" + name, link}, true, 120*time.Second)
	return e
}
func (l *ManagedLab) StageGuest(member string) error {
	mount, e := l.MountRoot(member, false)
	if e != nil {
		return e
	}
	stageErr := func() error {
		if e := CheckManagedGuestTools(mount); e != nil {
			return e
		}
		for _, copy := range [][2]string{{"go_host_test", "/opt/ts-managed-member/host.test"}, {"tb_server", "/opt/ts-managed-member/tb-server"}} {
			input := l.Manifest.Inputs[copy[0]]
			if e = l.Install(mount, input.Path, copy[1], "0755", "root"); e != nil {
				return e
			}
			h, e := l.StagedSHA256(mount, copy[1])
			if e != nil {
				return e
			}
			if h != input.SHA256 {
				return fmt.Errorf("%s: staged %s changed", member, copy[0])
			}
		}
		inputs := l.Manifest.Members[member].Inputs
		if e = l.StageManagedMaterial(mount, member, inputs); e != nil {
			return e
		}
		if e := l.stageS3Credentials(mount, member); e != nil {
			return e
		}
		caDest := "/usr/local/share/ca-certificates/ts-managed-rustfs.crt"
		if e = l.Install(mount, l.FixtureCA, caDest, "0644", "root"); e != nil {
			return e
		}
		h, e := l.StagedSHA256(mount, caDest)
		if e != nil {
			return e
		}
		expected, e := DirectDigest(l.FixtureCA)
		if e != nil {
			return e
		}
		if h != expected {
			return fmt.Errorf("%s: RustFS CA staging changed", member)
		}
		hostsPath, e := GuestPath(mount, "/etc/hosts")
		if e != nil {
			return e
		}
		s, e := os.Lstat(hostsPath)
		if e != nil {
			return e
		}
		if !s.Mode().IsRegular() {
			return fmt.Errorf("%s: guest hosts file is not regular", member)
		}
		b, e := os.ReadFile(hostsPath)
		if e != nil {
			return e
		}
		hosts := string(b)
		if strings.Contains(hosts, S3Host) {
			return fmt.Errorf("%s: guest hosts already defines RustFS name", member)
		}
		source, e := l.StageText(member+"-hosts", strings.TrimRight(hosts, "\n")+"\n10.77.39.1 "+S3Host+"\n", 0o644)
		if e != nil {
			return e
		}
		if e = l.Install(mount, source, "/etc/hosts", "0644", "root"); e != nil {
			return e
		}
		if _, e = l.cmd(member+"-update-ca", []string{"chroot", mount, "/usr/sbin/update-ca-certificates"}, true, 60*time.Second); e != nil {
			return e
		}
		caBundle, e := GuestPath(mount, "/etc/ssl/certs/ca-certificates.crt")
		if e != nil {
			return e
		}
		if _, e = l.cmd(member+"-verify-ca", []string{"openssl", "verify", "-CAfile", caBundle, l.FixtureCA}, false, 15*time.Second); e != nil {
			return e
		}
		for _, copy := range [][2]string{{"client_api_token", "client-api-token"}, {"client_https_ca_pem", "client-https-ca.pem"}} {
			destination := "/opt/ts-managed-member/" + copy[1]
			input := inputs[copy[0]]
			if e = l.Install(mount, input.Path, destination, "0600", "root"); e != nil {
				return e
			}
			h, e := l.StagedSHA256(mount, destination)
			if e != nil {
				return e
			}
			if h != input.SHA256 {
				return fmt.Errorf("%s: staged %s changed", member, copy[0])
			}
		}
		config := object(strictToJSON(l.Manifest.Members[member].Config))
		for k, v := range (Object{"artifact_path": "/opt/ts-managed-member/tb-server", "artifact_sha256": l.Manifest.Inputs["tb_server"].SHA256, "control_address": ManagedGuestIPs[member] + ":9540", "control_host_ip": "10.77.39.1", "control_token": l.Tokens[member], "client_root_path": "/opt/ts-managed-member/client-https-ca.pem", "client_root_sha256": inputs["client_https_ca_pem"].SHA256, "client_token_path": "/opt/ts-managed-member/client-api-token", "client_token_sha256": inputs["client_api_token"].SHA256}) {
			config[k] = v
		}
		b, e = json.Marshal(config, json.Deterministic(true))
		if e != nil {
			return e
		}
		configFile, e := l.StageText(member+"-guest-config.json", string(b)+"\n", 0o600)
		if e != nil {
			return e
		}
		if e = l.Install(mount, configFile, "/etc/ts-managed-member/guest-config.json", "0600", "root"); e != nil {
			return e
		}
		for _, text := range [][3]string{{member + "-volume-setup.sh", ManagedVolumeSetupScript(member), "/usr/local/sbin/ts-managed-member-volume-setup"}, {member + "-runner.sh", ManagedRunnerScript(member), "/usr/local/sbin/ts-managed-member-runner"}, {member + "-volume-setup.service", ManagedSetupUnit, "/etc/systemd/system/ts-managed-member-volume-setup.service"}, {member + "-test.service", ManagedTestUnit, "/etc/systemd/system/ts-managed-member-test.service"}, {member + "-system-slice-memory.conf", ManagedSystemSliceReservation, "/etc/systemd/system/system.slice.d/50-ts-managed-member-memory.conf"}, {member + "-network.conf", "[Match]\nMACAddress=" + ManagedGuestMACs[member] + "\n\n[Network]\nAddress=" + ManagedGuestIPs[member] + "/24\n", "/etc/systemd/network/80-ts-managed-member.network"}, {member + "-cloud-init.disabled", "", "/etc/cloud/cloud-init.disabled"}} {
			source, e := l.StageText(text[0], text[1], 0o600)
			if e != nil {
				return e
			}
			mode := "0644"
			if strings.HasSuffix(text[0], ".sh") {
				mode = "0755"
			}
			if e = l.Install(mount, source, text[2], mode, "root"); e != nil {
				return e
			}
		}
		for _, unit := range []string{"ts-managed-member-volume-setup.service", "ts-managed-member-test.service"} {
			if e = l.EnableUnit(mount, unit); e != nil {
				return e
			}
		}
		l.Note("guest_staged", Object{"member": member, "guest_config_sha256": hashBytes(b), "artifact_sha256": l.Manifest.Inputs["tb_server"].SHA256})
		return nil
	}()
	return errors.Join(stageErr, l.UnmountRoot(member))
}

func (l *ManagedLab) stageS3Credentials(mount, member string) error {
	keys, e := S3Credentials(l.S3CredentialPaths)
	if e != nil {
		return e
	}
	if l.S3KeyHashes != ([2]string{hashBytes([]byte(keys[0])), hashBytes([]byte(keys[1]))}) {
		return errors.New("S3 fixture credentials changed after RustFS startup")
	}
	for i, destination := range []string{"/etc/ts-managed-member/s3-access-key-id", "/etc/ts-managed-member/s3-secret-access-key"} {
		if e = l.Install(mount, l.S3CredentialPaths[i], destination, "0600", "root"); e != nil {
			return e
		}
		h, e := l.StagedSHA256(mount, destination)
		if e != nil {
			return e
		}
		if h != l.S3KeyHashes[i] {
			return fmt.Errorf("%s: staged S3 credential changed: %s", member, destination)
		}
		target, e := GuestPath(mount, destination)
		if e != nil {
			return e
		}
		if _, e = l.cmd(member+"-verify-"+filepath.Base(destination), []string{"cmp", "-s", "--", l.S3CredentialPaths[i], target}, true, 15*time.Second); e != nil {
			return e
		}
	}
	return nil
}

func CheckManagedSubnetCollision(ctx context.Context, command CommandFunc) error {
	subnet := netip.MustParsePrefix("10.77.39.0/24")
	for _, kind := range []string{"route", "addr"} {
		argv := []string{"ip", "-j", kind, "show"}
		if kind == "route" {
			argv = append(argv, "table", "all")
		}
		r, e := command(ctx, argv, CommandOptions{Timeout: 10 * time.Second})
		if e != nil {
			return e
		}
		v, e := decode(r.Stdout)
		if e != nil {
			return e
		}
		if kind == "route" {
			for _, row := range array(v) {
				s := str(object(row)["dst"])
				if s == "" || s == "default" {
					continue
				}
				p, e := netip.ParsePrefix(s)
				if e != nil {
					if a, e := netip.ParseAddr(s); e == nil {
						p = netip.PrefixFrom(a, a.BitLen())
					} else {
						continue
					}
				}
				if p.Overlaps(subnet) {
					return fmt.Errorf("fixture subnet collides with host route %s", s)
				}
			}
		} else {
			for _, row := range array(v) {
				for _, raw := range array(object(row)["addr_info"]) {
					a := object(raw)
					if a["family"] != "inet" {
						continue
					}
					p, e := netip.ParsePrefix(fmt.Sprintf("%s/%d", str(a["local"]), integer(a["prefixlen"])))
					if e != nil {
						return e
					}
					if p.Overlaps(subnet) {
						return fmt.Errorf("fixture subnet collides with host address %s", p.Masked())
					}
				}
			}
		}
	}
	return nil
}
func ManagedPrerequisites(ctx context.Context) error {
	for _, name := range []string{"sudo", "ip", "mount", "umount", "install", "ln", "cp", "cmp", "e2fsck", "resize2fs", "blkid", "sha256sum", "stat", "chroot", "openssl", "curl", "podman"} {
		if _, e := exec.LookPath(name); e != nil {
			return fmt.Errorf("host commands missing: %s", name)
		}
	}
	if e := unix.Access("/dev/kvm", unix.R_OK|unix.W_OK); e != nil {
		return errors.New("Firecracker requires /dev/kvm and /dev/net/tun")
	}
	if _, e := os.Stat("/dev/net/tun"); e != nil {
		return errors.New("Firecracker requires /dev/kvm and /dev/net/tun")
	}
	return CheckManagedSubnetCollision(ctx, Execute)
}
func (l *ManagedLab) Network() error {
	command := l.Command
	if command == nil {
		command = Execute
	}
	if e := CheckManagedSubnetCollision(l.Ctx, command); e != nil {
		if pending, ok := errors.AsType[*PendingCommandError](e); ok {
			l.pendingCommands = append(l.pendingCommands, managedPendingCommand{label: "network-collision-probe", process: pending.Process})
		}
		return e
	}
	if e := l.createOwnedLink("bridge-add", l.Bridge, []string{"ip", "link", "add", "name", l.Bridge, "type", "bridge"}); e != nil {
		return e
	}
	for _, command := range []struct {
		label string
		args  []string
	}{{"bridge-address", []string{"ip", "addr", "add", "10.77.39.1/24", "dev", l.Bridge}}, {"bridge-up", []string{"ip", "link", "set", l.Bridge, "up"}}} {
		if _, e := l.cmd(command.label, command.args, true, 120*time.Second); e != nil {
			return e
		}
	}
	for _, member := range []string{"a", "b"} {
		tap := l.Taps[member]
		if e := l.createOwnedLink("tap-"+member+"-add", tap, []string{"ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", strconv.Itoa(os.Getuid())}); e != nil {
			return e
		}
		for _, command := range []struct {
			label string
			args  []string
		}{{"tap-" + member + "-master", []string{"ip", "link", "set", tap, "master", l.Bridge}}, {"tap-" + member + "-up", []string{"ip", "link", "set", tap, "up"}}} {
			if _, e := l.cmd(command.label, command.args, true, 120*time.Second); e != nil {
				return e
			}
		}
	}
	l.Note("private_network", Object{"bridge": l.Bridge, "taps": l.Taps, "subnet": "10.77.39.0/24"})
	return nil
}

func (l *ManagedLab) linkExists(name string) (bool, error) {
	output, e := l.cmd("probe-"+name, []string{"ip", "-json", "link", "show"}, false, 30*time.Second)
	if e != nil {
		return false, e
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if e := json.Unmarshal([]byte(output), &links); e != nil {
		return false, fmt.Errorf("probe owned link %s: %w", name, e)
	}
	for _, link := range links {
		if link.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (l *ManagedLab) createOwnedLink(label, name string, argv []string) error {
	exists, e := l.linkExists(name)
	if e != nil {
		return e
	}
	if exists {
		return fmt.Errorf("private link name already exists: %s", name)
	}
	// Record the absent randomized name before dispatch: a canceled helper can
	// return after the kernel mutation, or remain pending until cleanup retries.
	l.CreatedLinks = append(l.CreatedLinks, name)
	_, e = l.cmd(label, argv, true, 120*time.Second)
	return e
}
func (l *ManagedLab) StartRustFS() error {
	keys, e := S3Credentials(l.S3CredentialPaths)
	if e != nil {
		return e
	}
	l.S3KeyHashes = [2]string{hashBytes([]byte(keys[0])), hashBytes([]byte(keys[1]))}
	tls := filepath.Join(l.Fixture, "tls")
	if e = os.Mkdir(tls, 0o755); e != nil {
		return e
	}
	caKey, leafKey, leafCert, csr := filepath.Join(l.Fixture, "ca.key"), filepath.Join(tls, "rustfs_key.pem"), filepath.Join(tls, "rustfs_cert.pem"), filepath.Join(l.Fixture, "leaf.csr")
	extension, e := l.StageText("rustfs-leaf.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"+S3Host+"\n", 0o600)
	if e != nil {
		return e
	}
	for _, command := range []struct {
		label string
		args  []string
	}{{"rustfs-ca", []string{"openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1", "-subj", "/CN=TerraBase managed member RustFS CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", caKey, "-out", l.FixtureCA}}, {"rustfs-leaf-request", []string{"openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=" + S3Host, "-keyout", leafKey, "-out", csr}}, {"rustfs-leaf-sign", []string{"openssl", "x509", "-req", "-sha256", "-days", "1", "-in", csr, "-CA", l.FixtureCA, "-CAkey", caKey, "-CAcreateserial", "-extfile", extension, "-out", leafCert}}} {
		if _, e = l.cmd(command.label, command.args, false, 30*time.Second); e != nil {
			return e
		}
	}
	for _, file := range []string{leafCert, leafKey} {
		if e = os.Chmod(file, 0o644); e != nil {
			return e
		}
	}
	auth := filepath.Join(l.Fixture, "curl.conf")
	if e = os.WriteFile(auth, []byte(fmt.Sprintf("aws-sigv4 = \"aws:amz:%s:s3\"\nuser = \"%s:%s\"\n", S3Region, keys[0], keys[1])), 0o600); e != nil {
		return e
	}
	location, e := l.StageText("rustfs-bucket-location.xml", "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>"+S3Region+"</LocationConstraint></CreateBucketConfiguration>", 0o600)
	if e != nil {
		return e
	}
	env := append(os.Environ(), "RUSTFS_ACCESS_KEY="+keys[0], "RUSTFS_SECRET_KEY="+keys[1], "RUSTFS_TLS_PATH=/opt/tls", "RUSTFS_ADDRESS=10.77.39.1:9000", "RUSTFS_REGION="+S3Region, "RUSTFS_CONSOLE_ENABLE=false")
	l.RustFSStarted = true
	if _, e = l.RunCommand("rustfs-create", []string{"podman", "create", "--pull=missing", "--name", l.RustFSName, "--network", "host", "--memory", "1073741824", "--env", "RUSTFS_ACCESS_KEY", "--env", "RUSTFS_SECRET_KEY", "--env", "RUSTFS_TLS_PATH", "--env", "RUSTFS_ADDRESS", "--env", "RUSTFS_REGION", "--env", "RUSTFS_CONSOLE_ENABLE", RustFSImage}, false, 120*time.Second, []int{0}, env); e != nil {
		return e
	}
	if _, e = l.cmd("rustfs-copy-tls", []string{"podman", "cp", tls + "/.", l.RustFSName + ":/opt/tls"}, false, 30*time.Second); e != nil {
		return e
	}
	if _, e = l.cmd("rustfs-start", []string{"podman", "start", l.RustFSName}, false, 30*time.Second); e != nil {
		return e
	}
	bucket := str(l.Manifest.Members["a"].S3["bucket"])
	curl := []string{"curl", "--silent", "--show-error", "--noproxy", "*", "--cacert", l.FixtureCA, "--resolve", S3Host + ":9000:10.77.39.1", "--config", auth, "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "2"}
	url := S3Endpoint + "/" + bucket
	ready := false
	for attempt := range 60 {
		output, e := l.RunCommand(fmt.Sprintf("rustfs-ready-%d", attempt), append(slices.Clone(curl), "--head", url), false, 5*time.Second, []int{0, 7, 28}, nil)
		if e != nil {
			return e
		}
		status := tail(strings.TrimSpace(output), 3)
		if status == "404" {
			ready = true
			break
		}
		if !slices.Contains([]string{"000", "500", "502", "503", "504"}, status) {
			return fmt.Errorf("RustFS authenticated bucket absence returned HTTP %s", status)
		}
		select {
		case <-l.Ctx.Done():
			return l.Ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if !ready {
		return errors.New("RustFS authenticated HTTPS readiness timed out")
	}
	output, e := l.cmd("rustfs-create-bucket", append(slices.Clone(curl), "--max-time", "10", "--request", "PUT", "--header", "Content-Type: application/xml", "--data-binary", "@"+location, url), false, 15*time.Second)
	if e != nil {
		return e
	}
	if status := strings.TrimSpace(output); status != "200" && status != "201" {
		return fmt.Errorf("RustFS bucket creation returned HTTP %s", status)
	}
	output, e = l.cmd("rustfs-check-bucket", append(slices.Clone(curl), "--head", url), false, 5*time.Second)
	if e != nil {
		return e
	}
	if strings.TrimSpace(output) != "200" {
		return fmt.Errorf("RustFS authenticated bucket probe returned HTTP %s", output)
	}
	h, e := DirectDigest(l.FixtureCA)
	if e != nil {
		return e
	}
	l.Note("rustfs_ready", Object{"endpoint": S3Endpoint, "bucket": bucket, "ca_sha256": h})
	return nil
}
func (l *ManagedLab) StartVMs() error {
	if e := l.RecheckInputs(); e != nil {
		return e
	}
	directory, e := os.MkdirTemp("/tmp", "tsmm-")
	if e != nil {
		return e
	}
	l.SocketDir = directory
	if e = os.Chmod(directory, 0o700); e != nil {
		return e
	}
	if len(filepath.Join(directory, "a.sock")) >= 100 {
		return errors.New("private Firecracker socket directory is too long")
	}
	for _, member := range []string{"a", "b"} {
		vm := &ManagedVM{Lab: l, Member: member, Socket: filepath.Join(directory, member+".sock")}
		l.VMs[member] = vm
		if e = vm.Start(); e != nil {
			return e
		}
	}
	return nil
}
func (l *ManagedLab) Exercise() error {
	binding := l.Manifest.Members["a"].Config
	aBefore, e := l.WaitEvidence("a", 180*time.Second)
	if e != nil {
		return e
	}
	bBefore, e := l.WaitEvidence("b", 180*time.Second)
	if e != nil {
		return e
	}
	l.Note("members_ready", Object{"a": aBefore, "b": bBefore})
	durableKey, appliedKey := `terrabase_replication_acks_total{stage="durable"}`, `terrabase_replication_acks_total{stage="applied"}`
	durableBefore, e := ManagedMetric(object(bBefore["metrics"]), durableKey, false)
	if e != nil {
		return e
	}
	appliedBefore, e := ManagedMetric(object(bBefore["metrics"]), appliedKey, false)
	if e != nil {
		return e
	}
	status, absent, e := l.Request("b", "GET", "/read")
	if e != nil {
		return e
	}
	body := object(absent["body"])
	if status != 200 || !exactFields(absent, []string{"status", "body"}) || integer(absent["status"]) != 200 || integer(body["version"]) != 1 || body["state"] != "absent" || !jsonEqual(body["context"], []any{}) || !jsonEqual(body["siblings"], []any{}) {
		return fmt.Errorf("B's pinned document was not absent before A wrote it: %v", absent)
	}
	l.Note("https_peer_absent_before_write", Object{"member": "b", "status": 200, "point": body, "document_id": binding["document_id"]})
	status, write, e := l.Request("a", "POST", "/write")
	if e != nil {
		return e
	}
	writeBody := object(write["body"])
	if status != 200 || !exactFields(write, []string{"status", "body"}) || integer(write["status"]) != 200 || writeBody["durability"] != "local_durable" {
		return fmt.Errorf("A local HTTPS write did not return local_durable: %v", write)
	}
	for _, key := range []string{"received", "applied", "remote_ack"} {
		if _, ok := writeBody[key]; ok {
			return errors.New("local durable receipt incorrectly claimed peer durability")
		}
	}
	l.Note("https_write", Object{"member": "a", "status": 200, "receipt": writeBody})
	deadline := time.Now().Add(90 * time.Second)
	last := "no read"
	readReady := false
	for time.Now().Before(deadline) {
		status, read, e := l.Request("b", "GET", "/read")
		if e != nil {
			return e
		}
		body := object(read["body"])
		siblings := array(body["siblings"])
		if status == 200 && exactFields(read, []string{"status", "body"}) && integer(read["status"]) == 200 && integer(body["version"]) == 1 && body["state"] == "value" && len(siblings) == 1 {
			value := object(siblings[0])
			generation, _ := integerExact(binding["schema_generation"])
			if value["kind"] == "live" && jsonEqual(value["document"], Object{}) && value["schema_generation"] == strconv.FormatUint(generation, 10) && value["schema_digest"] == binding["schema_digest"] {
				l.Note("https_peer_read", Object{"member": "b", "status": 200, "point": body, "document_id": binding["document_id"]})
				readReady = true
				break
			}
		}
		last = fmt.Sprintf("HTTP %d: %v", status, read)
		select {
		case <-l.Ctx.Done():
			return l.Ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !readReady {
		return fmt.Errorf("B did not read A's committed document: %s", last)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		a, e := l.WaitEvidence("a", 10*time.Second)
		if e != nil {
			return e
		}
		b, e := l.WaitEvidence("b", 10*time.Second)
		if e != nil {
			return e
		}
		durable, e := ManagedMetric(object(b["metrics"]), durableKey, false)
		if e != nil {
			return e
		}
		applied, e := ManagedMetric(object(b["metrics"]), appliedKey, false)
		if e != nil {
			return e
		}
		connected, e := ManagedMetric(object(a["metrics"]), "terrabase_replication_sender_connected", true)
		if e != nil {
			return e
		}
		durableLag, e := ManagedMetric(object(a["metrics"]), "terrabase_replication_sender_durable_lag_events", true)
		if e != nil {
			return e
		}
		appliedLag, e := ManagedMetric(object(a["metrics"]), "terrabase_replication_sender_applied_lag_events", true)
		if e != nil {
			return e
		}
		if durable > durableBefore && applied > appliedBefore && connected == 1 && durableLag == 0 && appliedLag == 0 {
			l.Note("peer_acks_observed", Object{"receiver_before": Object{"durable": durableBefore, "applied": appliedBefore}, "receiver_after": Object{"durable": durable, "applied": applied}, "source": Object{"connected": connected, "durable_lag": durableLag, "applied_lag": appliedLag}, "a": a, "b": b})
			return nil
		}
		select {
		case <-l.Ctx.Done():
			return l.Ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("peer read succeeded but durable/applied ACK delta or source lag evidence was absent")
}
func (l *ManagedLab) FinishGuests() error {
	for _, member := range []string{"a", "b"} {
		status, _, e := l.Request(member, "POST", "/finish")
		if e != nil {
			return e
		}
		if status != 204 {
			return fmt.Errorf("%s: guest refused finish signal", member)
		}
	}
	for _, member := range []string{"a", "b"} {
		if e := l.VMs[member].NaturalExit(); e != nil {
			return e
		}
	}
	return nil
}
func (l *ManagedLab) CollectResults() error {
	for _, member := range []string{"a", "b"} {
		mount, e := l.MountRoot(member, true)
		if e != nil {
			return e
		}
		collectErr := func() error {
			source, e := GuestPath(mount, "/var/log/ts-managed-member/go-host-test.log")
			if e != nil {
				return e
			}
			s, e := os.Lstat(source)
			if e != nil {
				return e
			}
			if !s.Mode().IsRegular() || s.Size() == 0 || s.Size() > 32<<20 {
				return fmt.Errorf("%s: guest test log missing or oversized", member)
			}
			target := filepath.Join(l.Logs, member+"-go-host-test.log")
			if _, e = l.cmd("copy-"+member+"-guest-log", []string{"install", "-o", strconv.Itoa(os.Getuid()), "-g", strconv.Itoa(os.Getgid()), "-m", "0600", source, target}, true, 120*time.Second); e != nil {
				return e
			}
			b, e := os.ReadFile(target)
			if e != nil {
				return e
			}
			if int64(len(b)) != s.Size() {
				return fmt.Errorf("%s: copied guest log length changed", member)
			}
			serial, e := os.ReadFile(filepath.Join(l.Logs, member+"-serial.log"))
			if e != nil {
				return e
			}
			if e = ParseManagedTestResult(member, string(b), string(serial)); e != nil {
				return e
			}
			l.Note("guest_result", Object{"member": member, "log_sha256": hashBytes(b), "status": "PASS"})
			return nil
		}()
		if e = errors.Join(collectErr, l.UnmountRoot(member)); e != nil {
			return e
		}
	}
	return nil
}
func (l *ManagedLab) Cleanup() {
	original := l.Ctx
	l.Ctx = context.WithoutCancel(l.Ctx)
	defer func() { l.Ctx = original }()
	remaining := l.pendingCommands[:0]
	for _, pending := range l.pendingCommands {
		if e := pending.process.Stop(10*time.Second, true); e != nil && !pending.process.Reaped {
			l.CleanupErrors = append(l.CleanupErrors, fmt.Sprintf("stop pending command %s (log %s): %v", pending.label, pending.path, e))
			remaining = append(remaining, pending)
		} else if e != nil {
			l.CleanupErrors = append(l.CleanupErrors, fmt.Sprintf("finish pending command %s: %v", pending.label, e))
		}
	}
	l.pendingCommands = remaining
	for _, vm := range l.VMs {
		l.CleanupErrors = append(l.CleanupErrors, vm.Stop()...)
	}
	if len(l.pendingCommands) > 0 {
		l.CleanupErrors = append(l.CleanupErrors, "private network, images, mounts and fixture retained while commands may still be live")
		return
	}
	if l.RustFSStarted {
		_, e := l.RunCommand("rustfs-stop", []string{"podman", "rm", "--force", "--volumes", l.RustFSName}, false, 30*time.Second, []int{0, 1}, nil)
		if e == nil {
			_, e = l.RunCommand("rustfs-removed", []string{"podman", "container", "exists", l.RustFSName}, false, 10*time.Second, []int{1}, nil)
		}
		if e != nil {
			l.CleanupErrors = append(l.CleanupErrors, "remove RustFS fixture: "+e.Error())
		} else {
			l.RustFSStarted = false
		}
	}
	for member := range l.Mounted {
		if len(l.pendingCommands) > 0 {
			break
		}
		if e := l.UnmountRoot(member); e != nil {
			l.CleanupErrors = append(l.CleanupErrors, "unmount "+member+": "+e.Error())
		}
	}
	stopped := true
	for _, vm := range l.VMs {
		if !vm.Stopped {
			stopped = false
		}
	}
	if !stopped || l.RustFSStarted || len(l.pendingCommands) > 0 {
		l.CleanupErrors = append(l.CleanupErrors, "private network retained while a VM, RustFS or command may still be live")
	} else {
		for i := len(l.CreatedLinks) - 1; i >= 0; i-- {
			if len(l.pendingCommands) > 0 {
				break
			}
			link := l.CreatedLinks[i]
			exists, e := l.linkExists(link)
			if e != nil {
				l.CleanupErrors = append(l.CleanupErrors, "probe owned link "+link+": "+e.Error())
				continue
			}
			if !exists {
				l.CreatedLinks = slices.Delete(l.CreatedLinks, i, i+1)
				continue
			}
			if _, e := l.cmd("remove-"+link, []string{"ip", "link", "del", "dev", link}, true, 120*time.Second); e != nil {
				l.CleanupErrors = append(l.CleanupErrors, "remove owned link "+link+": "+e.Error())
			} else {
				l.CreatedLinks = slices.Delete(l.CreatedLinks, i, i+1)
			}
		}
	}
	if l.SocketDir != "" {
		if !stopped || len(l.pendingCommands) > 0 {
			l.CleanupErrors = append(l.CleanupErrors, "private API sockets retained while a VM may still be live")
		} else {
			entries, e := os.ReadDir(l.SocketDir)
			if e == nil {
				for _, entry := range entries {
					info, se := entry.Info()
					if se != nil {
						e = se
						break
					}
					if info.Mode()&os.ModeSocket == 0 || !slices.Contains([]string{"a.sock", "b.sock"}, entry.Name()) {
						e = fmt.Errorf("unexpected API socket entry %s", entry.Name())
						break
					}
					if e = os.Remove(filepath.Join(l.SocketDir, entry.Name())); e != nil {
						break
					}
				}
			}
			if e == nil {
				e = os.Remove(l.SocketDir)
			}
			if e != nil {
				l.CleanupErrors = append(l.CleanupErrors, "remove private API socket directory: "+e.Error())
			}
		}
	}
	if len(l.Mounted) == 0 && stopped && !l.RustFSStarted && len(l.pendingCommands) == 0 {
		for _, member := range []string{"a", "b"} {
			if e := removeMissing(filepath.Join(l.Images, member+"-rootfs.ext4")); e != nil {
				l.CleanupErrors = append(l.CleanupErrors, "remove private rootfs: "+e.Error())
			}
		}
		if l.Failure == "" && len(l.CleanupErrors) == 0 {
			for _, member := range []string{"a", "b"} {
				if e := removeMissing(filepath.Join(l.Images, member+"-volume.ext4")); e != nil {
					l.CleanupErrors = append(l.CleanupErrors, "remove private volume: "+e.Error())
				}
			}
		}
		l.Note("private_rootfs_removed", Object{})
	} else {
		l.CleanupErrors = append(l.CleanupErrors, "private rootfs with S3 credentials could not be removed")
	}
	if !l.RustFSStarted && len(l.pendingCommands) == 0 {
		if e := os.RemoveAll(l.Fixture); e != nil {
			l.CleanupErrors = append(l.CleanupErrors, "remove RustFS TLS and auth files: "+e.Error())
		}
	}
}
func (l *ManagedLab) Run() (Object, error) {
	if e := l.PrepareDirs(); e != nil {
		return nil, e
	}
	var failure error
	steps := []struct {
		name string
		run  func() error
	}{{"recheck_inputs", l.RecheckInputs}, {"copy_images", l.CopyImages}, {"network", l.Network}, {"start_rustfs", l.StartRustFS}, {"stage_a", func() error { return l.StageGuest("a") }}, {"stage_b", func() error { return l.StageGuest("b") }}, {"start_vms", l.StartVMs}, {"exercise", l.Exercise}, {"finish_guests", l.FinishGuests}, {"collect_results", l.CollectResults}}
	for _, step := range steps {
		if l.Step != nil {
			failure = l.Step(step.name, step.run)
		} else {
			failure = step.run()
		}
		if failure != nil {
			break
		}
	}

	if failure != nil {
		l.Failure = failure.Error()
		l.Note("failure", Object{"detail": l.Failure})
	}
	changed := Object{}
	if l.NativeProvenance.ExecutableSHA256 != "" {
		if e := l.NativeProvenance.VerifyExecutable(); e != nil {
			l.Failure = strings.Trim(l.Failure+"; "+e.Error(), "; ")
			failure = errors.Join(failure, e)
			l.Note("executable_changed", Object{"detail": e.Error()})
		}
	}
	for name, path := range l.SourcePaths {
		current, e := DirectDigest(path)
		if e != nil {
			current = "missing"
		}
		if current != l.SourceHashes[name] {
			changed[name] = Object{"initial": l.SourceHashes[name], "observed": current}
		}
	}
	if len(changed) > 0 {
		l.Failure = strings.Trim(l.Failure+"; local qualification source changed", "; ")
		failure = errors.Join(failure, errors.New("local qualification source changed"))
		l.Note("source_changed", Object{"files": changed})
	}
	l.Cleanup()
	outcome := "PASS"
	if len(l.CleanupErrors) > 0 {
		outcome = "CLEANUP_FAILED"
	} else if l.Failure != "" {
		outcome = "FAILED"
	}
	logs := Object{}
	for _, member := range []string{"a", "b"} {
		logs[member] = Object{"serial": filepath.Join(l.Logs, member+"-serial.log"), "vmm": filepath.Join(l.Logs, member+"-vmm.log"), "go_test": filepath.Join(l.Logs, member+"-go-host-test.log")}
	}
	summary := Object{"schema_version": 1, "profile": ManagedMemberProfile, "outcome": outcome, "failure": l.Failure, "cleanup_errors": l.CleanupErrors, "manifest_sha256": l.Manifest.SHA256, "source_commits": l.Manifest.Commits, "local_source_hashes": l.SourceHashes, "native_provenance": l.NativeProvenance, "started_at": l.StartedAt, "finished_at": time.Now().UTC(), "run_dir": l.Root, "events": l.Events, "logs": logs}
	target := filepath.Join(l.Root, "summary.json")
	if e := writeJSON(target+".tmp", summary); e != nil {
		return summary, e
	}
	if e := os.Rename(target+".tmp", target); e != nil {
		return summary, e
	}
	if l.Stdout != nil {
		b, _ := json.Marshal(Object{"outcome": outcome, "summary": target, "failure": l.Failure})
		fmt.Fprintln(l.Stdout, string(b))
	}
	if outcome != "PASS" {
		failure = errors.Join(failure, fmt.Errorf("qualification %s: cleanup %v", outcome, l.CleanupErrors))
	}
	return summary, failure
}
func RunManagedMember(ctx context.Context, args []string, out, errout io.Writer) error {
	if len(args) == 0 || !slices.Contains([]string{"check", "run"}, args[0]) {
		return errors.New("managedmember requires check or run")
	}
	action := args[0]
	f := flag.NewFlagSet("qualification firecracker managedmember", flag.ContinueOnError)
	f.SetOutput(errout)
	var manifestPath, runDir, sourceRoot string
	var credentials [2]string
	f.StringVar(&manifestPath, "manifest", "", "immutable signed fixture manifest")
	f.StringVar(&runDir, "run-dir", "", "absolute new durable evidence directory")
	f.StringVar(&sourceRoot, "source-root", ".", "repository source root")
	f.StringVar(&credentials[0], "s3-access-key-file", "", "private S3 access key file")
	f.StringVar(&credentials[1], "s3-secret-key-file", "", "private S3 secret key file")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if manifestPath == "" {
		return errors.New("--manifest is required")
	}
	m, e := LoadManagedManifest(manifestPath)
	if e != nil {
		return e
	}
	if e = ManagedPrerequisites(ctx); e != nil {
		return e
	}
	if action == "check" {
		b, _ := json.Marshal(Object{"profile": ManagedMemberProfile, "manifest_sha256": m.SHA256, "status": "CHECK_PASS"})
		fmt.Fprintln(out, string(b))
		return nil
	}
	s, e := os.Stat(filepath.Dir(runDir))
	if runDir == "" || !filepath.IsAbs(runDir) || e != nil || !s.IsDir() {
		return errors.New("run requires an absolute new --run-dir under an existing parent")
	}
	if credentials[0] == "" || credentials[1] == "" {
		return errors.New("run requires both private S3 credential file paths")
	}
	if _, e = S3Credentials(credentials); e != nil {
		return e
	}
	sourceRoot, e = filepath.Abs(sourceRoot)
	if e != nil {
		return e
	}
	l, e := NewManagedLab(ctx, m, runDir, sourceRoot, credentials, out)
	if e != nil {
		return e
	}
	_, e = l.Run()
	return e
}
