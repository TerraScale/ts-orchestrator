package memberstatus

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
)

type Command func(context.Context, string, []string, time.Duration, []int) (int, string, error)
type Qualification struct {
	Manifest                                                                                        Object
	RawManifest                                                                                     []byte
	Inputs                                                                                          map[string]string
	Root, Logs, Commands, Images, MountRoot, Stage, Image, ManagedVolumeImage, MountPath, SocketDir string
	Managed                                                                                         bool
	Events                                                                                          *EventLog
	CommandRunner                                                                                   *CommandRunner
	Command                                                                                         Command
	SudoPath                                                                                        string
	VM                                                                                              *VM
	MountOwned, MountpointOwned                                                                     bool
	IsMounted                                                                                       func(string) bool
	TestResults                                                                                     Object
	Failure                                                                                         string
	CleanupErrors                                                                                   []string
	SourcePaths, SourceHashes, SourceHashesAfter                                                    map[string]string
	SourceStable                                                                                    bool
	StartedAt                                                                                       string
	ctx                                                                                             context.Context
	err                                                                                             error
}

func New(ctx context.Context, m Object, raw []byte, inputs map[string]string, runDir, repoRoot string) (*Qualification, error) {
	q := &Qualification{Manifest: m, RawManifest: raw, Inputs: inputs, Root: runDir, Managed: m["profile"] == ManagedVolumeProfile, ctx: ctx, TestResults: Object{}, CleanupErrors: []string{}, SourcePaths: map[string]string{}, SourceHashes: map[string]string{}, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceStable: true, IsMounted: IsMountPoint}
	q.Logs = filepath.Join(runDir, "logs")
	q.Commands = filepath.Join(runDir, "commands")
	q.Images = filepath.Join(runDir, "images")
	q.MountRoot = filepath.Join(runDir, "mount")
	q.Stage = filepath.Join(runDir, "stage")
	q.Image = filepath.Join(q.Images, "member-status.ext4")
	q.ManagedVolumeImage = filepath.Join(q.Images, "managed-volume.ext4")
	q.MountPath = filepath.Join(q.MountRoot, "guest")
	q.Events = &EventLog{Path: filepath.Join(q.Logs, "events.json")}
	q.CommandRunner = &CommandRunner{Root: runDir, Events: q.Events}
	q.Command = q.CommandRunner.Run
	if repoRoot != "" {
		paths := map[string]string{"tests": "tests/firecracker/memberstatus/main_test.go", "memberstatus_probe_source": "tests/firecracker/memberstatus/main.go", "native_test_support": "internal/testutil/script/script.go", "readme": "tests/firecracker/README.md", "focused_go_test_source": "internal/host/runner_test.go", "shared_runtime": "internal/qualification/firecracker/runtime.go", "go_mod": "go.mod", "go_sum": "go.sum"}
		if q.Managed {
			paths["focused_go_test_source"] = "internal/host/managed_runtime_firecracker_test.go"
		}
		files, e := os.ReadDir(filepath.Join(repoRoot, "internal/qualification/memberstatus"))
		if e != nil {
			return nil, e
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), ".sh") {
				paths["driver/"+f.Name()] = filepath.Join("internal/qualification/memberstatus", f.Name())
			}
		}
		for name, path := range paths {
			path = filepath.Join(repoRoot, path)
			digest, e := firecracker.Digest(path)
			if e != nil {
				return nil, e
			}
			q.SourcePaths[name] = path
			q.SourceHashes[name] = digest
		}
		// Linux exposes the executing inode here even if the executable's
		// original pathname is replaced while qualification is running.
		digest, err := firecracker.Digest("/proc/self/exe")
		if err != nil {
			return nil, err
		}
		q.SourcePaths["driver_binary"] = "/proc/self/exe"
		q.SourceHashes["driver_binary"] = digest
	}
	return q, nil
}
func (q *Qualification) fail(e error) {
	if q.err == nil && e != nil {
		q.err = e
	}
}
func (q *Qualification) Err() error { return q.err }
func (q *Qualification) note(event string, fields Object) {
	q.Events.Add(event, fields)
	q.fail(q.Events.Err)
}
func (q *Qualification) names() []string {
	if q.Managed {
		return ManagedVolumeInputNames
	}
	return InputNames
}
func (q *Qualification) expected(name string) string {
	return str(obj(obj(q.Manifest["inputs"])[name]), "sha256")
}
func (q *Qualification) PrepareDirs() error {
	if e := os.Mkdir(q.Root, 0700); e != nil {
		return e
	}
	for _, path := range []string{q.Logs, q.Commands, q.Images, q.MountRoot, q.Stage} {
		if e := os.Mkdir(path, 0700); e != nil {
			return e
		}
	}
	if e := os.WriteFile(filepath.Join(q.Root, "manifest.json"), q.RawManifest, 0600); e != nil {
		return e
	}
	q.note("qualification_start", Object{"manifest_sha256": shaBytes(q.RawManifest), "source_commits": q.Manifest["source_commits"], "run_dir": q.Root, "profile": q.Manifest["profile"], "go_test_name": q.Manifest["go_test_name"]})
	return q.err
}
func Sudo() (string, error) {
	if info, e := os.Stat("/run/wrappers/bin/sudo"); e == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
		return "/run/wrappers/bin/sudo", nil
	}
	p, e := exec.LookPath("sudo")
	if e != nil {
		return "", fmt.Errorf("sudo is required for scoped mount and staging commands")
	}
	return p, nil
}
func (q *Qualification) run(label string, timeout time.Duration, allowed []int, args ...string) string {
	if q.err != nil {
		return ""
	}
	_, log, e := q.Command(q.ctx, label, args, timeout, allowed)
	q.fail(e)
	return log
}
func (q *Qualification) sudo(label string, timeout time.Duration, args ...string) string {
	if q.err != nil {
		return ""
	}
	path := q.SudoPath
	if path == "" {
		var e error
		path, e = Sudo()
		q.fail(e)
	}
	return q.run(label, timeout, nil, append([]string{path, "-n"}, args...)...)
}
func (q *Qualification) recheckInputs() {
	for _, name := range q.names() {
		if q.err != nil {
			return
		}
		digest, e := firecracker.Digest(q.Inputs[name])
		q.fail(e)
		if digest != q.expected(name) {
			q.fail(fmt.Errorf("input %s changed during qualification", name))
		}
	}
	q.note("inputs_rechecked", nil)
}
func (q *Qualification) CreatePrivateImage() {
	q.run("copy-rootfs", 240*time.Second, nil, "cp", "--reflink=auto", "--sparse=always", q.Inputs["rootfs"], q.Image)
	if q.err != nil {
		return
	}
	q.fail(os.Chmod(q.Image, 0600))
	copied, e := firecracker.Digest(q.Image)
	q.fail(e)
	if copied != q.expected("rootfs") {
		q.fail(fmt.Errorf("private rootfs copy SHA-256 mismatch"))
		return
	}
	info, e := os.Stat(q.Image)
	q.fail(e)
	if q.err != nil {
		return
	}
	size := max(info.Size(), int64(ImageMinBytes))
	q.fail(os.Truncate(q.Image, size))
	q.note("private_image_created", Object{"source": q.Inputs["rootfs"], "image": q.Image, "virtual_size_bytes": size, "copy_sha256": copied})
	q.run("e2fsck", 240*time.Second, []int{0, 1}, "e2fsck", "-f", "-y", q.Image)
	q.run("resize2fs", 240*time.Second, nil, "resize2fs", q.Image)
	if !q.Managed || q.err != nil {
		return
	}
	info, e = os.Stat(q.Inputs["volume_ext4"])
	q.fail(e)
	if q.err != nil {
		return
	}
	if info.Size() != ManagedVolumeImageSizeBytes {
		q.fail(fmt.Errorf("managed volume image must be exactly %d bytes", ManagedVolumeImageSizeBytes))
		return
	}
	q.run("copy-managed-volume", 120*time.Second, nil, "cp", "--reflink=auto", "--sparse=always", q.Inputs["volume_ext4"], q.ManagedVolumeImage)
	if q.err != nil {
		return
	}
	q.fail(os.Chmod(q.ManagedVolumeImage, 0600))
	copied, e = firecracker.Digest(q.ManagedVolumeImage)
	q.fail(e)
	if copied != q.expected("volume_ext4") {
		q.fail(fmt.Errorf("private managed volume copy SHA-256 mismatch"))
		return
	}
	q.run("managed-volume-e2fsck", 120*time.Second, nil, "e2fsck", "-fn", q.ManagedVolumeImage)
	uuidLog := q.run("managed-volume-blkid", 30*time.Second, nil, "blkid", "-s", "UUID", "-o", "value", q.ManagedVolumeImage)
	observed := q.logText(uuidLog)
	if strings.TrimSpace(observed) != str(obj(q.Manifest["managed_volume"]), "filesystem_uuid") {
		q.fail(fmt.Errorf("managed volume UUID mismatch"))
	}
	typeLog := q.run("managed-volume-blkid-type", 30*time.Second, nil, "blkid", "-s", "TYPE", "-o", "value", q.ManagedVolumeImage)
	if strings.TrimSpace(q.logText(typeLog)) != "ext4" {
		q.fail(fmt.Errorf("managed volume filesystem type must be ext4"))
	}
	q.note("private_managed_volume_created", Object{"source": q.Inputs["volume_ext4"], "image": q.ManagedVolumeImage, "filesystem_uuid": ManagedVolumeUUID, "virtual_size_bytes": ManagedVolumeImageSizeBytes})
}
func (q *Qualification) logText(path string) string {
	if q.err != nil {
		return ""
	}
	s, oversized, e := ReadTextBounded(path, MaxCommandLogBytes)
	q.fail(e)
	if oversized {
		q.fail(fmt.Errorf("command log exceeded collection bound"))
	}
	return s
}
func IsMountPoint(path string) bool {
	data, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return true
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return true
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\").Replace(fields[4])
		if mount == absolute {
			return true
		}
	}
	return false
}
func lexists(path string) bool { _, e := os.Lstat(path); return e == nil || !os.IsNotExist(e) }
func (q *Qualification) Mount(readOnly bool) {
	if q.err != nil {
		return
	}
	if lexists(q.MountPath) {
		q.fail(fmt.Errorf("owned mount path unexpectedly exists: %s", q.MountPath))
		return
	}
	q.fail(os.Mkdir(q.MountPath, 0700))
	q.MountpointOwned = q.err == nil
	options, label := "loop", "mount-writable"
	if readOnly {
		options, label = "loop,ro,noload", "mount-readonly"
	}
	q.sudo(label, time.Minute, "mount", "-o", options, q.Image, q.MountPath)
	q.MountOwned = q.IsMounted(q.MountPath)
	if !q.MountOwned {
		q.removeMountpoint()
		q.fail(fmt.Errorf("mount command returned successfully without mounting %s", q.MountPath))
		return
	}
	q.note("image_mounted", Object{"mount": q.MountPath, "read_only": readOnly, "image": q.Image})
}
func (q *Qualification) removeMountpoint() {
	if q.MountpointOwned {
		if e := os.Remove(q.MountPath); e == nil || os.IsNotExist(e) {
			q.MountpointOwned = false
		} else {
			q.fail(e)
		}
	}
}
func (q *Qualification) Unmount() error {
	saved := q.err
	q.err = nil
	ctx := q.ctx
	q.ctx = context.WithoutCancel(ctx)
	defer func() {
		q.ctx = ctx
		if saved != nil {
			q.err = saved
		}
	}()
	if !q.IsMounted(q.MountPath) {
		q.MountOwned = false
		q.removeMountpoint()
		return q.err
	}
	if !q.MountOwned {
		return fmt.Errorf("refusing to unmount unowned mount: %s", q.MountPath)
	}
	q.sudo("umount", time.Minute, "umount", q.MountPath)
	if !q.IsMounted(q.MountPath) {
		q.MountOwned = false
		q.removeMountpoint()
	}
	if q.MountOwned {
		q.fail(fmt.Errorf("owned mount remains active after umount"))
	}
	q.note("image_unmounted", Object{"mount": q.MountPath})
	return q.err
}
func (q *Qualification) stageFile(name, content string, mode os.FileMode) string {
	path := filepath.Join(q.Stage, name)
	if q.err == nil {
		q.fail(os.WriteFile(path, []byte(content), mode))
		if q.err == nil {
			q.fail(os.Chmod(path, mode))
		}
	}
	return path
}
func (q *Qualification) Install(source, destination, mode, group string) {
	target, e := GuestPath(q.MountPath, destination)
	q.fail(e)
	q.sudo("install-"+filepath.Base(destination), time.Minute, "install", "-D", "-o", "root", "-g", group, "-m", mode, source, target)
}
func (q *Qualification) InstallDirectory(destination, mode, group string) {
	target, e := GuestPath(q.MountPath, destination)
	q.fail(e)
	q.sudo("install-dir-"+filepath.Base(destination), 30*time.Second, "install", "-d", "-o", "root", "-g", group, "-m", mode, target)
}
func (q *Qualification) HashStagedGuestFile(label, destination string) string {
	target, e := GuestPath(q.MountPath, destination)
	q.fail(e)
	log := q.sudo(label, time.Minute, "sha256sum", "--zero", "--", target)
	if q.err != nil {
		return ""
	}
	b, e := os.ReadFile(log)
	q.fail(e)
	digest, filename, ok := bytes.Cut(b, []byte("  "))
	if !ok || string(filename) != target+"\x00" || !validHex(string(digest), 64, 64) {
		q.fail(fmt.Errorf("staged guest hash output is malformed for %s", destination))
		return ""
	}
	return string(digest)
}

type Directory struct {
	Guest, Target string
	Mode          os.FileMode
}
type Material struct{ Guest, Target string }

func ManagedDirectories() []Directory {
	return []Directory{{"/srv/ts-managed", "", 0750}, {MemberDir, "", 0750}, {MaterialPath, "", 0750}, {ControlPath, "", 0730}, {MountPath, "", 0750}}
}
func (q *Qualification) LockdownManagedVolumeLayout(dirs []Directory, material []Material) {
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		q.sudo("install-dir-"+filepath.Base(d.Guest), 30*time.Second, "install", "-d", "-o", "root", "-g", "65534", "-m", fmt.Sprintf("%04o", d.Mode), d.Target)
	}
	args := []string{"stat", "-c", "%u:%g:%f", "--"}
	for _, d := range dirs {
		args = append(args, d.Target)
	}
	for _, m := range material {
		args = append(args, m.Target)
	}
	log := q.sudo("verify-managed-volume-layout", 30*time.Second, args...)
	ls := strings.Split(strings.TrimSuffix(q.logText(log), "\n"), "\n")
	if q.err != nil {
		return
	}
	if len(ls) != len(dirs)+len(material) {
		q.fail(fmt.Errorf("managed volume layout stat count mismatch"))
		return
	}
	for i, line := range ls {
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			q.fail(fmt.Errorf("malformed managed volume layout stat"))
			return
		}
		mode, e := strconv.ParseUint(parts[2], 16, 32)
		q.fail(e)
		expected, typeBits := uint64(0440), uint64(0100000)
		guest := ""
		if i < len(dirs) {
			expected, typeBits, guest = uint64(dirs[i].Mode), 0040000, dirs[i].Guest
		} else {
			guest = material[i-len(dirs)].Guest
		}
		if parts[0] != "0" || parts[1] != "65534" || mode&07777 != expected || mode&0170000 != typeBits {
			q.fail(fmt.Errorf("unsafe final managed volume layout at %s", guest))
			return
		}
	}
	q.note("guest_managed_volume_layout_locked", Object{"material_files": len(material), "owner": "root", "group": "65534", "file_mode": "0440"})
}
func (q *Qualification) EnableGuestService(name string) {
	_, e := GuestPath(q.MountPath, "/etc/systemd/system/"+name)
	q.fail(e)
	wants, e := GuestPath(q.MountPath, "/etc/systemd/system/multi-user.target.wants")
	q.fail(e)
	q.sudo("create-service-wants-dir", 30*time.Second, "install", "-d", "-o", "root", "-g", "root", "-m", "0755", wants)
	link, e := GuestPath(q.MountPath, "/etc/systemd/system/multi-user.target.wants/"+name)
	q.fail(e)
	if lexists(link) {
		q.fail(fmt.Errorf("guest service enable path already exists"))
		return
	}
	q.sudo("enable-guest-service-"+name, 30*time.Second, "ln", "-s", "../"+name, link)
}
func (q *Qualification) ValidateGuestRootfs() {
	required := []string{"/usr/lib/systemd/systemd", "/usr/bin/setpriv", "/usr/bin/curl", "/usr/bin/systemctl"}
	if q.Managed {
		required = []string{"/usr/lib/systemd/systemd", "/usr/bin/systemctl", ManagedVolumeBlkidPath, "/usr/bin/findmnt", "/usr/bin/mountpoint", "/usr/bin/readlink"}
	}
	for _, path := range required {
		host, e := GuestPath(q.MountPath, path)
		q.fail(e)
		if q.err != nil {
			return
		}
		info, e := os.Stat(host)
		if e != nil || !info.Mode().IsRegular() {
			q.fail(fmt.Errorf("guest rootfs is missing required probe executable: %s", path))
			return
		}
	}
	text, oversized, e := ReadGuestRegularFile(q.MountPath, "/var/lib/dpkg/status", 16<<20)
	q.fail(e)
	if oversized {
		q.fail(fmt.Errorf("guest package status database exceeded its read bound"))
		return
	}
	version := 0
	for stanza := range strings.SplitSeq(text, "\n\n") {
		fields := map[string]string{}
		for line := range strings.SplitSeq(stanza, "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok {
				fields[k] = v
			}
		}
		if fields["Package"] == "systemd" && fields["Status"] == "install ok installed" {
			m := regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+)(?:\.|-|$)`).FindStringSubmatch(fields["Version"])
			if m != nil {
				version, _ = strconv.Atoi(m[1])
			}
			break
		}
	}
	if version < 255 {
		q.fail(fmt.Errorf("guest requires an installed systemd package at version 255 or newer"))
		return
	}
	q.note("guest_systemd_version", Object{"version": version, "source": "dpkg-status"})
}
func (q *Qualification) StageGuest() {
	q.Mount(false)
	if q.err != nil {
		return
	}
	defer func() {
		if err := q.Unmount(); err != nil {
			q.CleanupErrors = append(q.CleanupErrors, err.Error())
			q.fail(err)
		}
	}()
	q.ValidateGuestRootfs()
	if q.err != nil {
		return
	}
	if q.Managed {
		q.StageManagedVolumeGuest()
		return
	}
	destinations := map[string]string{"go_host_test": "/opt/ts-member-status/go-host-test", "memberstatus_probe": "/opt/ts-member-status/memberstatus-probe", "rust_server": "/opt/ts-member-status/tb-server", "rust_test": "/opt/ts-member-status/rust-test"}
	for _, name := range []string{"go_host_test", "memberstatus_probe", "rust_server", "rust_test"} {
		dest := destinations[name]
		q.Install(q.Inputs[name], dest, "0755", "root")
		if q.err != nil {
			return
		}
		digest, e := firecracker.Digest(filepath.Join(q.MountPath, strings.TrimPrefix(dest, "/")))
		q.fail(e)
		if digest != q.expected(name) {
			q.fail(fmt.Errorf("staged %s SHA-256 mismatch", name))
			return
		}
		q.note("guest_binary_staged", Object{"name": name, "path": dest, "sha256": digest})
	}
	runner := q.stageFile("guest-runner.sh", ShellRunner("/", str(q.Manifest, "rust_test_name")), 0700)
	unit := q.stageFile("guest-unit.service", ServiceUnit(""), 0644)
	q.Install(runner, "/usr/local/sbin/ts-member-status-qualification", "0755", "root")
	q.Install(unit, "/etc/systemd/system/"+ServiceName, "0644", "root")
	q.EnableGuestService(ServiceName)
	q.note("guest_service_staged", Object{"unit": ServiceName, "delegate": true, "delegate_subgroup": "supervisor", "memory_max": "5G", "no_new_privileges": true, "ambient_capabilities": []any{}, "capability_bounding_set": CapabilityBoundingSet})
}
func (q *Qualification) StageManagedVolumeGuest() {
	binary := "/opt/ts-managed-volume-qualification/host.test"
	q.Install(q.Inputs["go_host_test"], binary, "0755", "root")
	if q.err != nil {
		return
	}
	digest, e := firecracker.Digest(filepath.Join(q.MountPath, strings.TrimPrefix(binary, "/")))
	q.fail(e)
	if digest != q.expected("go_host_test") {
		q.fail(fmt.Errorf("staged go_host_test SHA-256 mismatch"))
		return
	}
	dirs := ManagedDirectories()
	for i, d := range dirs {
		target, e := GuestPath(q.MountPath, d.Guest)
		q.fail(e)
		dirs[i].Target = target
		q.sudo("install-dir-"+filepath.Base(d.Guest), 30*time.Second, "install", "-d", "-o", "root", "-g", "65534", "-m", "0755", target)
	}
	names := []string{"authority_tbca", "trusted_public_key", "server_crt", "server_key", "client_ca_pem", "client_managed_manifest", "client_config", "client_chain", "client_private_key", "client_api_keys"}
	destinations := []string{"authority.tbca", "trusted-public-key", "server.crt", "server.key", "client-ca.pem", "client-managed-manifest.json", "client-config.json", "client-chain.pem", "client-private-key.pem", "client-api-keys.json"}
	var materials []Material
	for i, name := range names {
		destination := MaterialPath + "/" + destinations[i]
		q.Install(q.Inputs[name], destination, "0440", "65534")
		target, e := GuestPath(q.MountPath, destination)
		q.fail(e)
		actual := q.HashStagedGuestFile("hash-managed-volume-"+name, destination)
		if actual != q.expected(name) {
			q.fail(fmt.Errorf("staged %s SHA-256 mismatch", name))
			return
		}
		materials = append(materials, Material{destination, target})
		q.note("guest_material_staged", Object{"name": name, "path": destination, "sha256": actual})
	}
	serverCA := MaterialPath + "/server-ca.pem"
	q.Install(q.Inputs["client_ca_pem"], serverCA, "0440", "65534")
	target, e := GuestPath(q.MountPath, serverCA)
	q.fail(e)
	actual := q.HashStagedGuestFile("hash-managed-volume-server-ca", serverCA)
	if actual != q.expected("client_ca_pem") {
		q.fail(fmt.Errorf("staged server-ca.pem differs from the pinned shared fixture CA"))
		return
	}
	materials = append(materials, Material{serverCA, target})
	q.LockdownManagedVolumeLayout(dirs, materials)
	runner := q.stageFile("managed-volume-runner.sh", ManagedVolumeShellRunner("/"), 0700)
	setup := q.stageFile("managed-volume-setup.sh", ManagedVolumeSetupScript(), 0700)
	unit := q.stageFile("managed-volume-unit.service", ServiceUnit(ManagedVolumeUUID), 0644)
	setupUnit := q.stageFile("managed-volume-setup-unit.service", ManagedVolumeSetupUnit(ManagedVolumeUUID), 0644)
	for _, r := range [][3]string{{runner, "/usr/local/sbin/ts-member-status-qualification", "0755"}, {setup, ManagedVolumeSetupScriptPath, "0755"}, {unit, "/etc/systemd/system/" + ServiceName, "0644"}, {setupUnit, "/etc/systemd/system/" + ManagedVolumeSetupService, "0644"}} {
		q.Install(r[0], r[1], r[2], "root")
	}
	q.EnableGuestService(ManagedVolumeSetupService)
	q.EnableGuestService(ServiceName)
	q.note("guest_service_staged", Object{"unit": ServiceName, "delegate": true, "delegate_subgroup": "supervisor", "memory_max": "5G", "no_new_privileges": true, "ambient_capabilities": []any{}, "capability_bounding_set": ManagedVolumeCapabilityBoundingSet, "profile": ManagedVolumeProfile})
}
func (q *Qualification) checkSourceStability() {
	q.SourceHashesAfter = map[string]string{}
	for name, path := range q.SourcePaths {
		digest, e := firecracker.Digest(path)
		if e != nil {
			q.SourceStable = false
			q.Failure += fmt.Sprintf("; local source disappeared during qualification: %s: %v", path, e)
			return
		}
		q.SourceHashesAfter[name] = digest
	}
	q.SourceStable = maps.Equal(q.SourceHashes, q.SourceHashesAfter)
	if !q.SourceStable {
		q.Failure += "; local source files changed during qualification"
		q.note("source_changed_during_qualification", Object{"initial": q.SourceHashes, "observed": q.SourceHashesAfter})
	}
}
