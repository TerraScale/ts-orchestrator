package image

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/runtimepriority"
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func fileHash(path string) (string, error) { return client.SHA256(path) }

type GuestBuildOptions struct {
	Image, KernelRelease, KernelOut, Work, Sysusers, Profile, PriorityRoot, Binary, NativeVerifier, Timesyncd, NetBirdBinary, NetBirdConfig string
	BootstrapRoots                                                                                                                          []string
}

func GuestBuild(ctx context.Context, repo string, o GuestBuildOptions, out io.Writer) (result error) {
	pin, e := client.LoadPin(filepath.Join(repo, "deploy/image/image-inputs.json"))
	if e != nil {
		return e
	}
	architecture, e := binaryArchitecture(o.Binary)
	if e != nil {
		return e
	}
	nativeArchitecture, e := binaryArchitecture(o.NativeVerifier)
	if e != nil {
		return e
	}
	if nativeArchitecture != architecture {
		return errors.New("native verifier and orchestrator architectures differ")
	}
	archive, e := pin.Archive(architecture)
	if e != nil {
		return e
	}
	if e = client.VerifyBinary(o.NetBirdBinary, archive.BinarySHA256, architecture); e != nil {
		return e
	}
	g, e := NewGuest(ctx, o.Image, false, nil)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, g.Close(result != nil)) }()
	if e = auditKernel(g, o.KernelRelease, o.Work, o.KernelOut, architecture, out); e != nil {
		return e
	}
	if e = requireDirectParents(g, path.Dir(Native)); e != nil {
		return e
	}
	if e = auditSystemd(g, o.Work, out); e != nil {
		return e
	}
	if e = auditTimeConfig(g, o.Work); e != nil {
		return e
	}
	if e = auditVolumeTools(g, o.Work, out); e != nil {
		return e
	}
	if e = auditSSHServer(g, o.Work, out); e != nil {
		return e
	}
	for _, p := range append([]string{Profile, Helper}, Dropins...) {
		if e = g.AssertAbsent(p, "runtime-priority profile artifact"); e != nil {
			return e
		}
	}
	for _, p := range []string{NetBird, NetBirdConfig, NetBirdPin, NetBirdFallback, "/var/lib/netbird"} {
		if e = g.AssertAbsent(p, "NetBird artifact"); e != nil {
			return e
		}
	}
	if e = g.AssertAbsent(App+"/host-enrollment-public.json", "host enrollment public bundle"); e != nil {
		return e
	}
	bootstrap := []string{Bootstrap + "/anchor.json", Bootstrap + "/identity.json", Bootstrap + "/host-enrollment-public.json", Bootstrap + "/operator-ssh-key.pub"}
	for i := range o.BootstrapRoots {
		bootstrap = append(bootstrap, fmt.Sprintf("%s/trust-roots/%03d.pem", Bootstrap, i+1))
	}
	for _, p := range bootstrap {
		if e = g.AssertAbsent(p, "bootstrap artifact"); e != nil {
			return e
		}
	}
	names, e := g.List(Bootstrap + "/trust-roots")
	if e != nil {
		return e
	}
	if len(names) > 0 {
		return errors.New("base image has a conflicting bootstrap trust-root directory")
	}
	for _, p := range []string{"/var/lib/terrascale-orchestrator", "/var/lib/terrascale-orchestrator-bootstrap", "/var/lib/terrascale-orchestrator-secrets", "/var/lib/terrascale-orchestrator-controller"} {
		if e = g.AssertAbsent(p, "orchestrator state root"); e != nil {
			return e
		}
	}
	kind, e := g.Kind("/srv")
	if e != nil {
		return e
	}
	if kind != "dir" {
		return errors.New("base /srv must be a direct root:root 0755 directory")
	}
	meta, e := g.Metadata("/srv")
	if e != nil {
		return e
	}
	if meta["st_uid"] != 0 || meta["st_gid"] != 0 || meta["st_mode"]&07777 != 0755 {
		return errors.New("base /srv must be a direct root:root 0755 directory")
	}
	for _, entry := range []struct{ p, label string }{{"/srv/ts-managed", "managed root"}, {VolumeState, "managed volume initialization state root"}, {OCIDevicePaths, "OCI device path rule"}} {
		if e = g.AssertAbsent(entry.p, entry.label); e != nil {
			return e
		}
	}
	uid, gid, accountFiles, e := accounts(g, o.Work, o.Sysusers, out)
	if e != nil {
		return e
	}
	kind, e = g.Kind(AppLib)
	if e != nil {
		return e
	}
	if kind == "" {
		if e = g.Directory(AppLib, 0, 0, 0755); e != nil {
			return e
		}
		meta, e = g.Metadata(AppLib)
		if e != nil {
			return e
		}
		if meta["st_uid"] != 0 || meta["st_gid"] != 0 || meta["st_mode"]&07777 != 0755 {
			return fmt.Errorf("installed application library parent has unexpected metadata: %s", AppLib)
		}
	}
	for _, directory := range []string{App, Bootstrap, Bootstrap + "/trust-roots", "/etc/sysusers.d", "/etc/systemd", "/etc/systemd/system", "/etc/systemd/timesyncd.conf.d", "/etc/systemd/system/system.slice.d", "/etc/systemd/system/terrascale-orchestrator-host.service.d", "/etc/systemd/system/terrascale-orchestrator-controller.service.d", "/etc/systemd/system/terrascale-orchestrator-host-setup.service.d", path.Dir(TimeDropin), "/usr/local/bin", path.Dir(Helper), path.Dir(Native), "/etc/udev", path.Dir(OCIDevicePaths), "/var/lib/terrascale-orchestrator-bootstrap"} {
		if e = g.Directory(directory, 0, 0, 0755); e != nil {
			return e
		}
	}
	if e = g.Directory("/etc/systemd/system/terrascale-netbird-enroll.service.d", 0, 0, 0755); e != nil {
		return e
	}
	for _, dir := range []struct {
		p       string
		u, g, m int
	}{{"/var/lib/terrascale-orchestrator", 0, 0, 0755}, {"/var/lib/terrascale-orchestrator-secrets", uid, gid, 0700}, {"/var/lib/terrascale-orchestrator-controller", uid, gid, 0700}, {"/srv/ts-managed", 0, 2000, 0750}, {VolumeState, 0, 0, 0700}, {"/var/lib/netbird", 0, 0, 0700}} {
		if e = g.Directory(dir.p, dir.u, dir.g, dir.m); e != nil {
			return e
		}
	}
	pinWire, e := json.Marshal(pin)
	if e != nil {
		return e
	}
	pinPath := filepath.Join(o.Work, "netbird-pin.json")
	if e = os.WriteFile(pinPath, pinWire, 0644); e != nil {
		return e
	}
	uploads := []upload{{o.Sysusers, "/etc/sysusers.d/terrascale-orchestrator.conf", 0644}, {o.Profile, Profile, 0644}, {o.Binary, Helper, 0755}, {o.Binary, "/usr/local/bin/terrascale-orchestrator", 0755}, {o.NetBirdBinary, NetBird, 0755}, {o.NetBirdBinary, NetBirdFallback, 0755}, {pinPath, NetBirdPin, 0644}, {o.NetBirdConfig, NetBirdConfig, 0644}, {o.NativeVerifier, Native, 0755}, {o.Timesyncd, TimeConfig, 0644}, {filepath.Join(repo, "deploy/udev", path.Base(OCIDevicePaths)), OCIDevicePaths, 0644}}
	for _, name := range append(append([]string{"terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-controller-install.service", "terrascale-orchestrator-managed-host-start.service", "terrascale-orchestrator-managed-runtime.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"}, NetBirdUnits...), HostUnitFiles...) {
		uploads = append(uploads, upload{filepath.Join(repo, "deploy/systemd", name), "/etc/systemd/system/" + name, 0644})
	}
	for _, name := range append(append([]string{}, SelfUpdateDropins...), SelfUpdateUnitFiles...) {
		uploads = append(uploads, upload{filepath.Join(repo, "deploy/systemd/selfupdate", name), "/etc/systemd/system/" + name, 0644})
	}
	for _, p := range Dropins {
		uploads = append(uploads, upload{filepath.Join(o.PriorityRoot, strings.TrimPrefix(p, "/")), p, 0644})
	}
	for i, source := range o.BootstrapRoots {
		uploads = append(uploads, upload{source, fmt.Sprintf("%s/trust-roots/%03d.pem", Bootstrap, i+1), 0444})
	}
	timeout := filepath.Join(o.Work, "terrascale-timeout.conf")
	if e = os.WriteFile(timeout, []byte("[Service]\nTimeoutStartSec=300s\n"), 0644); e != nil {
		return e
	}
	uploads = append(uploads, upload{timeout, TimeDropin, 0644})
	for _, u := range uploads {
		if e = g.Upload(u.source, u.destination, u.mode); e != nil {
			return e
		}
	}
	for _, u := range accountFiles {
		if e = g.Replace(u.source, u.destination, u.mode); e != nil {
			return e
		}
	}
	if e = installRuntime(ctx, g, architecture, o.Work, out); e != nil {
		return e
	}
	if e = installLinks(g, o.Work, repo, out); e != nil {
		return e
	}
	meta, e = g.Metadata("/srv/ts-managed")
	if e != nil {
		return e
	}
	if meta["st_uid"] != 0 || meta["st_gid"] != 2000 || meta["st_mode"]&07777 != 0750 {
		return errors.New("installed managed root has unexpected metadata")
	}
	return g.AssertFile(Native, 0, 0, 0755)
}
func GuestVerify(ctx context.Context, image string, expect []string, out io.Writer) (result error) {
	type expectation struct{ p, d string }
	var expected []expectation
	for _, item := range expect {
		p, d, ok := strings.CutLast(item, "=")
		if !ok || !strings.HasPrefix(p, "/") || !client.SHA256Pattern.MatchString(d) {
			return fmt.Errorf("invalid --expect GUEST_PATH=SHA256: %s", item)
		}
		expected = append(expected, expectation{p, d})
	}
	g, e := NewGuest(ctx, image, true, nil)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, g.Close(result != nil)) }()
	work, e := os.MkdirTemp("", "ts-image-verify-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for i, item := range expected {
		kind, e := g.Kind(item.p)
		if e != nil {
			return e
		}
		if kind != "file" {
			return fmt.Errorf("finished image lacks regular file: %s", item.p)
		}
		target := filepath.Join(work, strconv.Itoa(i))
		if _, e = g.Read(item.p, target); e != nil {
			return e
		}
		d, e := fileHash(target)
		if e != nil {
			return e
		}
		if d != item.d {
			return fmt.Errorf("finished image bytes differ from the expected SHA-256: %s", item.p)
		}
		if _, e = fmt.Fprintf(out, "image readback sha256=%s guest_path=%s\n", d, item.p); e != nil {
			return e
		}
	}
	return nil
}
func NormalizeTimesync(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 16384 {
		return nil, errors.New("timesyncd config must be between 1 byte and 16384 bytes")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("timesyncd config must be UTF-8")
	}
	section := ""
	lists := map[string][]string{"NTP": {}, "FallbackNTP": {}}
	var preserved strings.Builder
	for i, raw := range strings.SplitAfter(string(data), "\n") {
		if raw == "" {
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			preserved.WriteString(raw)
			continue
		}
		if strings.HasSuffix(line, "\\") {
			return nil, fmt.Errorf("timesyncd config line %d uses a continuation; use single-line server assignments", i+1)
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			preserved.WriteString(raw)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid timesyncd config line %d", i+1)
		}
		key = strings.TrimSpace(key)
		if section == "Time" && (key == "PollIntervalMinSec" || key == "PollIntervalMaxSec") {
			continue
		}
		if section == "Time" && (key == "NTP" || key == "FallbackNTP") {
			value = strings.TrimSpace(value)
			if strings.ContainsAny(value, "#;\"'\\") {
				return nil, fmt.Errorf("timesyncd config line %d uses unsupported inline comments, quoting, or escapes", i+1)
			}
			if value == "" {
				lists[key] = nil
			} else {
				lists[key] = append(lists[key], strings.Fields(value)...)
			}
			continue
		}
		preserved.WriteString(raw)
	}
	if len(lists["NTP"]) == 0 {
		return nil, errors.New("timesyncd config must contain nonempty [Time] NTP endpoints")
	}
	lab := regexp.MustCompile(`198\.19(?:\.[0-9]{1,3}){2}`)
	for key, list := range lists {
		for _, endpoint := range list {
			indices := lab.FindAllStringIndex(endpoint, -1)
			for _, idx := range indices {
				if (idx[0] == 0 || endpoint[idx[0]-1] < '0' || endpoint[idx[0]-1] > '9') && (idx[1] == len(endpoint) || endpoint[idx[1]] < '0' || endpoint[idx[1]] > '9') {
					return nil, fmt.Errorf("timesyncd config effective %s list must not contain the Firecracker lab NTP address range", key)
				}
			}
		}
	}
	normalized := preserved.String()
	if normalized != "" && !strings.HasSuffix(normalized, "\n") && !strings.HasSuffix(normalized, "\r") {
		normalized += "\n"
	}
	if section != "Time" {
		normalized += "[Time]\n"
	}
	normalized += "NTP=\nNTP=" + strings.Join(lists["NTP"], " ") + "\nFallbackNTP=\n"
	if len(lists["FallbackNTP"]) > 0 {
		normalized += "FallbackNTP=" + strings.Join(lists["FallbackNTP"], " ") + "\n"
	}
	normalized += "PollIntervalMinSec=32\nPollIntervalMaxSec=64\n"
	return []byte(normalized), nil
}
func renderPriority(p PriorityInputs, root, profile string, out io.Writer) error {
	if !token.MatchString(p.ProfileID) {
		return errors.New("runtime-priority profile ID must be a 1-128 character safe token")
	}
	if p.HostMin > math.MaxInt64-p.ControllerMin || p.HostLow > math.MaxInt64-p.ControllerLow {
		return errors.New("system.slice floors must cover aggregate service floors within signed byte range")
	}
	args := runtimepriority.Object{"profile_id": p.ProfileID, "service_memory_min_bytes": p.HostMin, "service_memory_low_bytes": p.HostLow, "controller_memory_min_bytes": p.ControllerMin, "controller_memory_low_bytes": p.ControllerLow, "system_slice_memory_min_bytes": p.SystemMin, "system_slice_memory_low_bytes": p.SystemLow, "system_reserve_bytes": p.SystemReserve, "output_root": root}
	if err := runtimepriority.RenderDropIns(args, out); err != nil {
		return err
	}
	v := struct {
		Version int    `json:"version"`
		ID      string `json:"profile_id"`
		Reserve int64  `json:"system_reserve_bytes"`
	}{1, p.ProfileID, p.SystemReserve}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err = os.WriteFile(profile, b, 0644); err != nil {
		return err
	}
	d, err := fileHash(profile)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s sha256=%s\n", profile, d)
	return err
}

type OfflineOptions struct {
	Base, KernelRelease, Binary, Qualification, SourceRevision, NativeVerifier, NativeSHA256, NetBirdBinary, NetBirdSHA256, NetBirdConfig, ReleaseTool, Timesyncd, Out, KernelOut string
	BootstrapRoots                                                                                                                                                                []string
	Priority                                                                                                                                                                      PriorityInputs
}

func OfflineBuild(ctx context.Context, repo string, o OfflineOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, required := range []string{o.Base, o.KernelRelease, o.Binary, o.Qualification, o.SourceRevision, o.NativeVerifier, o.NativeSHA256, o.ReleaseTool, o.Timesyncd, o.Out, o.KernelOut} {
		if required == "" {
			return errors.New("missing required build-offline argument")
		}
	}
	if len(o.BootstrapRoots) == 0 || len(o.BootstrapRoots) > bootstrapstart.MaxRootFiles {
		return fmt.Errorf("bootstrap root set must contain at most %d files", bootstrapstart.MaxRootFiles)
	}
	if !gitSHA.MatchString(o.SourceRevision) {
		return errors.New("source revision must be a full lowercase Git SHA-1")
	}
	if !kernelRelease.MatchString(o.KernelRelease) {
		return errors.New("kernel release must be a plain Linux release string")
	}
	if !client.SHA256Pattern.MatchString(o.NativeSHA256) {
		return errors.New("native verifier SHA-256 must be 64 lowercase hex characters")
	}
	if (o.NetBirdBinary != "" || o.NetBirdSHA256 != "") && (o.NetBirdBinary == "" || !client.SHA256Pattern.MatchString(o.NetBirdSHA256)) {
		return errors.New("a supplied NetBird binary needs --netbird-binary and a lowercase --netbird-sha256")
	}
	pin, e := client.LoadPin(filepath.Join(repo, "deploy/image/image-inputs.json"))
	if e != nil {
		return e
	}
	architecture, e := binaryArchitecture(o.Binary)
	if e != nil {
		return e
	}
	archive, e := pin.Archive(architecture)
	if e != nil {
		return e
	}
	if o.NetBirdBinary != "" && o.NetBirdSHA256 != archive.BinarySHA256 {
		return errors.New("supplied NetBird SHA-256 differs from the image pin")
	}
	for _, tool := range []string{"qemu-img", "guestfish", "systemctl", "systemd-sysusers"} {
		if _, e := exec.LookPath(tool); e != nil {
			return fmt.Errorf("missing required command: %s", tool)
		}
	}
	s, e := os.Stat(o.ReleaseTool)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 {
		return errors.New("release tool must be executable")
	}
	for _, p := range []string{o.Base, o.Binary, o.NativeVerifier, o.Qualification, o.Timesyncd} {
		s, e := os.Stat(p)
		if e != nil {
			return e
		}
		if !s.Mode().IsRegular() {
			return fmt.Errorf("input must be a regular file: %s", p)
		}
	}
	for _, target := range []*string{&o.Out, &o.KernelOut} {
		absolute, err := filepath.Abs(*target)
		if err != nil {
			return err
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return err
		}
		*target = filepath.Join(parent, filepath.Base(absolute))
	}
	var total int64
	for _, p := range o.BootstrapRoots {
		s, e := os.Stat(p)
		if e != nil {
			return e
		}
		if !s.Mode().IsRegular() || s.Size() <= 0 || s.Size() > bootstrapstart.MaxRootBytes {
			return fmt.Errorf("each bootstrap root must be between 1 byte and %d bytes", bootstrapstart.MaxRootBytes)
		}
		total += s.Size()
	}
	if total > bootstrapstart.MaxRootsTotal {
		return fmt.Errorf("bootstrap roots must total no more than %d bytes", bootstrapstart.MaxRootsTotal)
	}
	for _, p := range []string{o.Out, o.KernelOut} {
		if _, e := os.Lstat(p); e == nil || !os.IsNotExist(e) {
			return errors.New("output must be a new path distinct from the base image")
		}
		if _, e := os.Stat(filepath.Dir(p)); e != nil {
			return e
		}
	}
	a, _ := filepath.Abs(o.Out)
	b, _ := filepath.Abs(o.KernelOut)
	base, _ := filepath.Abs(o.Base)
	if a == b || a == base || b == base {
		return errors.New("output must be a new path distinct from the base image")
	}
	work, e := os.MkdirTemp(filepath.Dir(o.Out), ".ts-orchestrator-image.")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if o.NetBirdConfig == "" {
		inputs, e := LoadInputs(repo, filepath.Join(repo, "deploy/image/image-inputs.json"))
		if e != nil {
			return e
		}
		o.NetBirdConfig = filepath.Join(repo, inputs.NetBird.EnrollmentConfig.Path)
	}
	if _, e = client.ValidateConfig(o.NetBirdConfig); e != nil {
		return e
	}
	config := filepath.Join(work, "netbird.json")
	if e = copyFile(o.NetBirdConfig, config, 0644); e != nil {
		return e
	}
	netbird := filepath.Join(work, "netbird")
	if o.NetBirdBinary == "" {
		if e = client.Fetch(ctx, pin, architecture, netbird, os.Getenv("TS_NETBIRD_CLIENT_CACHE"), nil); e != nil {
			return e
		}
		o.NetBirdSHA256 = archive.BinarySHA256
	} else {
		if e = copyFile(o.NetBirdBinary, netbird, 0755); e != nil {
			return e
		}
	}
	if e = client.VerifyBinary(netbird, o.NetBirdSHA256, architecture); e != nil {
		return e
	}
	profile := filepath.Join(work, "runtime-priority.json")
	priorityRoot := filepath.Join(work, "runtime-priority")
	if e = renderPriority(o.Priority, priorityRoot, profile, out); e != nil {
		return e
	}
	timesyncData, e := os.ReadFile(o.Timesyncd)
	if e != nil {
		return e
	}
	timesyncData, e = NormalizeTimesync(timesyncData)
	if e != nil {
		return e
	}
	timesync := filepath.Join(work, "timesyncd.conf")
	if e = os.WriteFile(timesync, timesyncData, 0644); e != nil {
		return e
	}
	native := filepath.Join(work, "terrabase-server")
	if e = copyFile(o.NativeVerifier, native, 0755); e != nil {
		return e
	}
	nativeInfo, e := os.Stat(native)
	if e != nil {
		return e
	}
	if nativeInfo.Size() <= 0 || nativeInfo.Size() > 128<<20 {
		return errors.New("native verifier must be between 1 byte and 128 MiB")
	}
	nativeArchitecture, e := binaryArchitecture(native)
	if e != nil {
		return e
	}
	if nativeArchitecture != architecture {
		return errors.New("native verifier and orchestrator architectures differ")
	}
	nativeDigest, e := fileHash(native)
	if e != nil {
		return e
	}
	if nativeDigest != o.NativeSHA256 {
		return errors.New("native verifier bytes do not match the supplied SHA-256")
	}
	fmt.Fprintf(out, "native verifier artifact sha256=%s bytes=%d architecture=%s\n", nativeDigest, nativeInfo.Size(), architecture)
	binaryPath := filepath.Join(work, "terrascale-orchestrator")
	if e = copyFile(o.Binary, binaryPath, 0755); e != nil {
		return e
	}
	timesyncDigest, e := fileHash(timesync)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "timesyncd image config sha256=%s\n", timesyncDigest)
	if _, e = Execute(ctx, "", nil, o.ReleaseTool, "release", "binary-candidate", "--binary", binaryPath, "--source-revision", o.SourceRevision, "--qualification", o.Qualification, "--out", filepath.Join(work, "binary-candidate.json")); e != nil {
		return e
	}
	binaryDigest, e := fileHash(binaryPath)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "qualified orchestrator binary sha256=%s source=%s\n", binaryDigest, o.SourceRevision)
	if _, e = Execute(ctx, "", nil, "qemu-img", "check", "--", o.Base); e != nil {
		return e
	}
	info, e := Execute(ctx, "", nil, "qemu-img", "info", "--output=json", "--", o.Base)
	if e != nil {
		return e
	}
	var qemu struct {
		Format  string `json:"format"`
		Backing string `json:"backing-filename"`
	}
	if e = json.Unmarshal([]byte(info), &qemu); e != nil {
		return e
	}
	if qemu.Format != "qcow2" || qemu.Backing != "" {
		return errors.New("base must be standalone QCOW2 with no backing file")
	}
	candidate := filepath.Join(work, "image.qcow2")
	if _, e = Execute(ctx, "", nil, "cp", "--reflink=auto", "--sparse=always", "--", o.Base, candidate); e != nil {
		return e
	}
	kernel := filepath.Join(work, "guest-kernel")
	if e = GuestBuild(ctx, repo, GuestBuildOptions{candidate, o.KernelRelease, kernel, work, filepath.Join(repo, "deploy/image/terrascale-orchestrator.sysusers"), profile, priorityRoot, binaryPath, native, timesync, netbird, config, o.BootstrapRoots}, out); e != nil {
		return e
	}
	if _, e = Execute(ctx, "", nil, "qemu-img", "check", "--", candidate); e != nil {
		return e
	}
	kernelDigest, e := fileHash(kernel)
	if e != nil {
		return e
	}
	configDigest, e := fileHash(config)
	if e != nil {
		return e
	}
	ruleDigest, e := fileHash(filepath.Join(repo, "deploy/udev", path.Base(OCIDevicePaths)))
	if e != nil {
		return e
	}
	expected := []string{"/usr/local/bin/terrascale-orchestrator=" + binaryDigest, NetBird + "=" + o.NetBirdSHA256, NetBirdConfig + "=" + configDigest, Native + "=" + o.NativeSHA256, "/boot/vmlinuz-" + o.KernelRelease + "=" + kernelDigest, OCIDevicePaths + "=" + ruleDigest}
	for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
		digest, err := fileHash(filepath.Join(work, name))
		if err != nil {
			return err
		}
		expected = append(expected, "/usr/local/bin/"+name+"="+digest)
	}
	for _, artifact := range [][2]string{
		{"containerd.service", filepath.Join(work, "containerd.service")},
		{"terrascale-orchestrator-controller.service.d/70-containerd.conf", filepath.Join(work, "70-containerd.conf")},
		{"terrascale-orchestrator-host.service.d/70-containerd.conf", filepath.Join(work, "70-containerd.conf")},
		{"terrascale-orchestrator-managed-runtime.service", filepath.Join(repo, "deploy/systemd/terrascale-orchestrator-managed-runtime.service")},
		{"terrascale-orchestrator-managed-host-start.service", filepath.Join(repo, "deploy/systemd/terrascale-orchestrator-managed-host-start.service")},
		{"terrascale-orchestrator-controller.service", filepath.Join(repo, "deploy/systemd/terrascale-orchestrator-controller.service")},
	} {
		digest, err := fileHash(artifact[1])
		if err != nil {
			return err
		}
		expected = append(expected, "/etc/systemd/system/"+artifact[0]+"="+digest)
	}
	pinDigest, e := fileHash(filepath.Join(work, "netbird-pin.json"))
	if e != nil {
		return e
	}
	expected = append(expected, NetBirdFallback+"="+o.NetBirdSHA256, NetBirdPin+"="+pinDigest)
	if e = GuestVerify(ctx, candidate, expected, out); e != nil {
		return e
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e = exclusiveCopy(kernel, o.KernelOut, 0644); e != nil {
		return e
	}
	if e = os.Link(candidate, o.Out); e != nil {
		os.Remove(o.KernelOut)
		return e
	}
	_, e = fmt.Fprintf(out, "offline QCOW2 candidate created at %s kernel=%s sha256=%s\n", o.Out, o.KernelOut, kernelDigest)
	return e
}
func exclusiveCopy(source, destination string, mode os.FileMode) error {
	f, e := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	in, e := os.Open(source)
	if e != nil {
		f.Close()
		os.Remove(destination)
		return e
	}
	defer in.Close()
	_, e = io.Copy(f, in)
	e = errors.Join(e, f.Close())
	if e != nil {
		os.Remove(destination)
	}
	return e
}
