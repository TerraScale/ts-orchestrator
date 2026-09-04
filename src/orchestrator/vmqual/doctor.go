package vmqual

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

// Check is one read-only host qualification check.
type Check struct {
	Name   string
	OK     bool
	Detail string
	Repair string
}

// DoctorReport is the bounded, operator-readable result of vm-qualify doctor.
type DoctorReport struct{ Checks []Check }

func (r DoctorReport) OK() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return true
}

func (r DoctorReport) Error() error {
	if r.OK() {
		return nil
	}
	return errors.New("vmqual: host is not eligible for Firecracker qualification")
}

func (r DoctorReport) Write(w io.Writer) {
	for _, check := range r.Checks {
		state := "FAIL"
		if check.OK {
			state = "OK"
		}
		_, _ = fmt.Fprintf(w, "%s %-18s %s\n", state, check.Name, check.Detail)
		if !check.OK && check.Repair != "" {
			_, _ = fmt.Fprintf(w, "      repair: %s\n", check.Repair)
		}
	}
}

// RunDoctor performs bounded host checks. It invokes Firecracker only with
// --version and creates/removes one bounded cgroup probe directory when the
// current cgroup is delegated; it never creates a VM, network device, or cache.
func RunDoctor(ctx context.Context, config Config) DoctorReport {
	report := DoctorReport{}
	add := func(name string, ok bool, detail, repair string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail, Repair: repair})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	add("platform", runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"), HostPlatform(), "run on native Linux amd64 or arm64; software emulation is not supported")
	kvmOK, kvmDetail := writableKVM()
	add("kvm", kvmOK, kvmDetail, "grant the qualification runner narrow writable access to /dev/kvm")
	if err := config.Validate(); err != nil {
		add("configuration", false, err.Error(), "set TS_VM_ROOT and the checked-in architecture-specific manifests")
	} else {
		add("configuration", true, "paths and resource limits are valid", "")
	}

	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		add("pins", false, err.Error(), "provide the checked-in architecture-specific Firecracker pin manifest")
	} else {
		if string(pins.Architecture) != runtime.GOARCH {
			add("pins", false, fmt.Sprintf("manifest architecture %s does not match native %s", pins.Architecture, runtime.GOARCH), "use the pin manifest for the qualification host architecture")
		} else {
			add("pins", true, "host and guest artifacts are declared", "")
		}
		config = config.ApplyPins(pins)
		installer := vmimage.ToolchainInstaller{Root: config.Root}
		location, locationErr := installer.Location(pins)
		if locationErr != nil {
			add("toolchain", false, locationErr.Error(), "use an absolute private qualification root")
		} else if err := installer.Verify(location); err != nil {
			add("toolchain", false, err.Error(), "materialize the exact pinned Firecracker release with vm-qualify image")
		} else {
			add("toolchain", true, location.Dir, "")
		}
		versionOK, versionDetail := verifyFirecrackerVersion(ctx, config.FirecrackerPath, pins.FirecrackerVersion)
		add("fc-version", versionOK, versionDetail, "run make vm-image and remove any stale toolchain cache entry")
		sdkOK, sdkDetail := verifySDKPin(repositoryRoot(), pins.SDKModule, pins.SDKVersion)
		add("sdk", sdkOK, sdkDetail, "pin the official Firecracker Go SDK at the version declared by the native pin manifest")
	}
	image, imageErr := LoadImageManifest(config.ImageManifestPath)
	if imageErr != nil {
		add("image-manifest", false, imageErr.Error(), "restore the checked-in native Ubuntu image manifest")
	} else {
		imageOK := string(image.Architecture) == runtime.GOARCH && pinnedImageSources(image)
		add("image-manifest", imageOK, fmt.Sprintf("Ubuntu %s for linux/%s", image.UbuntuRelease, image.Architecture), "select a native manifest with fixed immutable HTTPS sources")
		for _, artifact := range []struct {
			name string
			path string
			pin  vmimage.ArtifactManifest
		}{{"kernel", config.KernelPath, image.Kernel}, {"rootfs", config.RootFSPath, image.RootFS}} {
			err := verifyArtifactFile(artifact.path, artifact.pin, artifact.name)
			add(artifact.name, err == nil, pathOrError(artifact.path, err), "run make vm-image to build and verify the pinned native guest artifact")
		}
	}
	for _, tool := range []struct {
		name, repair, usage string
	}{
		{"ip", "install iproute2", "network namespaces, TAPs, bridges, and stable guest addresses"},
		{"nft", "install nftables", "deterministic cross-Region partitions"},
		{"tc", "install iproute2", "netem fault profiles"},
		{"qemu-img", "install qemu-utils", "pinned QCOW2 conversion"},
		{"cloud-localds", "install cloud-image-utils", "per-VM NoCloud seed drives"},
		{"mkfs.ext4", "install e2fsprogs", "persistent guest data disks"},
	} {
		toolPath, lookErr := exec.LookPath(tool.name)
		add(tool.name, lookErr == nil && filepath.IsAbs(toolPath), pathOrError(toolPath, lookErr)+" (required for "+tool.usage+")", tool.repair)
	}
	capabilityOK, capabilityDetail := netAdminCapability()
	add("net-admin", capabilityOK, capabilityDetail, "run the isolated qualification job with CAP_NET_ADMIN or as a narrowly scoped privileged runner")
	cgroupOK, cgroupDetail := cgroupV2Access()
	add("cgroup-v2", cgroupOK, cgroupDetail, "provide a delegated writable cgroup v2 subtree for jailer")
	portOK, portDetail := loopbackPort()
	add("ports", portOK, portDetail, "allow loopback ports for bounded local provider endpoints")
	resourceOK, resourceDetail := hostResourceBudget()
	add("resources", resourceOK, resourceDetail, "provide at least 2 CPUs and 5 GiB available RAM for the six-VM gate")
	if config.Root != "" {
		diskPath := existingParent(config.Root)
		need := uint64(config.MaxDiskBytes)
		if need == 0 {
			need = 8 << 30
		}
		ok, detail := diskBudget(diskPath, need)
		add("disk", ok, detail, "make the configured disk budget available for the qualification stack")
	}
	return report
}

func pathOrError(path string, err error) string {
	if err != nil {
		return err.Error()
	}
	return path
}

func writableKVM() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "/dev/kvm is Linux-only"
	}
	stat, err := os.Stat("/dev/kvm")
	if err != nil {
		return false, err.Error()
	}
	if stat.Mode()&os.ModeDevice == 0 {
		return false, "/dev/kvm is not a device"
	}
	file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return false, err.Error()
	}
	_ = file.Close()
	return true, "/dev/kvm is writable"
}

func verifyFirecrackerVersion(ctx context.Context, path, version string) (bool, string) {
	if path == "" || !filepath.IsAbs(path) {
		return false, "Firecracker path is unavailable"
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var output boundedBuffer
	command := exec.CommandContext(checkCtx, path, "--version")
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return false, "cannot query Firecracker version: " + err.Error()
	}
	got := strings.Split(strings.TrimSpace(output.String()), "\n")[0]
	want := "Firecracker v" + version
	return got == want, fmt.Sprintf("%s (want %s)", got, want)
}

type boundedBuffer struct{ bytes.Buffer }

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	const limit = 4096
	original := len(data)
	if remaining := limit - buffer.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = buffer.Buffer.Write(data)
	}
	return original, nil
}

func verifySDKPin(root, module, version string) (bool, string) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return false, err.Error()
	}
	want := module + " " + version
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0]+" "+fields[1] == want {
			return true, want
		}
	}
	return false, want + " is not an exact go.mod requirement"
}

func pinnedImageSources(manifest vmimage.GuestImageManifest) bool {
	for _, source := range []string{manifest.Kernel.Source, manifest.RootFS.Source} {
		parsed, err := url.Parse(source)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.Path, "/current/") || strings.Contains(parsed.Path, "/release/") {
			return false
		}
	}
	return manifest.RootFS.Transform != nil
}

func netAdminCapability() (bool, string) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err.Error()
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return false, err.Error()
		}
		const capNetAdmin = uint64(1 << 12)
		return mask&capNetAdmin != 0, "effective capability mask 0x" + value
	}
	return false, "CapEff is absent from /proc/self/status"
}

func cgroupV2Access() (bool, string) {
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, "cannot read cgroup mount information: " + err.Error()
	}
	mount, err := unifiedCgroupMount(string(mountInfo))
	if err != nil {
		return false, "cgroup v2 is unavailable: " + err.Error()
	}
	cgroupData, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false, "cannot read current cgroup: " + err.Error()
	}
	cgroup, err := unifiedCgroupPath(string(cgroupData))
	if err != nil {
		return false, "cannot resolve current cgroup: " + err.Error()
	}
	subtree, err := cgroupSubtree(mount, cgroup)
	if err != nil {
		return false, "cannot resolve current cgroup subtree: " + err.Error()
	}
	if _, err := os.Stat(filepath.Join(mount, "cgroup.controllers")); err != nil {
		return false, "cgroup v2 is unavailable: " + err.Error()
	}
	if err := syscall.Access(subtree, 2); err != nil {
		return false, fmt.Sprintf("current cgroup subtree %s is not writable or delegated: %v", cgroup, err)
	}
	probe, err := os.MkdirTemp(subtree, ".ts-vmqual-probe-")
	if err != nil {
		return false, fmt.Sprintf("current cgroup subtree %s cannot create a child: %v", cgroup, err)
	}
	if err := os.Remove(probe); err != nil {
		return false, fmt.Sprintf("current cgroup subtree %s probe cleanup failed: %v", cgroup, err)
	}
	return true, fmt.Sprintf("cgroup v2 delegated at current subtree %s", cgroup)
}

// unifiedCgroupPath extracts and validates the process path in the unified
// cgroup hierarchy. The kernel format is one hierarchy per line:
// hierarchy-ID:controllers:path. Only the cgroup v2 line has an empty
// controllers field.
func unifiedCgroupPath(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 || fields[1] != "" {
			continue
		}
		path := fields[2]
		if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
			return "", errors.New("unified cgroup path is invalid")
		}
		clean := filepath.Clean(path)
		if clean != path || strings.Contains(path, "//") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
			return "", errors.New("unified cgroup path contains traversal")
		}
		return clean, nil
	}
	return "", errors.New("unified cgroup hierarchy is absent")
}

// unifiedCgroupMount finds the cgroup2 mountpoint from mountinfo rather than
// assuming a distribution-specific mount path.
func unifiedCgroupMount(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		post := strings.Fields(parts[1])
		pre := strings.Fields(parts[0])
		if len(post) < 1 || post[0] != "cgroup2" || len(pre) < 5 {
			continue
		}
		mount := decodeMountInfoPath(pre[4])
		if !filepath.IsAbs(mount) || strings.ContainsRune(mount, 0) {
			return "", errors.New("cgroup v2 mountpoint is invalid")
		}
		return filepath.Clean(mount), nil
	}
	return "", errors.New("cgroup2 mount is absent")
}

func decodeMountInfoPath(value string) string {
	value = strings.ReplaceAll(value, `\040`, " ")
	value = strings.ReplaceAll(value, `\011`, "\t")
	value = strings.ReplaceAll(value, `\012`, "\n")
	return strings.ReplaceAll(value, `\134`, `\`)
}

// cgroupSubtree resolves a kernel-reported cgroup path beneath its discovered
// mountpoint. It rejects traversal lexically before any filesystem operation.
func cgroupSubtree(mount, cgroup string) (string, error) {
	if !filepath.IsAbs(mount) || filepath.Clean(mount) != mount {
		return "", errors.New("cgroup mountpoint is not a clean absolute path")
	}
	if !filepath.IsAbs(cgroup) || strings.Contains(cgroup, "..") {
		return "", errors.New("cgroup path is not a safe absolute path")
	}
	subtree := filepath.Join(mount, strings.TrimPrefix(cgroup, string(filepath.Separator)))
	rel, err := filepath.Rel(mount, subtree)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("cgroup path escapes mountpoint")
	}
	return subtree, nil
}

func loopbackPort() (bool, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return false, err.Error()
	}
	return true, "loopback bind available at " + address
}

func hostResourceBudget() (bool, string) {
	available := int64(0)
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if _, scanErr := fmt.Sscanf(line, "MemAvailable: %d kB", &available); scanErr == nil {
				available *= 1024
				break
			}
		}
	}
	cpus := runtime.NumCPU()
	return cpus >= 2 && available >= 5<<30, fmt.Sprintf("%d CPUs, %d bytes available RAM", cpus, available)
}

func existingParent(path string) string {
	path = filepath.Clean(path)
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}

func diskBudget(path string, need uint64) (bool, string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return false, err.Error()
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	return free >= need, fmt.Sprintf("%d bytes free (need %d)", free, need)
}

// VerifyPinnedFiles verifies already-materialized artifacts without creating
// directories or downloading anything. It is retained for callers that want
// the artifact gate without the host report.
func VerifyPinnedFiles(config Config) error {
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		return err
	}
	config = config.ApplyPins(pins)
	installer := vmimage.ToolchainInstaller{Root: config.Root}
	location, err := installer.Location(pins)
	if err != nil {
		return err
	}
	if err := installer.Verify(location); err != nil {
		return fmt.Errorf("toolchain: %w", err)
	}
	manifest, err := LoadImageManifest(config.ImageManifestPath)
	if err != nil {
		return err
	}
	if err := verifyArtifactFile(config.KernelPath, manifest.Kernel, "kernel"); err != nil {
		return err
	}
	return verifyArtifactFile(config.RootFSPath, manifest.RootFS, "rootfs")
}

func verifyArtifactFile(path string, artifact vmimage.ArtifactManifest, name string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s path is not absolute", name)
	}
	stat, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 || stat.Size() != artifact.Size {
		return fmt.Errorf("%s metadata does not match its manifest", name)
	}
	if uint32(stat.Mode().Perm()) != artifact.Mode {
		return fmt.Errorf("%s mode %04o does not match manifest %04o", name, stat.Mode().Perm(), artifact.Mode)
	}
	hash := sha256.New()
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("%s: %w", name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%s: %w", name, closeErr)
	}
	if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(artifact.SHA256) {
		return fmt.Errorf("%s sha256 mismatch", name)
	}
	return nil
}
