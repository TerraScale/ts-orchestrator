package vmqual

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// RunDoctor performs bounded, read-only host checks. It invokes Firecracker
// and jailer only with --version and never creates a VM, cgroup, network
// device, artifact, or cache entry.
func RunDoctor(ctx context.Context, config Config) DoctorReport {
	report := DoctorReport{}
	add := func(name string, ok bool, detail, repair string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail, Repair: repair})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	add("platform", runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"), HostPlatform(), "run on native Linux amd64 or arm64; software emulation is not supported")
	clockError, clockErr := SynchronizedHostTime()
	clockDetail := fmt.Sprintf("host kernel synchronized; maximum error %s; NTP leap indicator %d", clockError.MaximumError, clockError.LeapIndicator)
	if clockErr != nil {
		clockDetail = clockErr.Error()
	}
	add("host-clock", clockErr == nil, clockDetail, "provide a synchronized host clock with valid adjtimex uncertainty and leap state; inspect the host time daemon")
	kvmOK, kvmDetail := writableKVM()
	add("kvm", kvmOK, kvmDetail, "grant the qualification runner narrow writable access to /dev/kvm")
	if err := config.Validate(); err != nil {
		add("configuration", false, err.Error(), "set TS_VM_ROOT and the checked-in architecture-specific manifests")
	} else {
		add("configuration", true, "paths and resource limits are valid", "")
	}

	var pins vmimage.ToolchainManifest
	pinsLoaded := false
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		add("pins", false, err.Error(), "provide the checked-in architecture-specific Firecracker pin manifest")
	} else {
		pinsLoaded = true
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
		for _, artifact := range []struct {
			name string
			path string
			pin  vmimage.ArchiveMember
		}{
			{"firecracker", config.FirecrackerPath, pins.Firecracker},
			{"jailer", config.JailerPath, pins.Jailer},
		} {
			err := verifyExecutableFile(artifact.path, artifact.pin, artifact.name)
			add(artifact.name, err == nil, pathOrError(artifact.path, err), "run make vm-image to install the exact pinned executable")
		}
		versionOK, versionDetail := verifyFirecrackerVersion(ctx, config.FirecrackerPath, pins.FirecrackerVersion)
		add("fc-version", versionOK, versionDetail, "run make vm-image and remove any stale toolchain cache entry")
		jailerVersionOK, jailerVersionDetail := verifyJailerVersion(ctx, config.JailerPath, pins.FirecrackerVersion)
		add("jailer-version", jailerVersionOK, jailerVersionDetail, "run make vm-image and remove any stale toolchain cache entry")
		sdkOK, sdkDetail := verifySDKPin(repositoryRoot(), pins.SDKModule, pins.SDKVersion)
		add("sdk", sdkOK, sdkDetail, "pin the official Firecracker Go SDK directly in go.mod with its module and go.mod checksums in go.sum")
	}
	var image vmimage.GuestImageManifest
	imageLoaded := false
	image, imageErr := LoadImageManifest(config.ImageManifestPath)
	if imageErr != nil {
		add("image-manifest", false, imageErr.Error(), "restore the checked-in native Ubuntu image manifest")
		add("image-receipt", false, "guest image manifest could not be read", "restore the native image manifest, then run make vm-image")
	} else {
		imageLoaded = true
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
		receipt, receiptErr := verifyPreparedImage(config, image)
		receiptDetail := pathOrError("prepared image receipt is verified", receiptErr)
		if receiptErr == nil {
			receiptDetail = fmt.Sprintf("verified %s %s; sanitized %s; %s", receipt.OSID, receipt.OSVersion, strings.Join(receipt.SanitizedMounts, ", "), receipt.FilesystemCheck)
		}
		add("image-receipt", receiptErr == nil, receiptDetail, "run make vm-image to inspect, sanitize, check, and atomically publish the pinned Ubuntu rootfs")
	}
	if pinsLoaded && imageLoaded {
		consistencyErr := validateManifestConsistency(config, pins, image, runtime.GOARCH)
		add("manifest-pair", consistencyErr == nil, pathOrError("toolchain and guest image pins agree", consistencyErr), "select the matching native toolchain and image manifests and remove conflicting TS_VM_* overrides")
	} else {
		add("manifest-pair", false, "toolchain and guest image manifests could not both be read", "restore both checked-in architecture-specific manifests")
	}
	for _, tool := range []struct {
		name, repair, usage string
	}{
		{"ip", "install iproute2", "network namespaces, TAPs, bridges, and stable guest addresses"},
		{"nft", "install nftables", "deterministic cross-Region partitions"},
		{"iptables", "install iptables", "temporary host INPUT admission for owned qualification endpoints"},
		{"tc", "install iproute2", "netem fault profiles"},
		{"qemu-img", "install qemu-utils", "pinned QCOW2 conversion"},
		{"mkfs.ext4", "install e2fsprogs", "persistent guest data disks"},
		{"debugfs", "install e2fsprogs", "read-only Ubuntu identity inspection and fstab sanitization during image preparation"},
		{"e2fsck", "install e2fsprogs", "read-only ext4 consistency verification"},
		{"ssh", "install an OpenSSH client", "bounded guest control"},
		{"sysctl", "install procps", "network-namespace forwarding"},
		{"go", "install the Go toolchain declared by go.mod", "the pinned guest-control binary"},
	} {
		toolPath, lookErr := exec.LookPath(tool.name)
		add(tool.name, lookErr == nil && filepath.IsAbs(toolPath), pathOrError(toolPath, lookErr)+" (required for "+tool.usage+")", tool.repair)
	}
	capabilityOK, capabilityDetail := netAdminCapability()
	add("net-admin", capabilityOK, capabilityDetail, "run the isolated qualification job with CAP_NET_ADMIN or as a narrowly scoped privileged runner")
	jailerOK, jailerDetail := jailerPrivilege()
	add("jailer-access", jailerOK, jailerDetail, "run jailer as host root with its required effective capabilities; a rootless user namespace is insufficient")
	cgroupOK, cgroupDetail := cgroupV2Access()
	add("cgroup-v2", cgroupOK, cgroupDetail, "provide a delegated writable cgroup v2 subtree for jailer")
	portOK, portDetail := loopbackPorts(config.RequiredPorts)
	add("ports", portOK, portDetail, "allow loopback ports for bounded local provider endpoints")
	resourceOK, resourceDetail := hostResourceBudget()
	add("resources", resourceOK, resourceDetail, "provide at least 2 CPUs and 4 GiB available RAM for the six-VM gate")
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
	return verifyToolVersion(ctx, path, "firecracker", version, 5*time.Second)
}

func verifyJailerVersion(ctx context.Context, path, version string) (bool, string) {
	return verifyToolVersion(ctx, path, "jailer", version, 5*time.Second)
}

var reportedToolVersion = regexp.MustCompile(`(?i)^(firecracker|jailer)[[:space:]]+v?([0-9][0-9A-Za-z.+-]*)$`)

func verifyToolVersion(ctx context.Context, path, component, version string, timeout time.Duration) (bool, string) {
	if path == "" || !filepath.IsAbs(path) {
		return false, component + " path is unavailable"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return false, component + " version timeout is invalid"
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var output boundedBuffer
	command := exec.CommandContext(checkCtx, path, "--version")
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		if checkCtx.Err() != nil {
			return false, "cannot query " + component + " version: " + checkCtx.Err().Error()
		}
		return false, "cannot query " + component + " version: " + err.Error()
	}
	got := firstNonemptyLine(output.String())
	match := reportedToolVersion.FindStringSubmatch(got)
	wantVersion := strings.TrimPrefix(version, "v")
	want := component + " v" + wantVersion
	if len(match) != 3 || !strings.EqualFold(match[1], component) || match[2] != wantVersion {
		return false, fmt.Sprintf("%s reported %q (want %s)", component, got, want)
	}
	return true, fmt.Sprintf("%s reported %s", component, wantVersion)
}

func firstNonemptyLine(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
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
	const officialSDK = "github.com/firecracker-microvm/firecracker-go-sdk"
	if module != officialSDK {
		return false, fmt.Sprintf("SDK module %q is not the official Firecracker SDK", module)
	}
	modData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return false, err.Error()
	}
	requiredVersion, direct, replaced, excluded := goModSDKState(string(modData), module, version)
	if requiredVersion != version {
		if requiredVersion == "" {
			return false, module + " is absent from go.mod"
		}
		return false, fmt.Sprintf("%s requires %s in go.mod (want %s)", module, requiredVersion, version)
	}
	if !direct {
		return false, module + " is not a direct go.mod requirement"
	}
	if replaced {
		return false, module + " is replaced in go.mod"
	}
	if excluded {
		return false, module + " " + version + " is excluded in go.mod"
	}
	sumData, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return false, err.Error()
	}
	if err := verifyModuleSums(string(sumData), module, version); err != nil {
		return false, err.Error()
	}
	return true, module + " " + version + " is a direct requirement with module and go.mod checksums"
}

func goModSDKState(data, module, wantedVersion string) (version string, direct, replaced, excluded bool) {
	block := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "(" && (fields[0] == "require" || fields[0] == "replace" || fields[0] == "exclude") {
			block = fields[0]
			continue
		}
		if line == ")" {
			block = ""
			continue
		}
		directive := block
		if directive == "" && len(fields) > 0 && (fields[0] == "require" || fields[0] == "replace" || fields[0] == "exclude") {
			directive = fields[0]
			fields = fields[1:]
		}
		if len(fields) == 0 || fields[0] != module {
			continue
		}
		switch directive {
		case "require":
			if len(fields) >= 2 {
				version = fields[1]
				direct = !strings.Contains(line, "// indirect")
			}
		case "replace":
			replaced = true
		case "exclude":
			if len(fields) >= 2 && fields[1] == wantedVersion {
				excluded = true
			}
		}
	}
	return version, direct, replaced, excluded
}

func verifyModuleSums(data, module, version string) error {
	wanted := map[string]string{
		module + " " + version:             "",
		module + " " + version + "/go.mod": "",
	}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		key := fields[0] + " " + fields[1]
		if prior, needed := wanted[key]; needed {
			if !validGoSum(fields[2]) {
				return errors.New(key + " has an invalid h1 checksum in go.sum")
			}
			if prior != "" {
				return errors.New(key + " is duplicated in go.sum")
			}
			wanted[key] = fields[2]
		}
	}
	for _, key := range []string{module + " " + version, module + " " + version + "/go.mod"} {
		if wanted[key] == "" {
			return errors.New(key + " lacks a valid h1 checksum in go.sum")
		}
	}
	return nil
}

func validGoSum(value string) bool {
	if !strings.HasPrefix(value, "h1:") {
		return false
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "h1:"))
	if err != nil || len(digest) != sha256.Size {
		return false
	}
	for _, octet := range digest {
		if octet != 0 {
			return true
		}
	}
	return false
}

func validateManifestConsistency(config Config, pins vmimage.ToolchainManifest, image vmimage.GuestImageManifest, architecture string) error {
	if string(pins.Architecture) != architecture || string(image.Architecture) != architecture || pins.Architecture != image.Architecture {
		return fmt.Errorf("manifest architectures toolchain=%s image=%s do not match native %s", pins.Architecture, image.Architecture, architecture)
	}
	wantImageVersion := image.UbuntuRelease + "-fc" + pins.FirecrackerVersion
	if image.Version != wantImageVersion {
		return fmt.Errorf("image version %s does not bind Firecracker %s (want %s)", image.Version, pins.FirecrackerVersion, wantImageVersion)
	}
	for _, comparison := range []struct{ name, got, want string }{
		{"Firecracker version", config.ExpectedVersion, pins.FirecrackerVersion},
		{"Firecracker checksum", config.ExpectedFirecrackerSHA256, pins.Firecracker.SHA256},
		{"jailer checksum", config.ExpectedJailerSHA256, pins.Jailer.SHA256},
		{"SDK module", config.SDKModule, pins.SDKModule},
		{"SDK version", config.SDKVersion, pins.SDKVersion},
		{"kernel checksum", config.ExpectedKernelSHA256, image.Kernel.SHA256},
		{"rootfs checksum", config.ExpectedRootFSSHA256, image.RootFS.SHA256},
	} {
		if comparison.got != comparison.want {
			return fmt.Errorf("configured %s %q differs from manifest %q", comparison.name, comparison.got, comparison.want)
		}
	}
	return nil
}

func verifyPreparedImage(config Config, manifest vmimage.GuestImageManifest) (vmimage.PreparationReceipt, error) {
	cache, err := vmimage.NewCache(config.ImageCacheRoot)
	if err != nil {
		return vmimage.PreparationReceipt{}, err
	}
	plan, err := vmimage.NewBuildPlan(manifest, config.ImageCacheRoot)
	if err != nil {
		return vmimage.PreparationReceipt{}, err
	}
	installed := vmimage.InstalledImage{
		Manifest: manifest,
		Dir:      plan.CacheEntry,
		Kernel:   filepath.Join(plan.CacheEntry, manifest.Kernel.Name),
		RootFS:   filepath.Join(plan.CacheEntry, manifest.RootFS.Name),
		Receipt:  filepath.Join(plan.CacheEntry, "image-receipt.json"),
	}
	if err := cache.VerifyInstalled(installed); err != nil {
		return vmimage.PreparationReceipt{}, fmt.Errorf("vmqual: verify prepared image: %w", err)
	}
	data, err := os.ReadFile(installed.Receipt)
	if err != nil {
		return vmimage.PreparationReceipt{}, fmt.Errorf("vmqual: read prepared image receipt: %w", err)
	}
	receipt, err := vmimage.DecodePreparationReceipt(data, manifest)
	if err != nil {
		return vmimage.PreparationReceipt{}, fmt.Errorf("vmqual: verify prepared image receipt: %w", err)
	}
	return receipt, nil
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
	mask, rendered, err := effectiveCapabilities()
	if err != nil {
		return false, err.Error()
	}
	const capNetAdmin = uint64(1 << 12)
	return mask&capNetAdmin != 0, "effective capability mask 0x" + rendered
}

func effectiveCapabilities() (uint64, string, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return 0, "", err
		}
		return mask, value, nil
	}
	return 0, "", errors.New("CapEff is absent from /proc/self/status")
}

func jailerPrivilege() (bool, string) {
	if os.Geteuid() != 0 {
		return false, fmt.Sprintf("effective uid %d is not host root", os.Geteuid())
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false, "cannot inspect user namespace: " + err.Error()
	}
	if !initialUserNamespace(string(uidMap)) {
		return false, "effective uid 0 is mapped inside a non-initial user namespace"
	}
	mask, rendered, err := effectiveCapabilities()
	if err != nil {
		return false, err.Error()
	}
	required := []struct {
		name string
		bit  uint
	}{
		{"CAP_CHOWN", 0},
		{"CAP_SETGID", 6},
		{"CAP_SETUID", 7},
		{"CAP_SYS_CHROOT", 18},
		{"CAP_SYS_ADMIN", 21},
	}
	missing := make([]string, 0, len(required))
	for _, capability := range required {
		if mask&(uint64(1)<<capability.bit) == 0 {
			missing = append(missing, capability.name)
		}
	}
	if len(missing) != 0 {
		return false, fmt.Sprintf("effective capability mask 0x%s lacks %s", rendered, strings.Join(missing, ", "))
	}
	return true, "host root has the effective namespace, identity, and chroot capabilities required by jailer"
}

func initialUserNamespace(data string) bool {
	lines := strings.Split(strings.TrimSpace(data), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 3 {
		return false
	}
	inside, insideErr := strconv.ParseUint(fields[0], 10, 64)
	outside, outsideErr := strconv.ParseUint(fields[1], 10, 64)
	length, lengthErr := strconv.ParseUint(fields[2], 10, 64)
	return insideErr == nil && outsideErr == nil && lengthErr == nil && inside == 0 && outside == 0 && length == 4294967295
}

func cgroupV2Access() (bool, string) {
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, "cannot read cgroup mount information: " + err.Error()
	}
	mount, err := UnifiedCgroupMount(string(mountInfo))
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
	for _, controller := range []string{"cpu", "memory", "pids", "cpuset"} {
		if !cgroupFieldPresent(filepath.Join(mount, "cgroup.subtree_control"), controller) {
			return false, fmt.Sprintf("cgroup v2 controller %q is not delegated at mount root", controller)
		}
	}
	if err := syscall.Access(mount, 2); err != nil {
		return false, fmt.Sprintf("cgroup v2 mount root %s is not writable: %v", mount, err)
	}
	for _, target := range []string{subtree, filepath.Join(subtree, "cgroup.procs"), filepath.Join(subtree, "cgroup.subtree_control")} {
		if _, err := os.Stat(target); err != nil {
			return false, fmt.Sprintf("required cgroup v2 path %s is unavailable: %v", target, err)
		}
		if err := syscall.Access(target, 2); err != nil {
			return false, fmt.Sprintf("current cgroup subtree %s is not writable or delegated at %s: %v", cgroup, filepath.Base(target), err)
		}
	}
	return true, fmt.Sprintf("cgroup v2 is writable and delegated at current subtree %s", cgroup)
}

func cgroupFieldPresent(path, field string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, value := range strings.Fields(string(data)) {
		if value == field || value == "+"+field {
			return true
		}
	}
	return false
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
func UnifiedCgroupMount(data string) (string, error) {
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
	return loopbackPorts(nil)
}

func loopbackPorts(ports []int) (bool, string) {
	if err := validateRequiredPorts(ports); err != nil {
		return false, err.Error()
	}
	requested := append([]int(nil), ports...)
	if len(requested) == 0 {
		requested = []int{0}
	}
	listeners := make([]net.Listener, 0, len(requested))
	closeListeners := func() error {
		var first error
		for i := len(listeners) - 1; i >= 0; i-- {
			if err := listeners[i].Close(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	bound := make([]string, 0, len(requested))
	for _, port := range requested {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			_ = closeListeners()
			return false, fmt.Sprintf("cannot bind required loopback port %d: %v", port, err)
		}
		listeners = append(listeners, listener)
		bound = append(bound, listener.Addr().String())
	}
	if err := closeListeners(); err != nil {
		return false, "cannot release loopback port probe: " + err.Error()
	}
	if len(ports) == 0 {
		return true, "dynamic loopback allocation is available at " + bound[0]
	}
	return true, fmt.Sprintf("%d configured loopback ports are available: %s", len(bound), strings.Join(bound, ", "))
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
	return cpus >= 2 && available >= MaxIdleRSSBytes, fmt.Sprintf("%d CPUs, %d bytes available RAM (need at least 2 CPUs and %d bytes)", cpus, available, MaxIdleRSSBytes)
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
	if string(pins.Architecture) != runtime.GOARCH {
		return fmt.Errorf("vmqual: toolchain architecture %s does not match native %s", pins.Architecture, runtime.GOARCH)
	}
	config = config.ApplyPins(pins)
	if err := config.Validate(); err != nil {
		return err
	}
	installer := vmimage.ToolchainInstaller{Root: config.Root}
	location, err := installer.Location(pins)
	if err != nil {
		return err
	}
	if err := installer.Verify(location); err != nil {
		return fmt.Errorf("toolchain: %w", err)
	}
	if err := verifyExecutableFile(config.FirecrackerPath, pins.Firecracker, "firecracker"); err != nil {
		return err
	}
	if err := verifyExecutableFile(config.JailerPath, pins.Jailer, "jailer"); err != nil {
		return err
	}
	manifest, err := LoadImageManifest(config.ImageManifestPath)
	if err != nil {
		return err
	}
	if err := validateManifestConsistency(config, pins, manifest, runtime.GOARCH); err != nil {
		return err
	}
	if err := verifyArtifactFile(config.KernelPath, manifest.Kernel, "kernel"); err != nil {
		return err
	}
	if err := verifyArtifactFile(config.RootFSPath, manifest.RootFS, "rootfs"); err != nil {
		return err
	}
	_, err = verifyPreparedImage(config, manifest)
	return err
}

func verifyArtifactFile(path string, artifact vmimage.ArtifactManifest, name string) error {
	return verifyRegularFile(path, artifact.Size, artifact.Mode, artifact.SHA256, name)
}

func verifyExecutableFile(path string, artifact vmimage.ArchiveMember, name string) error {
	return verifyRegularFile(path, artifact.Size, artifact.Mode, artifact.SHA256, name)
}

func verifyRegularFile(path string, size int64, mode uint32, digest, name string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s path is not absolute", name)
	}
	stat, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 || stat.Size() != size {
		return fmt.Errorf("%s metadata does not match its manifest", name)
	}
	if uint32(stat.Mode().Perm()) != mode {
		return fmt.Errorf("%s mode %04o does not match manifest %04o", name, stat.Mode().Perm(), mode)
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
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("%s sha256 mismatch", name)
	}
	return nil
}
