package vmqual

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

func TestUnifiedCgroupPath(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{name: "root", data: "0::/\n", want: "/"},
		{name: "nested", data: "12:cpu:/legacy\n0::/user.slice/user-1000.slice/session.scope\n", want: "/user.slice/user-1000.slice/session.scope"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := unifiedCgroupPath(test.data)
			if err != nil || got != test.want {
				t.Fatalf("unifiedCgroupPath() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for _, data := range []string{"0:cpu:/x\n", "0::../escape\n", "0::/a/../b\n", "0::/a//b\n"} {
		if _, err := unifiedCgroupPath(data); err == nil {
			t.Fatalf("unifiedCgroupPath(%q) accepted unsafe or absent path", data)
		}
	}
}

func TestUnifiedCgroupMount(t *testing.T) {
	data := "36 29 0:32 / /run/cgroup2 rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
	if got, err := UnifiedCgroupMount(data); err != nil || got != "/run/cgroup2" {
		t.Fatalf("unifiedCgroupMount() = %q, %v", got, err)
	}
	data = "36 29 0:32 / /run/cgroup\\040v2 rw - cgroup2 cgroup rw\n"
	if got, err := UnifiedCgroupMount(data); err != nil || got != "/run/cgroup v2" {
		t.Fatalf("escaped unifiedCgroupMount() = %q, %v", got, err)
	}
	if _, err := UnifiedCgroupMount("36 29 0:32 / /run/cgroup2 rw - tmpfs tmpfs rw\n"); err == nil {
		t.Fatal("non-cgroup2 mount accepted")
	}
}

func TestCgroupSubtreeRejectsTraversal(t *testing.T) {
	if got, err := cgroupSubtree("/run/cgroup2", "/user.slice/worker.scope"); err != nil || got != "/run/cgroup2/user.slice/worker.scope" {
		t.Fatalf("cgroupSubtree() = %q, %v", got, err)
	}
	for _, mount := range []string{"relative", "/run/cgroup2/.."} {
		if _, err := cgroupSubtree(mount, "/worker.scope"); err == nil {
			t.Fatalf("cgroupSubtree(%q) accepted unsafe mount", mount)
		}
	}
	for _, cgroup := range []string{"relative", "/../escape", "/worker/../escape"} {
		if _, err := cgroupSubtree("/run/cgroup2", cgroup); err == nil {
			t.Fatalf("cgroupSubtree(%q) accepted unsafe cgroup", cgroup)
		}
	}
}

func TestCgroupFieldPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cgroup.subtree_control")
	if err := os.WriteFile(path, []byte("+cpu +memory pids\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"cpu", "memory", "pids"} {
		if !cgroupFieldPresent(path, field) {
			t.Fatalf("cgroupFieldPresent(%q) = false", field)
		}
	}
	if cgroupFieldPresent(path, "cpuset") {
		t.Fatal("cgroupFieldPresent accepted an absent controller")
	}
	if cgroupFieldPresent(filepath.Join(filepath.Dir(path), "missing"), "cpu") {
		t.Fatal("cgroupFieldPresent accepted a missing file")
	}
}

func TestToolVersionAcceptsCanonicalFirecrackerAndJailerOutput(t *testing.T) {
	for _, test := range []struct {
		component string
		output    string
	}{
		{component: "firecracker", output: "Firecracker v1.15.1"},
		{component: "firecracker", output: "firecracker 1.15.1"},
		{component: "jailer", output: "Jailer v1.15.1"},
		{component: "jailer", output: "jailer 1.15.1"},
	} {
		t.Run(test.component+"/"+test.output, func(t *testing.T) {
			path := writeVersionTool(t, test.output)
			ok, detail := verifyToolVersion(context.Background(), path, test.component, "1.15.1", time.Second)
			if !ok {
				t.Fatalf("verifyToolVersion() = false, %s", detail)
			}
		})
	}
}

func TestToolVersionRejectsWrongComponentVersionAndTimeout(t *testing.T) {
	for _, test := range []struct {
		component string
		output    string
	}{
		{component: "firecracker", output: "Jailer v1.15.1"},
		{component: "firecracker", output: "Firecracker v1.15.0"},
		{component: "jailer", output: "Jailer v1.15.1 unexpected"},
		{component: "jailer", output: ""},
	} {
		path := writeVersionTool(t, test.output)
		if ok, _ := verifyToolVersion(context.Background(), path, test.component, "1.15.1", time.Second); ok {
			t.Fatalf("verifyToolVersion(%q, %q) accepted invalid output", test.component, test.output)
		}
	}
	path := filepath.Join(t.TempDir(), "slow-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if ok, detail := verifyToolVersion(context.Background(), path, "firecracker", "1.15.1", 30*time.Millisecond); ok || !strings.Contains(detail, "deadline") {
		t.Fatalf("timeout result = %v, %q", ok, detail)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded version probe took %s", elapsed)
	}
}

func TestVerifySDKPinRequiresOfficialDirectModuleAndBothSums(t *testing.T) {
	const (
		module  = "github.com/firecracker-microvm/firecracker-go-sdk"
		version = "v1.0.0"
	)
	validSum := func(value byte) string {
		return "h1:" + base64.StdEncoding.EncodeToString(bytesOf(value, sha256.Size))
	}
	validGoMod := "module example.test/doctor\n\ngo 1.27\n\nrequire (\n\t" + module + " " + version + "\n)\n"
	validGoSum := module + " " + version + " " + validSum(1) + "\n" + module + " " + version + "/go.mod " + validSum(2) + "\n"

	root := writeModuleFiles(t, validGoMod, validGoSum)
	if ok, detail := verifySDKPin(root, module, version); !ok {
		t.Fatalf("verifySDKPin() = false, %s", detail)
	}
	for _, test := range []struct {
		name, goMod, goSum, requestedModule string
	}{
		{name: "unofficial", goMod: validGoMod, goSum: validGoSum, requestedModule: "example.test/firecracker-fork"},
		{name: "indirect", goMod: strings.Replace(validGoMod, version, version+" // indirect", 1), goSum: validGoSum, requestedModule: module},
		{name: "replacement", goMod: validGoMod + "\nreplace " + module + " => ../fork\n", goSum: validGoSum, requestedModule: module},
		{name: "excluded", goMod: validGoMod + "\nexclude " + module + " " + version + "\n", goSum: validGoSum, requestedModule: module},
		{name: "missing module sum", goMod: validGoMod, goSum: module + " " + version + "/go.mod " + validSum(2) + "\n", requestedModule: module},
		{name: "missing go-mod sum", goMod: validGoMod, goSum: module + " " + version + " " + validSum(1) + "\n", requestedModule: module},
		{name: "malformed sum", goMod: validGoMod, goSum: module + " " + version + " h1:not-base64\n" + module + " " + version + "/go.mod " + validSum(2) + "\n", requestedModule: module},
		{name: "duplicate sum", goMod: validGoMod, goSum: validGoSum + module + " " + version + " " + validSum(3) + "\n", requestedModule: module},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := writeModuleFiles(t, test.goMod, test.goSum)
			if ok, _ := verifySDKPin(root, test.requestedModule, version); ok {
				t.Fatal("verifySDKPin() accepted unverified SDK dependency")
			}
		})
	}
}

func TestRepositorySDKPinIsBackedByGoModAndGoSum(t *testing.T) {
	const module = "github.com/firecracker-microvm/firecracker-go-sdk"
	if ok, detail := verifySDKPin(repositoryRoot(), module, "v1.0.0"); !ok {
		t.Fatalf("repository SDK pin is not verified: %s", detail)
	}
}

func TestArchitectureSpecificManifestsAreConsistent(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			pinsPath, err := filepath.Abs(filepath.Join("..", "vmimage", "pins-"+architecture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			imagePath, err := filepath.Abs(filepath.Join("..", "vmimage", "ubuntu-24.04.3-"+architecture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			pins, err := LoadPins(pinsPath)
			if err != nil {
				t.Fatal(err)
			}
			image, err := LoadImageManifest(imagePath)
			if err != nil {
				t.Fatal(err)
			}
			config := manifestBackedConfig(pins, image)
			if err := validateManifestConsistency(config, pins, image, architecture); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManifestConsistencyRejectsCrossArchitectureVersionAndOverrides(t *testing.T) {
	pinsPath, err := filepath.Abs(filepath.Join("..", "vmimage", "pins-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	imagePath, err := filepath.Abs(filepath.Join("..", "vmimage", "ubuntu-24.04.3-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := LoadPins(pinsPath)
	if err != nil {
		t.Fatal(err)
	}
	image, err := LoadImageManifest(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	base := manifestBackedConfig(pins, image)

	wrongArchitecture := image
	wrongArchitecture.Architecture = vmimage.ArchitectureARM64
	wrongVersion := image
	wrongVersion.Version = "24.04.3-fc1.14.0"
	wrongOverride := base
	wrongOverride.ExpectedRootFSSHA256 = strings.Repeat("b", 64)
	wrongSDK := base
	wrongSDK.SDKModule = "example.test/firecracker-fork"
	for _, test := range []struct {
		name   string
		config Config
		image  vmimage.GuestImageManifest
	}{
		{name: "architecture", config: base, image: wrongArchitecture},
		{name: "version", config: base, image: wrongVersion},
		{name: "checksum override", config: wrongOverride, image: image},
		{name: "SDK override", config: wrongSDK, image: image},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManifestConsistency(test.config, pins, test.image, "amd64"); err == nil {
				t.Fatal("validateManifestConsistency() accepted mismatched manifests")
			}
		})
	}
}

func TestLoopbackPortChecksConfiguredPortsTogetherAndReleasesOnFailure(t *testing.T) {
	if ok, detail := loopbackPorts(nil); !ok {
		t.Fatalf("dynamic port probe failed: %s", detail)
	}
	first := reservePortNumber(t)
	blocked, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	second := blocked.Addr().(*net.TCPAddr).Port
	if ok, _ := loopbackPorts([]int{first, second}); ok {
		t.Fatal("loopbackPorts() accepted an occupied configured port")
	}
	reused, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", first))
	if err != nil {
		t.Fatalf("first listener leaked after partial failure: %v", err)
	}
	_ = reused.Close()
}

func TestInitialUserNamespaceRecognition(t *testing.T) {
	if !initialUserNamespace("         0          0 4294967295\n") {
		t.Fatal("initial user namespace was not recognized")
	}
	for _, data := range []string{
		"0 1000 1\n",
		"0 0 65536\n",
		"0 0 4294967295\n1 1 1\n",
		"invalid\n",
	} {
		if initialUserNamespace(data) {
			t.Fatalf("non-initial mapping %q was accepted", data)
		}
	}
}

func TestRunDoctorDoesNotCreateQualificationRoot(t *testing.T) {
	clearVMManifestEnvironment(t)
	config := defaultConfigForArchitecture(runtimeArchitectureForTest(t))
	root := filepath.Join(t.TempDir(), "absent-qualification-root")
	config.Root = root
	config.StateRoot = filepath.Join(root, "state")
	config.JournalPath = filepath.Join(root, "journal.json")
	config.ImageCacheRoot = filepath.Join(root, "images")
	config.ReadinessRoot = filepath.Join(root, "readiness")
	config.GuestControlPath = filepath.Join(root, "bin", "vm-guest-control")
	report := RunDoctor(context.Background(), config)
	if len(report.Checks) == 0 {
		t.Fatal("RunDoctor() returned no checks")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("RunDoctor() changed qualification root: %v", err)
	}
	for _, name := range []string{"firecracker", "jailer", "fc-version", "jailer-version", "sdk", "image-manifest", "image-receipt", "manifest-pair", "ports", "resources", "disk"} {
		if !reportHasCheck(report, name) {
			t.Fatalf("RunDoctor() omitted %q check", name)
		}
	}
}

func writeVersionTool(t *testing.T, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "version-tool")
	script := "#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 12\nprintf '%s\\n' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func bytesOf(value byte, length int) []byte {
	data := make([]byte, length)
	for index := range data {
		data[index] = value
	}
	return data
}

func writeModuleFiles(t *testing.T, goMod, goSum string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte(goSum), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func manifestBackedConfig(pins vmimage.ToolchainManifest, image vmimage.GuestImageManifest) Config {
	return Config{
		ExpectedVersion:           pins.FirecrackerVersion,
		ExpectedFirecrackerSHA256: pins.Firecracker.SHA256,
		ExpectedJailerSHA256:      pins.Jailer.SHA256,
		SDKModule:                 pins.SDKModule,
		SDKVersion:                pins.SDKVersion,
		ExpectedKernelSHA256:      image.Kernel.SHA256,
		ExpectedRootFSSHA256:      image.RootFS.SHA256,
	}
}

func reservePortNumber(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func reportHasCheck(report DoctorReport, name string) bool {
	for _, check := range report.Checks {
		if check.Name == name {
			return true
		}
	}
	return false
}

func runtimeArchitectureForTest(t *testing.T) string {
	t.Helper()
	for _, architecture := range []string{"amd64", "arm64"} {
		pinsPath := filepath.Join("..", "vmimage", "pins-"+architecture+".json")
		if absolute, err := filepath.Abs(pinsPath); err == nil {
			pins, loadErr := LoadPins(absolute)
			if loadErr == nil && string(pins.Architecture) == architecture && HostPlatform() == "linux/"+architecture {
				return architecture
			}
		}
	}
	t.Skip("doctor root mutation check requires native Linux amd64 or arm64")
	return ""
}

func TestVerifyExecutableFileChecksExactBytesMetadataAndNoSymlink(t *testing.T) {
	data := []byte("executable")
	digest := sha256.Sum256(data)
	path := filepath.Join(t.TempDir(), "firecracker")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	pin := vmimage.ArchiveMember{Name: "firecracker", Size: int64(len(data)), Mode: 0o755, SHA256: hex.EncodeToString(digest[:])}
	if err := verifyExecutableFile(path, pin, "firecracker"); err != nil {
		t.Fatal(err)
	}
	pin.SHA256 = strings.Repeat("a", 64)
	if err := verifyExecutableFile(path, pin, "firecracker"); err == nil {
		t.Fatal("wrong executable digest was accepted")
	}
	link := filepath.Join(filepath.Dir(path), "jailer")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	pin.SHA256 = hex.EncodeToString(digest[:])
	if err := verifyExecutableFile(link, pin, "jailer"); err == nil {
		t.Fatal("executable symlink was accepted")
	}
}
