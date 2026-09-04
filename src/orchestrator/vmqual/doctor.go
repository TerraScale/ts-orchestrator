package vmqual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type Check struct {
	Name   string
	OK     bool
	Detail string
	Repair string
}
type DoctorReport struct{ Checks []Check }

func (r DoctorReport) OK() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}
func (r DoctorReport) Error() error {
	if r.OK() {
		return nil
	}
	return errors.New("vmqual: host is not eligible for Firecracker qualification")
}

func (r DoctorReport) Write(w io.Writer) {
	for _, c := range r.Checks {
		state := "FAIL"
		if c.OK {
			state = "OK"
		}
		_, _ = fmt.Fprintf(w, "%s %-18s %s\n", state, c.Name, c.Detail)
		if !c.OK && c.Repair != "" {
			_, _ = fmt.Fprintf(w, "      repair: %s\n", c.Repair)
		}
	}
}

// RunDoctor performs read-only checks. It does not create directories, invoke
// ip/nft/tc, start Firecracker, or alter any host resource.
func RunDoctor(ctx context.Context, config Config) DoctorReport {
	report := DoctorReport{}
	add := func(name string, ok bool, detail, repair string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail, Repair: repair})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	add("platform", runtime.GOOS == "linux", HostPlatform(), "run on a native Linux host; software emulation is not supported")
	kvmOK, kvmDetail := writableKVM()
	add("kvm", kvmOK, kvmDetail, "grant the qualification runner narrow writable access to /dev/kvm")
	if err := config.Validate(); err != nil {
		add("configuration", false, err.Error(), "set TS_VM_ROOT, TS_VM_PINS and the pinned image manifest")
	} else {
		add("configuration", true, "paths and resource limits are valid", "")
	}
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		add("pins", false, err.Error(), "provide a checked-in, versioned pin manifest with SHA-256 digests")
	} else {
		config = config.applyPins(pins)
		add("pins", true, "host and guest artifacts are declared", "")
		for name, pin := range map[string]ArtifactPin{"firecracker": pins.Firecracker, "jailer": pins.Jailer, "kernel": pins.Kernel, "rootfs": pins.RootFS} {
			ok, detail := verifyPinnedFile(pin, name)
			add(name, ok, detail, "restore the exact versioned release asset whose published digest is pinned")
		}
		add("sdk", strings.Contains(config.SDKModule, "firecracker") && config.SDKVersion == pins.SDKVersion, config.SDKModule+"@"+config.SDKVersion, "pin the official Firecracker Go SDK in go.mod")
	}
	for _, tool := range []string{"ip", "nft", "tc"} {
		path, err := exec.LookPath(tool)
		add(tool, err == nil, pathOrError(path, err), "install the host fault tool without using a container runtime")
	}
	if config.Root != "" {
		ok, detail := diskBudget(config.Root, 4<<30)
		add("disk", ok, detail, "make at least 4 GiB available for the six-guest qualification stack")
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
	st, err := os.Stat("/dev/kvm")
	if err != nil {
		return false, err.Error()
	}
	if st.Mode()&os.ModeDevice == 0 {
		return false, "/dev/kvm is not a device"
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return false, err.Error()
	}
	_ = f.Close()
	return true, "/dev/kvm is writable"
}
func verifyPinnedFile(pin ArtifactPin, name string) (bool, string) {
	if pin.Path == "" || !filepath.IsAbs(pin.Path) {
		return false, name + " path is not absolute"
	}
	f, err := os.Open(pin.Path)
	if err != nil {
		return false, err.Error()
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, err.Error()
	}
	if st.IsDir() {
		return false, "artifact is a directory"
	}
	if (name == "firecracker" || name == "jailer") && st.Mode()&0111 == 0 {
		return false, "executable is not executable"
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err.Error()
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, pin.SHA256) {
		return false, "sha256 mismatch: got " + got
	}
	return true, pin.Path + " sha256=" + pin.SHA256
}
func diskBudget(path string, need uint64) (bool, string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return false, err.Error()
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	return free >= need, fmt.Sprintf("%d bytes free (need %d)", free, need)
}

// VerifyPinnedFiles is useful to vm-image and tests that want the artifact
// gate without emitting a host report.
func VerifyPinnedFiles(config Config) error {
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		return err
	}
	for name, pin := range map[string]ArtifactPin{"firecracker": pins.Firecracker, "jailer": pins.Jailer, "kernel": pins.Kernel, "rootfs": pins.RootFS} {
		if ok, detail := verifyPinnedFile(pin, name); !ok {
			return fmt.Errorf("%s: %s", name, detail)
		}
	}
	return nil
}
