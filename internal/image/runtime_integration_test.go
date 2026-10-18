package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

func TestManagedRuntimeImageIntegration(t *testing.T) {
	for _, architecture := range []string{"arm64", "amd64"} {
		t.Run(architecture, func(t *testing.T) {
			containerd := runtimeFixtureELF(architecture, "github.com/containerd/containerd/v2", "v"+containerdVersion)
			runc := runtimeFixtureELF(architecture, "github.com/opencontainers/runc", "v"+runcVersion)
			for _, scenario := range []string{"install", "tampered-download", "corrupt-archive", "duplicate-executable", "wrong-architecture", "invalid-ELF", "wrong-module-version"} {
				t.Run(scenario, func(t *testing.T) {
					payload := containerd
					switch scenario {
					case "wrong-architecture":
						other := "amd64"
						if architecture == other {
							other = "arm64"
						}
						payload = runtimeFixtureELF(other, "github.com/containerd/containerd/v2", "v"+containerdVersion)
					case "invalid-ELF":
						payload = bytes.Repeat([]byte("invalid"), 32)
					case "wrong-module-version":
						payload = runtimeFixtureELF(architecture, "github.com/containerd/containerd/v2", "v0.0.1")
					}
					archive := runtimeFixtureArchive(t, payload, scenario == "duplicate-executable")
					if scenario == "corrupt-archive" {
						archive = []byte("not a gzip archive")
					}
					pin := runtimeDigests[architecture]
					originalPin := pin
					pin.containerd = fmt.Sprintf("%x", sha256.Sum256(archive))
					pin.runc = fmt.Sprintf("%x", sha256.Sum256(runc))
					runtimeDigests[architecture] = pin
					t.Cleanup(func() { runtimeDigests[architecture] = originalPin })
					if scenario == "tampered-download" {
						archive = append(bytes.Clone(archive), 'x')
					}
					runtimeFixtureHTTP(t, architecture, archive, runc)
					g, root := runtimeFixtureGuest(t)
					var output bytes.Buffer
					work := t.TempDir()
					err := installRuntime(t.Context(), g, architecture, work, &output)
					if scenario != "install" {
						expected := map[string]string{
							"tampered-download":    "SHA-256",
							"corrupt-archive":      "gzip: invalid header",
							"duplicate-executable": "invalid pinned containerd archive executable",
							"wrong-architecture":   "architecture differs from host image",
							"invalid-ELF":          "bad magic",
							"wrong-module-version": "runtime module or version differs",
						}[scenario]
						if err == nil || !strings.Contains(err.Error(), expected) {
							t.Fatalf("expected %s rejection, got %v", scenario, err)
						}
						if entries, readErr := os.ReadDir(filepath.Join(root, "usr/local/bin")); readErr != nil || len(entries) != 0 {
							t.Fatalf("rejected runtime changed guest executable directory: %v, %v", entries, readErr)
						}
						t.Logf("rejected %s: %v", scenario, err)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
						expected := containerd
						if name == "runc" {
							expected = runc
						}
						installed := filepath.Join(root, "usr/local/bin", name)
						actual, err := os.ReadFile(installed)
						if err != nil || !bytes.Equal(actual, expected) {
							t.Fatalf("installed %s bytes differ: %v", name, err)
						}
						info, err := os.Stat(installed)
						if err != nil || info.Mode().Perm() != 0755 {
							t.Fatalf("installed %s mode differs: %v", name, err)
						}
						if !strings.Contains(output.String(), "executable="+name+" architecture="+architecture) {
							t.Fatalf("missing runtime evidence for %s: %s", name, output.String())
						}
					}
					notices, err := runtimeNotices.ReadDir("runtime_licenses")
					if err != nil {
						t.Fatal(err)
					}
					for _, notice := range notices {
						expected, err := runtimeNotices.ReadFile("runtime_licenses/" + notice.Name())
						if err != nil {
							t.Fatal(err)
						}
						actual, err := os.ReadFile(filepath.Join(root, AppLib, "runtime-notices", notice.Name()))
						if err != nil || !bytes.Equal(actual, expected) {
							t.Fatalf("runtime license %s differs: %v", notice.Name(), err)
						}
					}
					runtimeFixtureSystemd(t, g, root, work, &output)
				})
			}
		})
	}
}

// The fixture contains ELF and Go build metadata; guest executable bytes are never run.
func runtimeFixtureELF(architecture, module, version string) []byte {
	data := make([]byte, 32)
	copy(data, "\xff Go buildinf:")
	data[14], data[15] = 8, 2
	for _, value := range []string{"go1.27.0", strings.Repeat("x", 16) + "path\t" + module + "/cmd/runtime\nmod\t" + module + "\t" + version + "\t\nbuild\tGOOS=linux\nbuild\tGOARCH=" + architecture + "\n" + strings.Repeat("y", 16)} {
		data = binary.AppendUvarint(data, uint64(len(value)))
		data = append(data, value...)
	}
	file := make([]byte, 4096)
	copy(file, "\x7fELF\x02\x01\x01")
	put16, put32, put64 := binary.LittleEndian.PutUint16, binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	put16(file[16:], 2)
	machine := uint16(183)
	if architecture == "amd64" {
		machine = 62
	}
	put16(file[18:], machine)
	put32(file[20:], 1)
	put64(file[32:], 64)
	put64(file[40:], 128)
	put16(file[52:], 64)
	put16(file[54:], 56)
	put16(file[56:], 1)
	put16(file[58:], 64)
	put16(file[60:], 3)
	put16(file[62:], 2)
	put32(file[64:], 1)
	put32(file[68:], 6)
	put64(file[72:], 4096)
	put64(file[80:], 0x400000)
	put64(file[96:], uint64(len(data)))
	put64(file[104:], uint64(len(data)))
	put64(file[112:], 4096)
	// Go 1.27 locates ELF build metadata through its named section, without a PT_LOAD fallback.
	put32(file[192:], 1)
	put32(file[196:], 1)
	put64(file[200:], 3)
	put64(file[208:], 0x400000)
	put64(file[216:], 4096)
	put64(file[224:], uint64(len(data)))
	put64(file[240:], 16)
	names := "\x00.go.buildinfo\x00.shstrtab\x00"
	put32(file[256:], uint32(len("\x00.go.buildinfo\x00")))
	put32(file[260:], 3)
	put64(file[280:], 320)
	put64(file[288:], uint64(len(names)))
	put64(file[304:], 1)
	copy(file[320:], names)
	return append(file, data...)
}

func runtimeFixtureArchive(t *testing.T, executable []byte, duplicate bool) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tarball := tar.NewWriter(gz)
	names := []string{"bin/containerd", "bin/containerd-shim-runc-v2"}
	if duplicate {
		names = append(names, "bin/containerd")
	}
	for _, name := range names {
		if err := tarball.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(executable)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarball.Write(executable); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tarball.Close(), gz.Close()); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

type runtimeFixtureTransport func(*http.Request) (*http.Response, error)

func (f runtimeFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func runtimeFixtureHTTP(t *testing.T, architecture string, archive, runc []byte) {
	t.Helper()
	archivePath := "/containerd/containerd/releases/download/v" + containerdVersion + "/containerd-static-" + containerdVersion + "-linux-" + architecture + ".tar.gz"
	runcPath := "/opencontainers/runc/releases/download/v" + runcVersion + "/runc." + architecture
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case archivePath:
			_, _ = w.Write(archive)
		case runcPath:
			_, _ = w.Write(runc)
		default:
			t.Errorf("unexpected runtime artifact request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	transport := server.Client().Transport
	http.DefaultTransport = runtimeFixtureTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Host != "github.com" {
			return nil, fmt.Errorf("unexpected runtime source: %s", request.URL)
		}
		request = request.Clone(request.Context())
		request.URL = request.URL.Clone()
		request.URL.Scheme, request.URL.Host = target.Scheme, target.Host
		request.Host = ""
		return transport.RoundTrip(request)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
}

// guestfish protocol operations use real files; guest root ownership is virtualized for rootless tests.
func runtimeFixtureGuest(t *testing.T) (*Guest, string) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"usr/local/bin", "usr/lib/systemd/system", "usr/local/lib", "etc/systemd/system/terrascale-orchestrator-host.service.d", "etc/systemd/system/terrascale-orchestrator-controller.service.d"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	errorsFile, err := os.CreateTemp(t.TempDir(), "guest-errors")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = errorsFile.Close() })
	g := &Guest{ctx: t.Context(), Env: os.Environ(), Errors: errorsFile, directories: map[string]bool{}}
	guestPath := func(p string) string { return filepath.Join(root, p) }
	g.exec = func(ctx context.Context, dir string, env []string, command ...string) (string, error) {
		if len(command) < 3 || command[0] != "guestfish" || command[1] != "--remote" {
			return Execute(ctx, dir, env, command...)
		}
		args := command[3:]
		switch command[2] {
		case "exists", "is-symlink":
			info, err := os.Lstat(guestPath(args[0]))
			if os.IsNotExist(err) {
				return "false", nil
			}
			if err != nil {
				return "", err
			}
			return strconv.FormatBool(command[2] == "exists" || info.Mode()&os.ModeSymlink != 0), nil
		case "lstatns":
			info, err := os.Lstat(guestPath(args[0]))
			if err != nil {
				return "", err
			}
			stat := info.Sys().(*syscall.Stat_t)
			return fmt.Sprintf("st_mode: %d\nst_uid: 0\nst_gid: 0\nst_nlink: %d", stat.Mode, stat.Nlink), nil
		case "chown":
			if args[0] != "0" || args[1] != "0" {
				return "", fmt.Errorf("unexpected guest ownership: %v", args)
			}
			_, err := os.Lstat(guestPath(args[2]))
			return "", err
		case "chmod":
			mode, err := strconv.ParseUint(args[0], 8, 32)
			if err != nil {
				return "", err
			}
			return "", os.Chmod(guestPath(args[1]), os.FileMode(mode))
		case "mkdir-p":
			return "", os.MkdirAll(guestPath(args[0]), 0755)
		case "upload":
			return "", copyFile(args[0], guestPath(args[1]), 0600)
		case "download":
			return "", copyFile(guestPath(args[0]), args[1], 0600)
		case "copy-out":
			return "", os.CopyFS(filepath.Join(args[1], filepath.Base(args[0])), os.DirFS(guestPath(args[0])))
		case "ln-s":
			return "", os.Symlink(args[0], guestPath(args[1]))
		case "readlink":
			return os.Readlink(guestPath(args[0]))
		default:
			return "", fmt.Errorf("unexpected guestfish operation: %v", command)
		}
	}
	return g, root
}

func runtimeFixtureSystemd(t *testing.T, g *Guest, root, work string, out io.Writer) {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"systemd-timesyncd.service", "systemd-time-wait-sync.service"} {
		unit := "[Unit]\nDescription=Fixture distribution time service\n[Service]\nExecStart=/usr/local/bin/containerd\n[Install]\nWantedBy=multi-user.target\n"
		if err := os.WriteFile(filepath.Join(root, "usr/lib/systemd/system", name), []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/systemd/system/ssh.socket"), []byte("[Socket]\nListenStream=22\n[Install]\nWantedBy=sockets.target\n"), 0644); err != nil {
		t.Fatal(err)
	}
	unitNames := append([]string{"terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-controller-install.service", "terrascale-orchestrator-managed-host-start.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"}, NetBirdUnits...)
	unitNames = append(unitNames, HostUnitFiles...)
	for _, name := range unitNames {
		if err := g.Upload(filepath.Join(repo, "deploy/systemd", imageUnitSource(name)), "/etc/systemd/system/"+name, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range append(append([]string{}, SelfUpdateUnitFiles...), SelfUpdateDropins...) {
		if err := g.Directory(filepath.Dir("/etc/systemd/system/"+name), 0, 0, 0755); err != nil {
			t.Fatal(err)
		}
		if err := g.Upload(filepath.Join(repo, "deploy/systemd/selfupdate", name), "/etc/systemd/system/"+name, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := installLinks(g, work, repo, out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"containerd.service", "terrascale-orchestrator-managed-host-start.service", "terrascale-orchestrator-host.service", "terrascale-orchestrator-controller.service"} {
		state, err := Execute(t.Context(), "", append(os.Environ(), "SYSTEMD_OFFLINE=1"), "systemctl", "--root="+root, "is-enabled", name)
		if err != nil || state != "enabled" {
			t.Fatalf("guest %s is not enabled: %s, %v", name, state, err)
		}
	}
	alias, err := os.Readlink(filepath.Join(root, "etc/systemd/system", selfupdate.ManagedRuntimeUnit))
	if err != nil || resolveLink(selfupdate.ManagedRuntimeUnit, alias) != "/etc/systemd/system/"+selfupdate.HostUnit {
		t.Fatalf("runtime does not share the canonical native volume cgroup: %q, %v", alias, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/systemd/system/multi-user.target.wants", selfupdate.ManagedRuntimeUnit)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("image activates a second runtime owner: %v", err)
	}
	if runtime, err := os.ReadFile(filepath.Join(root, "etc/systemd/system", selfupdate.HostUnit)); err != nil || string(runtime) != selfupdate.ManagedRuntimeService || strings.Contains(string(runtime), " host --config ") {
		t.Fatalf("canonical host starts a second native Agent: %s, %v", runtime, err)
	}
	if native, err := os.ReadFile(filepath.Join(repo, "deploy/systemd", selfupdate.HostUnit)); err != nil || !strings.Contains(string(native), " host --config ") || !strings.Contains(string(native), "KillMode=control-group") {
		t.Fatalf("legacy native host installation changed: %s, %v", native, err)
	}
	// Supply distribution targets and inert executable files so systemd verifies the real project dependency graph offline.
	for _, name := range []string{"basic", "sysinit", "sockets", "shutdown", "network", "network-online", "local-fs", "multi-user"} {
		if err := os.WriteFile(filepath.Join(root, "usr/lib/systemd/system", name+".target"), []byte("[Unit]\nDescription=Fixture distribution target\nDefaultDependencies=no\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, executable := range []string{"usr/local/bin/terrascale-orchestrator", "usr/local/bin/netbird", "usr/bin/systemctl", "bin/sh", "var/lib/terrascale-orchestrator/current/terrascale-orchestrator"} {
		p := filepath.Join(root, executable)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("fixture: never execute"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Execute(t.Context(), "", append(os.Environ(), "SYSTEMD_OFFLINE=1"), "systemd-analyze", "--root="+root, "--generators=no", "--man=no", "verify", "containerd.service", "terrascale-orchestrator-managed-host-start.service", "terrascale-orchestrator-managed-runtime.service", "terrascale-orchestrator-controller.service"); err != nil {
		t.Fatal(err)
	}
	for _, edge := range []struct{ unit, dependency string }{
		{"terrascale-orchestrator-host.service", "containerd.service"},
		{"terrascale-orchestrator-host.service", "terrascale-orchestrator-managed-host-start.service"},
	} {
		data, err := os.ReadFile(filepath.Join(root, "etc/systemd/system", edge.unit))
		if err != nil {
			t.Fatal(err)
		}
		for _, relationship := range []string{"Requires", "After"} {
			found := false
			for line := range strings.SplitSeq(string(data), "\n") {
				if value, ok := strings.CutPrefix(line, relationship+"="); ok && slices.Contains(strings.Fields(value), edge.dependency) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s lacks %s=%s", edge.unit, relationship, edge.dependency)
			}
		}
	}
	dependency := selfupdate.ControllerUnit + ".requires/" + selfupdate.HostUnit
	if target, err := os.Readlink(filepath.Join(root, "etc/systemd/system", dependency)); err != nil || resolveLink(dependency, target) != "/etc/systemd/system/"+selfupdate.HostUnit {
		t.Fatalf("controller lacks the required shared runtime: %q, %v", target, err)
	}
	for relative, expected := range map[string]string{
		selfupdate.HostUnit + ".d/90-managed-runtime.conf":                                   selfupdate.ManagedRuntimeHostDropin,
		selfupdate.ControllerUnit + ".d/90-managed-runtime.conf":                             selfupdate.ManagedRuntimeControllerDropin,
		"terrascale-orchestrator-selfupdate-watchdog@host.service.d/90-managed-runtime.conf": selfupdate.ManagedRuntimeWatchdogDropin,
	} {
		if contents, err := os.ReadFile(filepath.Join(root, "etc/systemd/system", relative)); err != nil || string(contents) != expected {
			t.Fatalf("shared runtime contract differs: %s: %s, %v", relative, contents, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/systemd/system", selfupdate.HostUnit+".d/65-netbird-agent.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("image installs controller-dependent native host ordering: %v", err)
	}
	dropins, err := os.ReadDir(filepath.Join(root, "etc/systemd/system", selfupdate.HostUnit+".d"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dropin := range dropins {
		contents, err := os.ReadFile(filepath.Join(root, "etc/systemd/system", selfupdate.HostUnit+".d", dropin.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(contents), "\n") {
			if value, ok := strings.CutPrefix(line, "After="); ok && (slices.Contains(strings.Fields(value), selfupdate.NetBirdAgentUnit) || slices.Contains(strings.Fields(value), selfupdate.HostSetupUnit)) {
				t.Fatalf("runtime waits for controller-dependent enrollment: %s: %s", dropin.Name(), line)
			}
		}
	}
	if !strings.Contains(selfupdate.ManagedRuntimeHostDropin, "InaccessiblePaths=\n") || !strings.Contains(selfupdate.ManagedRuntimeHostDropin, "KillMode=process\n") ||
		!strings.Contains(selfupdate.ManagedRuntimeService, "PartOf="+selfupdate.ControllerUnit+"\n") || !strings.Contains(selfupdate.ManagedRuntimeService, "Before="+selfupdate.ControllerUnit+"\n") ||
		selfupdate.ManagedRuntimeControllerDropin[strings.LastIndex(selfupdate.ManagedRuntimeControllerDropin, "ExecStartPre="):] != "ExecStartPre=\n" {
		t.Fatal("shared runtime lacks fixed restart, isolation or single prepare ordering")
	}
	for _, role := range []string{"host", "controller"} {
		data, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/terrascale-orchestrator-"+role+".service.d/70-containerd.conf"))
		if err != nil || !slices.Contains(strings.Split(string(data), "\n"), "Requires=containerd.service") || !slices.Contains(strings.Split(string(data), "\n"), "After=containerd.service") {
			t.Fatalf("%s boot lacks required containerd ordering: %s, %v", role, data, err)
		}
	}
}
