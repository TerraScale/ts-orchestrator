//go:build linux

package execution_test

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const renewalMemberExecutable = "/source-renewal-member"

// The same disposable test binary supplies the workload, including when cgo
// needs the host's ELF loader. No TerraBase binary is fetched or executed.
func init() {
	if os.Args[0] != renewalMemberExecutable {
		return
	}
	if os.Getpid() != 1 || os.Geteuid() == 0 {
		os.Exit(70)
	}
	if err := renewalMemberMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(71)
	}
	os.Exit(0)
}

func newRenewalContainerd(t *testing.T, directory string) *containerd.Client {
	t.Helper()
	for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("renewal runtime prerequisite %s: %v", name, err)
		}
	}
	log, err := os.OpenFile(filepath.Join(directory, "containerd.log"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	socket := filepath.Join(directory, "daemon.sock")
	command := exec.Command("nice", "-n", "19", "containerd", "--config", "/dev/null", "--root", filepath.Join(directory, "root"),
		"--state", filepath.Join(directory, "state"), "--address", socket, "--log-level", "error")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	client, err := containerd.New(socket, containerd.WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		if _, err := client.Version(ctx); err == nil {
			return client
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("owned renewal containerd exited: %v", err)
		case <-ctx.Done():
			t.Fatal("owned renewal containerd did not become ready")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func renewalLoopVolume(t *testing.T, directory, mount string) hostvolume.MountPins {
	t.Helper()
	image := filepath.Join(directory, "retained.ext4")
	file, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(32 << 20); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	device := strings.TrimSpace(renewalCommand(t, t.Context(), "losetup", "--find", "--show", "--nooverlap", image))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		renewalCommand(t, ctx, "losetup", "--detach", device)
	})
	id := uuid.New().String()
	tool, args, err := hostvolume.FormatCommand("ext4", id)
	if err != nil {
		t.Fatal(err)
	}
	renewalCommand(t, t.Context(), tool, append(args, device)...)
	if actual := strings.TrimSpace(renewalCommand(t, t.Context(), "blkid", "-p", "-s", "UUID", "-o", "value", device)); actual != id {
		t.Fatalf("fixture UUID readback = %q, want %q", actual, id)
	}
	alias := filepath.Join("/dev/disk/by-uuid", id)
	if err := os.Symlink(device, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(alias); err != nil {
			t.Error(err)
		}
	})
	if err := os.MkdirAll(mount, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(device, mount, "ext4", hostvolume.MountFlags, hostvolume.FilesystemData("ext4")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mount, 0); err != nil {
			t.Error(err)
		}
	})
	for _, path := range []string{mount, filepath.Join(mount, "data"), filepath.Join(mount, "replication")} {
		mode, uid := os.FileMode(0o700), 65532
		if path == mount {
			mode, uid = 0o750, 0
		} else if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	pins := hostvolume.MountPins{DevicePath: device, MountPath: mount, FileSystemUUID: id, FileSystemType: "ext4", UID: 65532, GID: 65532}
	witness, err := hostvolume.ObserveMount(pins)
	if err != nil {
		t.Fatal(err)
	}
	witness.Close()
	return pins
}

func renewalCommand(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "nice", append([]string{"-n", "19", name}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("disposable fixture command %s: %v: %s", name, err, output)
	}
	return string(output)
}

// renewalMemberImage retains the exact local workload bytes in containerd's
// content store and unpacks them with the same native snapshotter as production.
func renewalMemberImage(t *testing.T, client *containerd.Client, environment []string) (containerd.Image, map[string][]byte) {
	t.Helper()
	ctx := namespaces.WithNamespace(t.Context(), "terrascale")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{renewalMemberExecutable: executable}
	var addELF func(string)
	addELF = func(path string) {
		image, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer image.Close()
		for _, program := range image.Progs {
			if program.Type != elf.PT_INTERP {
				continue
			}
			wire, err := io.ReadAll(program.Open())
			if err != nil {
				t.Fatal(err)
			}
			loader := strings.TrimRight(string(wire), "\x00")
			if _, exists := files[loader]; !exists {
				files[loader] = loader
				addELF(loader)
			}
		}
		libraries, err := image.ImportedLibraries()
		if err != nil {
			t.Fatal(err)
		}
		for _, library := range libraries {
			found := false
			for _, directory := range []string{"/lib", "/lib64", "/usr/lib", "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu"} {
				path := filepath.Join(directory, library)
				if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
					continue
				}
				found = true
				if _, exists := files[path]; !exists {
					files[path] = path
					addELF(path)
				}
				break
			}
			if !found {
				t.Fatalf("fixture ELF library %s is unavailable", library)
			}
		}
	}
	addELF(executable)
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	for _, destination := range slices.Sorted(maps.Keys(files)) {
		wire, err := os.ReadFile(files[destination])
		if err != nil {
			t.Fatal(err)
		}
		if err := archive.WriteHeader(&tar.Header{Name: strings.TrimPrefix(destination, "/"), Mode: 0o755, Size: int64(len(wire)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	put := func(mediaType string, wire []byte) ocispec.Descriptor {
		t.Helper()
		descriptor := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(wire), Size: int64(len(wire))}
		if err := content.WriteBlob(ctx, client.ContentStore(), "source-renewal-"+descriptor.Digest.Encoded(), bytes.NewReader(wire), descriptor); err != nil {
			t.Fatal(err)
		}
		return descriptor
	}
	layerDescriptor := put(ocispec.MediaTypeImageLayer, layer.Bytes())
	config := ocispec.Image{Platform: ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"},
		Config: ocispec.ImageConfig{User: "65532:65532", Entrypoint: []string{renewalMemberExecutable}, Env: environment},
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDescriptor.Digest}}}
	configWire, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: put(ocispec.MediaTypeImageConfig, configWire), Layers: []ocispec.Descriptor{layerDescriptor}}
	manifest.SchemaVersion = 2
	manifestWire, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDescriptor := put(ocispec.MediaTypeImageManifest, manifestWire)
	record, err := client.ImageService().Create(ctx, images.Image{Name: "fixture.invalid/terrabase@" + manifestDescriptor.Digest.String(), Target: manifestDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	image := containerd.NewImage(client, record)
	if err := image.Unpack(ctx, "native"); err != nil {
		t.Fatal(err)
	}
	return image, map[string][]byte{manifestDescriptor.Digest.Encoded(): manifestWire, manifest.Config.Digest.Encoded(): configWire}
}

func renewalStartMember(t *testing.T, client *containerd.Client, image containerd.Image, pins execution.RuntimePins) containerd.Task {
	t.Helper()
	ctx := namespaces.WithNamespace(t.Context(), "terrascale")
	id := "ts-" + pins.Task.ID
	spec := &runtimespec.Spec{Version: runtimespec.Version, Process: &pins.Process, Root: &runtimespec.Root{Path: "rootfs", Readonly: true}, Mounts: pins.Mounts,
		Linux: &runtimespec.Linux{Namespaces: pins.Namespaces, Resources: &pins.Resources, CgroupsPath: "/terrascale/" + id}}
	container, err := client.NewContainer(ctx, id, containerd.WithImage(image), containerd.WithSnapshotter("native"), containerd.WithNewSnapshot(id, image),
		containerd.WithRuntime("io.containerd.runc.v2", nil), containerd.WithSpec(spec), containerd.WithContainerLabels(map[string]string{
			"terrascale.task": pins.Task.ID, "terrascale.service": pins.Task.ServiceID, "terrascale.spec": pins.ContainerSpecSHA256, "terrascale.task-binding": pins.ContainerSpecSHA256}))
	if err != nil {
		t.Fatal(err)
	}
	var process containerd.Task
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), "terrascale"), 10*time.Second)
		defer cancel()
		if process != nil {
			if _, err := process.Delete(cleanup, containerd.WithProcessKill); err != nil {
				t.Error(err)
			}
		}
		if err := container.Delete(cleanup, containerd.WithSnapshotCleanup); err != nil {
			t.Error(err)
		}
	})
	process, err = container.NewTask(ctx, cio.NullIO)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return process
}

func renewalMemberMain() error {
	arguments := make(map[string]string)
	for i := 1; i+1 < len(os.Args); i += 2 {
		arguments[os.Args[i]] = os.Args[i+1]
	}
	var authority memberstatus.Authority
	if err := json.Unmarshal([]byte(os.Getenv("TS_SOURCE_RENEWAL_AUTHORITY")), &authority); err != nil {
		return err
	}
	shard, err := strconv.ParseUint(arguments["--shard-id"], 10, 64)
	if err != nil {
		return err
	}
	scope := memberstatus.Scope{ClusterID: arguments["--cluster-id"], TenantID: arguments["--tenant-id"], DatabaseID: arguments["--database-id"], ShardID: shard,
		MemberID: arguments["--member-id"], Incarnation: arguments["--member-incarnation"]}
	listener, err := net.Listen("unix", arguments["--member-control-socket"])
	if err != nil {
		return err
	}
	if err := os.Chmod(listener.Addr().String(), 0o602); err != nil {
		_ = listener.Close()
		return err
	}
	process := memberstatus.Process{PID: 1, StartNonce: strings.Repeat("1", 32)}
	marker := func(name string) error {
		return os.WriteFile(filepath.Join(arguments["--data-dir"], "fixture-"+name), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600)
	}
	if err := marker("started"); err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/backup/prepare" && r.Method == http.MethodPost {
			if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10)); err != nil {
				return
			}
			if err := marker("prepare-started"); err != nil {
				w.WriteHeader(500)
				return
			}
			for {
				select {
				case <-r.Context().Done():
					_ = marker("prepare-canceled")
					return
				case <-time.After(20 * time.Millisecond):
					if _, err := os.Stat(filepath.Join(arguments["--data-dir"], "fixture-prepare-release")); err == nil {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"version":1,"payload":"fixture-cut","signature":"fixture-signature"}`)
						return
					}
				}
			}
		}
		if r.URL.Path != "/v1/member/status" || r.Method != http.MethodGet {
			w.WriteHeader(404)
			return
		}
		reply := memberstatus.Status{SchemaVersion: 2, Nonce: r.URL.Query().Get("nonce"), Process: process, Scope: scope, Authority: authority,
			Local: memberstatus.Local{StorageRecovered: true, ReplicationListenerReady: true}, Capabilities: memberstatus.Capabilities{ServingProof: true, DurableDrain: true}, CredentialGeneration: 1}
		wire, err := json.Marshal(reply)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		_, _ = w.Write(wire)
	})}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
