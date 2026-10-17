package bootstrapstart

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"golang.org/x/sys/unix"
)

func TestServiceMaterialInstallIsExactNoReplaceAndOwnerOnly(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "service-secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := MaterialStore{installedDirectory: directory, serviceUID: uint32(os.Getuid()),
		serviceGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
	fd, err := openMaterialDirectory(directory, store.serviceUID, store.serviceGID, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	content := []byte("exact credential fixture")
	want := digest(content)
	if err := store.installMaterial(fd, "controller.jwt", content, want, 128); err != nil {
		t.Fatal(err)
	}
	if err := store.installMaterial(fd, "controller.jwt", content, want, 128); err != nil {
		t.Fatalf("idempotent exact existing credential: %v", err)
	}
	if err := store.installMaterial(fd, "controller.jwt", []byte("changed"), digest([]byte("changed")), 128); !errors.Is(err, ErrMaterial) {
		t.Fatalf("changed existing credential = %v, want refusal", err)
	}
	path := filepath.Join(directory, "controller.jwt")
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("installed mode = %v, %v", info.Mode(), err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readMaterial(fd, "controller.jwt", store.serviceUID, store.serviceGID, want, 128); !errors.Is(err, ErrMaterial) {
		t.Fatalf("group-readable credential = %v, want refusal", err)
	}
}

func TestServiceMaterialRejectsSymlinkAndUntrustedParent(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "service-secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := openMaterialDirectory(directory, uint32(os.Getuid()), uint32(os.Getgid()), 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Symlink("/etc/passwd", filepath.Join(directory, "controller.jwt")); err != nil {
		t.Fatal(err)
	}
	if _, err := readMaterial(fd, "controller.jwt", uint32(os.Getuid()), uint32(os.Getgid()), digest([]byte("anything")), 128); err == nil {
		t.Fatal("followed symlink credential")
	}
	if _, err := openMaterialDirectory(directory, uint32(os.Getuid()), uint32(os.Getgid()), 0o700, false); !errors.Is(err, ErrMaterial) {
		t.Fatalf("untrusted parent = %v, want refusal", err)
	}
}

func TestServiceUIDCanReadRootInstalledMaterial(t *testing.T) {
	if os.Getenv("TS_BOOTSTRAP_MATERIAL_CHILD") == "1" {
		path := os.Getenv("TS_BOOTSTRAP_MATERIAL_DIR")
		want := os.Getenv("TS_BOOTSTRAP_MATERIAL_SHA256")
		fd, err := openMaterialDirectory(path, 0, 0, 0o755, true)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		content, err := readMaterial(fd, "controller.jwt", uint32(os.Getuid()), uint32(os.Getgid()), want, 128)
		if err != nil || string(content) != "root installed fixture" {
			t.Fatalf("unprivileged material read = %q, %v", content, err)
		}
		clear(content)
		for _, name := range []string{"system.creds", "membership.creds", "controller-account-signer.seed", "controller-tls-issuer-key.pem", "route-password", "controller-a-tls-key.pem", "controller-b-tls-key.pem", "controller-c-tls-key.pem", bootstrap.LinkCredentialsFile, "interregion-tls-controller-a-key.pem", "interregion-tls-controller-b-key.pem", "interregion-tls-controller-c-key.pem", "leaf-sfo.creds"} {
			if _, err := os.ReadFile(filepath.Join(path, name)); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("ordinary %s read: %v", name, err)
			}
		}
		if err := os.Remove(filepath.Join(path, "controller.jwt")); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("ordinary installed-client unlink: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "replacement"), []byte("replacement"), 0o600); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("ordinary credential parent mutation: %v", err)
		}
		stage := filepath.Join(path, generationStaging)
		if _, err := os.ReadFile(filepath.Join(stage, "controller.jwt")); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("ordinary adoption-stage read: %v", err)
		}
		if err := os.Rename(stage, stage+"-replacement"); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("ordinary adoption-stage replacement: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root-to-service process credential test requires root")
	}
	service, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no dedicated unprivileged fixture account: %v", err)
	}
	uid, err := strconv.ParseUint(service.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatal("unprivileged fixture UID is invalid")
	}
	gid, err := strconv.ParseUint(service.Gid, 10, 32)
	if err != nil || gid == 0 {
		t.Fatal("unprivileged fixture GID is invalid")
	}
	base := t.TempDir()
	// t.TempDir nests the returned directory below a 0700 test parent.
	if err := os.Chmod(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "service-secrets")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	store := MaterialStore{installedDirectory: directory, serviceUID: uint32(uid), serviceGID: uint32(gid), allowUnsafeAncestors: true}
	fd, err := openMaterialDirectory(directory, 0, 0, 0o755, true)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("root installed fixture")
	want := digest(content)
	if err := store.installMaterial(fd, "controller.jwt", content, want, 128); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	for _, name := range []string{"system.creds", "membership.creds", "controller-account-signer.seed", "controller-tls-issuer-key.pem", "route-password", "controller-a-tls-key.pem", "controller-b-tls-key.pem", "controller-c-tls-key.pem", bootstrap.LinkCredentialsFile, "interregion-tls-controller-a-key.pem", "interregion-tls-controller-b-key.pem", "interregion-tls-controller-c-key.pem", "leaf-sfo.creds"} {
		if err := store.installMaterial(fd, name, content, want, 128); err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
	}
	if err := unix.Mkdirat(fd, generationStaging, 0o700); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	stage, err := store.openStaging(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	rootStore := store
	rootStore.serviceUID, rootStore.serviceGID = 0, 0
	if err := rootStore.writeStaged(stage, "controller.jwt", content); err != nil {
		unix.Close(stage)
		unix.Close(fd)
		t.Fatal(err)
	}
	unix.Close(stage)
	unix.Close(fd)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	childBinary := filepath.Join(base, "material-test")
	copy, err := os.OpenFile(childBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(copy, binary); err != nil {
		copy.Close()
		t.Fatal(err)
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	// The root bootstrap service has UMask=0077; make the copied test binary
	// executable by the service UID before dropping privileges below.
	if err := os.Chmod(childBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(childBinary, "-test.run=^TestServiceUIDCanReadRootInstalledMaterial$")
	command.Env = append(os.Environ(), "TS_BOOTSTRAP_MATERIAL_CHILD=1", "TS_BOOTSTRAP_MATERIAL_DIR="+directory,
		"TS_BOOTSTRAP_MATERIAL_SHA256="+want)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged material process: %v\n%s", err, output)
	}
}
