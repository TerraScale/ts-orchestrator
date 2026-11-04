package runtimepriority

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeRoleRecreationRestoresAfterOldDescriptorError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "terrabase")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "memory.max"), []byte("500"), 0600); e != nil {
		t.Fatal(e)
	}
	remote := Remote{}
	fd, meta := remote.openDir(path)
	defer unix.Close(fd)
	limit := remote.openAt(fd, "memory.max", false)
	defer unix.Close(limit)
	if e := os.Rename(path, path+"-old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "memory.max"), []byte("1000"), 0600); e != nil {
		t.Fatal(e)
	}
	method, e := remote.restoreNativeCap(path, meta, fd, limit, 1000)
	if e != nil {
		t.Fatal(e)
	}
	if method != "native_role_recreated" {
		t.Fatalf("restore method %s", method)
	}
	if e := os.WriteFile(filepath.Join(path, "memory.max"), []byte("700"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := remote.restoreNativeCap(path, meta, fd, limit, 1000); e == nil {
		t.Fatal("unknown recreated cap accepted")
	}
}
