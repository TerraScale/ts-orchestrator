//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// prepare finds the host's runtime roots in host.json and refuses a root it
// could mount over the wrong place.
func TestReadHostRuntimeRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.json")
	for _, tc := range []struct {
		config string
		ok     bool
	}{
		{`{"host":{"managed_runtime_root":"/srv/ts-managed","terrabase_root":"/srv/ts-managed/terrabase","workload_gid":2000,"node":"ts-gru-1"}}`, true},
		{`{"host":{"node":"lab"}}`, true},
		{`{"host":{"managed_runtime_root":"srv/ts-managed","workload_gid":2000}}`, false},
		{`{"host":{"terrabase_root":"/srv/../etc","workload_gid":2000}}`, false},
		{`{"host":{"managed_runtime_root":"/srv/ts-managed"}}`, false},
	} {
		if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
			t.Fatal(err)
		}
		host, err := readHostRuntime(path)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: %+v, %v", tc.config, host, err)
		}
	}
}

// Root clears and mounts directories a service owns: a symlink in the path is
// refused, and clearing removes links without touching what they name.
func TestRuntimeDirectoryNeverFollowsSymlinks(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(base, "state", "spool")
	fd, err := openDirectoryNoFollow(spool, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := os.MkdirAll(filepath.Join(spool, "role"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{filepath.Join(spool, "escape"), filepath.Join(spool, "role", "escape")} {
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(spool, "role", "seed"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Opened after its contents exist, as prepare does.
	if fd, err = openDirectoryNoFollow(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := clearDirectory(fd); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(spool); err != nil || len(entries) != 0 {
		t.Fatalf("spool kept %v: %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("clearing followed a symlink: %v", err)
	}

	if err := os.Remove(spool); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, spool); err != nil {
		t.Fatal(err)
	}
	if fd, err := openDirectoryNoFollow(spool, 0o700); err == nil {
		unix.Close(fd)
		t.Fatal("opened a symlinked runtime directory")
	}
	if err := os.Symlink(filepath.Join(base, "state"), filepath.Join(base, "linked")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openDirectoryNoFollow(filepath.Join(base, "linked", "other"), 0o700); err == nil {
		unix.Close(fd)
		t.Fatal("followed a symlinked parent")
	}
}
