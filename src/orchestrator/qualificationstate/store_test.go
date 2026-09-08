package qualificationstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImmutableRecordRecoveryDoesNotReissue(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state", "admission")
	createCalls := 0
	create := func() ([]byte, error) { createCalls++; return []byte("exact-admitted-secret"), nil }
	validate := func(raw []byte) error {
		if !bytes.Equal(raw, []byte("exact-admitted-secret")) {
			return errors.New("invalid")
		}
		return nil
	}
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.LoadOrCreate("identity.json", 1024, create, validate)
	if err != nil {
		t.Fatal(err)
	}
	clear(first)
	store.Close()
	final := filepath.Join(directory, "identity.json")
	if err := os.Rename(final, final+".pending"); err != nil {
		t.Fatal(err)
	}
	store, err = Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recovered, err := store.LoadOrCreate("identity.json", 1024, create, validate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recovered)
	if createCalls != 1 || string(recovered) != "exact-admitted-secret" {
		t.Fatal("pending recovery issued different identity")
	}
	if _, err := os.Stat(final + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending admission was not published")
	}
	again, err := store.LoadOrCreate("identity.json", 1024, create, validate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(again)
	if createCalls != 1 || !bytes.Equal(again, recovered) {
		t.Fatal("committed record regenerated")
	}
}
func TestDamagedOrUnsafeRecordNeverInvokesIssuer(t *testing.T) {
	for _, name := range []string{"partial pending", "symlink final", "wide mode", "hard link", "invalid final"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "admission")
			store, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			final := filepath.Join(dir, "identity.json")
			switch name {
			case "partial pending":
				if err := os.WriteFile(final+".pending", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink final":
				if err := os.Symlink("missing", final); err != nil {
					t.Fatal(err)
				}
			case "wide mode":
				if err := os.WriteFile(final, []byte("original"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hard link":
				if err := os.WriteFile(final, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(final, final+".copy"); err != nil {
					t.Fatal(err)
				}
			case "invalid final":
				if err := os.WriteFile(final, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			_, err = store.LoadOrCreate("identity.json", 1024, func() ([]byte, error) { called = true; return []byte("replacement"), nil }, func([]byte) error { return errors.New("invalid") })
			if err == nil || called {
				t.Fatal("damaged prior admission silently regenerated")
			}
		})
	}
}
func TestOpenRejectsSymlinkAndWritableDirectory(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(filepath.Join(link, "child")); err == nil {
		store.Close()
		t.Fatal("symlink ancestry admitted")
	}
	if err := os.Chmod(target, 0777); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(target); err == nil {
		store.Close()
		t.Fatal("writable directory admitted")
	}
}
