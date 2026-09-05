package bootstrapcredentials

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadFileSafetyAndExactBounds(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "ancestor symlink", "hardlink", "FIFO", "shared private", "writable public", "writable ancestor", "over bound", "zero bound", "negative bound", "excess bound"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "files")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "input")
			if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
				t.Fatal(err)
			}
			limit := int64(3)
			private := true
			switch kind {
			case "symlink":
				link := filepath.Join(directory, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "ancestor symlink":
				link := filepath.Join(root, "link")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "input")
			case "hardlink":
				if err := os.Link(path, path+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "shared private":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "writable public":
				private = false
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "writable ancestor":
				if err := os.Chmod(directory, 0777); err != nil {
					t.Fatal(err)
				}
			case "over bound":
				limit = 2
			case "zero bound":
				limit = 0
			case "negative bound":
				limit = -1
			case "excess bound":
				limit = MaximumFileBytes + 1
			}
			done := make(chan error, 1)
			go func() {
				data, err := ReadFile(path, private, limit)
				if kind == "regular" && err == nil && string(data) != "abc" {
					t.Error("captured bytes differ")
				}
				done <- err
			}()
			select {
			case err := <-done:
				if kind == "regular" && err != nil {
					t.Fatal(err)
				}
				if kind != "regular" && err == nil {
					t.Fatal("unsafe file admitted")
				}
			case <-time.After(time.Second):
				t.Fatal("file read blocked")
			}
		})
	}
}
