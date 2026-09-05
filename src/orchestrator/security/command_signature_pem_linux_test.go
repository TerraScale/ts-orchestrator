//go:build linux

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadCommandSignatureSignerPEMRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		signer, err := LoadCommandSignatureSignerPEM(path)
		if signer != nil {
			signer.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO accepted as private credential")
		}
	case <-time.After(time.Second):
		// Release a regressed blocking reader without making the test itself hang.
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			writer.Close()
		}
		t.Fatal("credential loader blocked opening a FIFO")
	}
}

func TestLoadCommandSignatureSignerPEMRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "credential.pem")
	if err := os.WriteFile(target, []byte("private credential"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// Test the descriptor boundary directly: malformed contents cannot mask
	// whether the symlink itself was followed.
	file, err := openCommandSigningCredential(link)
	if err == nil {
		file.Close()
		t.Fatal("credential symlink was followed")
	}
}
