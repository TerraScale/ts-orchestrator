package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNatsJournalReadFileRejectsSymlinksAndNonPrivateFiles(t *testing.T) {
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "identity.pem")
	contents := []byte("journal identity")
	if err := os.WriteFile(identityPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, data, err := natsJournalReadFile(identityPath, 8192, true)
	if err != nil {
		t.Fatalf("read regular owner-private file: %v", err)
	}
	if resolved != identityPath || string(data) != string(contents) {
		t.Fatalf("resolved = %q, data = %q", resolved, data)
	}
	clear(data)

	linkPath := filepath.Join(directory, "identity-link.pem")
	if err := os.Symlink(identityPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := natsJournalReadFile(linkPath, 8192, true); err == nil {
		t.Fatal("final symbolic link must be rejected")
	}

	symlinkDirectory := filepath.Join(directory, "link-dir")
	if err := os.Symlink(directory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, _, err := natsJournalReadFile(filepath.Join(symlinkDirectory, "identity.pem"), 8192, true); err == nil {
		t.Fatal("symbolic-link path component must be rejected")
	}

	if err := os.Chmod(identityPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := natsJournalReadFile(identityPath, 8192, true); err == nil {
		t.Fatal("non-private identity file must be rejected")
	} else if strings.Contains(err.Error(), string(contents)) {
		t.Fatal("identity file contents must not appear in errors")
	}
}
