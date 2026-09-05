//go:build linux

package hostsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func directoryFixture(t *testing.T) (int, string) {
	t.Helper()
	path := t.TempDir()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd, path
}
func prepareFixture(t *testing.T, fd int, seed Seed) *publication {
	t.Helper()
	p, err := prepare(context.Background(), fd, seed, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestJournaledPublicationAndRestart(t *testing.T) {
	fd, root := directoryFixture(t)
	seed := testSeed()
	p := prepareFixture(t, fd, seed)
	entry := seed.Entries[0]
	if err := p.publish(entry, []byte("private-canary")); err != nil {
		t.Fatal(err)
	}
	p.close()
	installed := filepath.Join(root, entryName(entry))
	info, err := os.Stat(installed)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential is not owner-private")
	}
	body, err := os.ReadFile(filepath.Join(root, journalName))
	if err != nil || strings.Contains(string(body), "private-canary") {
		t.Fatal("journal leaked credential bytes")
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	ready, err := p.ready(entry)
	if err != nil || !ready {
		t.Fatalf("restart did not recognize owned credential: %v", err)
	}
	if err = p.publish(entry, []byte("private-canary")); err != nil {
		t.Fatal(err)
	}
}
func TestUnjournaledIdenticalFileIsRefused(t *testing.T) {
	fd, root := directoryFixture(t)
	seed := testSeed()
	entry := seed.Entries[0]
	destination := filepath.Join(root, entryName(entry))
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("private-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := prepare(context.Background(), fd, seed, os.Geteuid()); err != ErrJournal {
		if p != nil {
			p.close()
		}
		t.Fatalf("accepted unknown destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, journalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recorded ownership of unknown credential")
	}
}
func TestPartialTemporaryPublicationRecovers(t *testing.T) {
	fd, root := directoryFixture(t)
	seed := testSeed()
	p := prepareFixture(t, fd, seed)
	entry := seed.Entries[0]
	p.close()
	pending := filepath.Join(root, filepath.Dir(entryName(entry)), pendingName(entry))
	if err := os.WriteFile(pending, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	if err := p.publish(entry, []byte("private-canary")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary credential survived atomic publication")
	}
}
func TestRefusesChangedSeedAndCredential(t *testing.T) {
	fd, root := directoryFixture(t)
	seed := testSeed()
	p := prepareFixture(t, fd, seed)
	if err := p.publish(seed.Entries[0], []byte("private-canary")); err != nil {
		t.Fatal(err)
	}
	p.close()
	changed := testSeed()
	changed.OperationID = "another-generation"
	if p, err := prepare(context.Background(), fd, changed, os.Geteuid()); err != ErrJournal {
		if p != nil {
			p.close()
		}
		t.Fatal("accepted changed admission seed")
	}
	if err := os.WriteFile(filepath.Join(root, entryName(seed.Entries[0])), []byte("other-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	if _, err := p.ready(seed.Entries[0]); err != ErrDigest {
		t.Fatal("accepted replaced credential")
	}
	if err := p.publish(seed.Entries[0], []byte("private-canary")); err != ErrDigest {
		t.Fatal("overwrote changed credential")
	}
}
func TestNoSymlinkOrHardlinkPublication(t *testing.T) {
	for _, kind := range []string{"parent-symlink", "destination-symlink", "pending-symlink", "destination-hardlink", "insecure-mode"} {
		t.Run(kind, func(t *testing.T) {
			fd, root := directoryFixture(t)
			seed := testSeed()
			entry := seed.Entries[0]
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "parent-symlink" {
				if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "ts-node-bootstrap")); err != nil {
					t.Fatal(err)
				}
				if p, err := prepare(context.Background(), fd, seed, os.Geteuid()); err == nil {
					p.close()
					t.Fatal("followed parent symlink")
				}
				return
			}
			p := prepareFixture(t, fd, seed)
			defer p.close()
			destination := filepath.Join(root, entryName(entry))
			switch kind {
			case "destination-symlink":
				if err := os.Symlink(outside, destination); err != nil {
					t.Fatal(err)
				}
			case "pending-symlink":
				if err := os.Symlink(outside, filepath.Join(filepath.Dir(destination), pendingName(entry))); err != nil {
					t.Fatal(err)
				}
			case "destination-hardlink":
				if err := os.Link(outside, destination); err != nil {
					t.Fatal(err)
				}
			case "insecure-mode":
				if err := os.WriteFile(destination, []byte("private-canary"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.publish(entry, []byte("private-canary")); err == nil {
				t.Fatal("accepted unsafe publication")
			}
			got, err := os.ReadFile(outside)
			if err != nil || string(got) != "untouched" {
				t.Fatal("modified outside file")
			}
		})
	}
}

func TestJournalDirectorySyncFailureCanResume(t *testing.T) {
	fd, root := directoryFixture(t)
	seed := testSeed()
	body, _ := json.Marshal(seed)
	// O_PATH allows relative publication syscalls but refuses fsync. This
	// produces a real failure after the journal's atomic rename without root.
	pathFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = publishJournal(pathFD, body)
	unix.Close(pathFD)
	if err != ErrJournal {
		t.Fatalf("expected directory sync failure: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, journalName))
	if err != nil || info.Size() == 0 {
		t.Fatal("test did not reach journal publication")
	}
	p := prepareFixture(t, fd, seed)
	defer p.close()
	if err := p.publish(seed.Entries[0], []byte("private-canary")); err != nil {
		t.Fatalf("durable journal retry failed: %v", err)
	}
}
