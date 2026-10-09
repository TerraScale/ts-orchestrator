package client

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestManagedJournalReadKeepsPrivateBoundsAndAbsence(t *testing.T) {
	for _, kind := range []string{"absent", "valid", "limit", "oversized", "mode", "owner", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			f := newManagedFixture(t)
			if _, err := secureManagedDirectory(f.m.root, managedDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: "5Y9HYJTFQ3N1F9AYDYSNQ9PJ07",
				Version: f.pin.Version, RollbackDeadline: time.Now().UTC().Add(time.Minute)},
				BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64"}
			body, err := json.Marshal(transaction)
			if err != nil {
				t.Fatal(err)
			}
			path := f.m.path(managedDirectory + "/pending.json")
			if kind == "symlink" {
				outside := filepath.Join(t.TempDir(), "outside-journal")
				if err := os.WriteFile(outside, body, 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outside, path)
			} else if kind == "fifo" {
				err = syscall.Mkfifo(path, 0600)
			} else if kind != "absent" {
				if kind == "limit" || kind == "oversized" {
					size := 4096
					if kind == "oversized" {
						size++
					}
					body = append(body, strings.Repeat(" ", size-len(body))...)
				}
				err = os.WriteFile(path, body, 0600)
				if err == nil && kind == "mode" {
					err = os.Chmod(path, 0640)
				} else if err == nil && kind == "owner" {
					if os.Geteuid() != 0 {
						t.Skip("changing journal owner requires root")
					}
					err = os.Chown(path, 1, -1)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				transaction managedTransaction
				err         error
			}
			done := make(chan result, 1)
			go func() { transaction, err := f.m.readTransaction(); done <- result{transaction, err} }()
			select {
			case got := <-done:
				valid := kind == "valid" || kind == "limit"
				if (got.err == nil) != (valid || kind == "absent") || valid && got.transaction != transaction || kind == "absent" && got.transaction != (managedTransaction{}) {
					t.Fatalf("journal %s read=%+v error=%v", kind, got.transaction, got.err)
				}
			case <-time.After(time.Second):
				if kind == "fifo" {
					if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						_ = syscall.Close(fd)
					}
				}
				t.Fatal("hostile journal blocked managed recovery")
			}
		})
	}
}

func TestManagedJournalReadDoesNotFollowConcurrentSymlinkReplacement(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := secureManagedDirectory(f.m.root, managedDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: "5Y9HYJTFQ3N1F9AYDYSNQ9PJ07", Version: f.pin.Version,
		RollbackDeadline: time.Now().Add(time.Minute)}, BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64"}
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	safe, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	transaction.TransactionID = "6R1YJ635M4CKTW10K08R13Q5A4"
	unsafe, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-journal")
	if err := os.WriteFile(outside, unsafe, 0600); err != nil {
		t.Fatal(err)
	}
	path := f.m.path(managedDirectory + "/pending.json")
	done := make(chan error, 1)
	go func() {
		for range 250 {
			if err := os.Symlink(outside, path+".swap"); err != nil {
				done <- err
				return
			}
			if err := os.Rename(path+".swap", path); err != nil {
				done <- err
				return
			}
			if err := os.WriteFile(path+".swap", safe, 0600); err != nil {
				done <- err
				return
			}
			if err := os.Rename(path+".swap", path); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	followed := false
	for range 1000 {
		current, err := f.m.readTransaction()
		if err == nil && current.TransactionID == "6R1YJ635M4CKTW10K08R13Q5A4" {
			followed = true
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if followed {
		t.Fatal("journal path changed to a symlink between metadata validation and read")
	}
}
